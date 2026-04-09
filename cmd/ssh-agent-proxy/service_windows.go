//go:build windows

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"golang.org/x/term"
)

const (
	serviceName        = "ssh-agent-proxy"
	serviceDisplayName = "ssh-agent-proxy"
	serviceDescription = "Localhost HTTP signing proxy backed by a local ssh-agent"
)

// serviceEnvVars are the environment variables the install subcommand
// captures from the invoking shell and persists into the Windows
// service's Environment registry value, so the service process sees
// the same config when launched by the SCM. Keep in sync with
// loadConfig().
var serviceEnvVars = []string{
	"SSH_AGENT_PROXY_ADDR",
	"SSH_AGENT_PROXY_NAMESPACE",
	"SSH_AGENT_PROXY_UPSTREAM",
	"SSH_AGENT_PROXY_PUBKEY",
	"SSH_AGENT_PROXY_PUBKEY_FILE",
}

// isWindowsService reports whether the current process was launched
// by the Windows service control manager.
func isWindowsService() bool {
	inService, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return inService
}

// runAsWindowsService dispatches to the svc package and runs the
// service handler. Services have no console, so log output is sent
// to a file under %LOCALAPPDATA%.
func runAsWindowsService() {
	setupServiceLogging()
	log.Printf("ssh-agent-proxy service starting")
	if err := svc.Run(serviceName, &serviceHandler{}); err != nil {
		log.Fatalf("service dispatcher: %v", err)
	}
}

// serviceLogDir returns the directory we write service.log to. It
// prefers %LOCALAPPDATA% (which resolves to a per-user private
// directory whether the service runs as a user account or as
// LocalSystem) and falls back to the executable's directory if
// LOCALAPPDATA isn't set.
//
// We deliberately avoid %ProgramData% because it's world-readable by
// default, and service.log can contain error text and the selected
// public key.
func serviceLogDir() string {
	if lad := os.Getenv("LOCALAPPDATA"); lad != "" {
		return filepath.Join(lad, "ssh-agent-proxy")
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Dir(exe)
	}
	return ""
}

func setupServiceLogging() {
	dir := serviceLogDir()
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, "service.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	log.SetOutput(f)
}

// serviceHandler is the bridge between the Windows service control
// manager and our run() function.
type serviceHandler struct{}

func (h *serviceHandler) Execute(args []string, r <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepts = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- run(ctx) }()

	status <- svc.Status{State: svc.Running, Accepts: accepts}

loop:
	for {
		select {
		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				log.Printf("service: received %v, shutting down", c.Cmd)
				cancel()
				select {
				case err := <-errCh:
					if err != nil {
						log.Printf("service: run returned: %v", err)
					}
				case <-time.After(10 * time.Second):
					log.Printf("service: shutdown timeout after 10s")
				}
				break loop
			default:
				log.Printf("service: ignoring unexpected command %v", c.Cmd)
			}
		case err := <-errCh:
			if err != nil {
				log.Printf("service: run failed: %v", err)
			}
			break loop
		}
	}

	status <- svc.Status{State: svc.StopPending}
	return false, 0
}

// runServiceCmd is dispatched by main() for the install/uninstall
// subcommands.
func runServiceCmd(cmd string, args []string) error {
	switch cmd {
	case "install":
		return installService(args)
	case "uninstall":
		return uninstallService()
	default:
		return fmt.Errorf("unknown service command %q", cmd)
	}
}

// installService registers ssh-agent-proxy as a Windows service. By
// default it runs as the installing user so the service can reach
// per-user agent pipes (1Password Desktop creates its pipe in the
// user's session); pass -system to run as LocalSystem instead, which
// only works if the target agent's pipe is accessible to SYSTEM.
func installService(args []string) error {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asSystem := fs.Bool("system", false, "run the service as LocalSystem (by default: the current user)")
	user := fs.String("user", "", "service run-as user in DOMAIN\\user form (default: current user)")
	password := fs.String("password", "", "password for -user (prompted on stdin if empty)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("get executable path: %w", err)
	}
	absExe, err := filepath.Abs(exe)
	if err != nil {
		return fmt.Errorf("absolute exe path: %w", err)
	}

	env, err := collectServiceEnv()
	if err != nil {
		return err
	}

	cfg := mgr.Config{
		DisplayName:  serviceDisplayName,
		Description:  serviceDescription,
		StartType:    mgr.StartManual,
		ErrorControl: mgr.ErrorNormal,
	}

	if !*asSystem {
		account := *user
		if account == "" {
			account = currentUserAccount()
			if account == "" {
				return errors.New("could not determine current user; pass -user DOMAIN\\user or -system")
			}
		}
		pw := *password
		if pw == "" {
			prompted, err := promptPassword(account)
			if err != nil {
				return fmt.Errorf("read password: %w", err)
			}
			pw = prompted
		}
		cfg.ServiceStartName = account
		cfg.Password = pw
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Idempotent: remove an existing install so env and run-as user
	// always reflect the most recent call.
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		log.Printf("service %q already exists, reinstalling", serviceName)
		if err := uninstallService(); err != nil {
			return fmt.Errorf("remove existing service: %w", err)
		}
	}

	s, err := m.CreateService(serviceName, absExe, cfg)
	if err != nil {
		return fmt.Errorf("create service: %w", err)
	}
	defer s.Close()

	if len(env) > 0 {
		if err := setServiceEnvironment(serviceName, env); err != nil {
			_ = s.Delete()
			return fmt.Errorf("set service environment: %w", err)
		}
	}

	log.Printf("service %q installed", serviceName)
	log.Printf("  binary: %s", absExe)
	if cfg.ServiceStartName != "" {
		log.Printf("  run as: %s", cfg.ServiceStartName)
	} else {
		log.Printf("  run as: LocalSystem")
	}
	if len(env) > 0 {
		log.Printf("  environment (%d vars):", len(env))
		for _, e := range env {
			log.Printf("    %s", e)
		}
	} else {
		log.Printf("  no SSH_AGENT_PROXY_* env vars set in the current shell; the service will use platform defaults (%s)", defaultAgentPath())
	}
	log.Printf("start with: sc start %s", serviceName)
	log.Printf("logs at: %%LOCALAPPDATA%%\\ssh-agent-proxy\\service.log")
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("open service %q: %w", serviceName, err)
	}
	defer s.Close()

	_, _ = s.Control(svc.Stop)

	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	log.Printf("service %q removed", serviceName)
	return nil
}

// currentUserAccount returns the installing user in DOMAIN\user form,
// or an empty string if the lookup fails.
func currentUserAccount() string {
	domain := os.Getenv("USERDOMAIN")
	user := os.Getenv("USERNAME")
	if user == "" {
		return ""
	}
	if domain == "" {
		return user
	}
	return domain + `\` + user
}

// promptPassword reads a password from the terminal without echo.
// Errors out if stdin isn't a TTY so an automated install gets a
// clear failure instead of hanging.
func promptPassword(account string) (string, error) {
	if !term.IsTerminal(int(syscall.Stdin)) {
		return "", fmt.Errorf("stdin is not a terminal; pass -password or -system for non-interactive installs")
	}
	fmt.Fprintf(os.Stderr, "Password for %s: ", account)
	pw, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(pw), nil
}

// collectServiceEnv snapshots the env vars we care about from the
// current shell, trimming trailing CR/LF (common when users pipe
// pubkey files into env vars) and rejecting embedded CR/LF which
// would silently corrupt the REG_MULTI_SZ environment block.
func collectServiceEnv() ([]string, error) {
	var env []string
	for _, name := range serviceEnvVars {
		raw := os.Getenv(name)
		if raw == "" {
			continue
		}
		trimmed := strings.TrimRight(raw, "\r\n")
		if strings.ContainsAny(trimmed, "\r\n") {
			return nil, fmt.Errorf("%s contains an embedded newline; cannot persist to service environment", name)
		}
		env = append(env, name+"="+trimmed)
	}
	return env, nil
}

// setServiceEnvironment writes env vars to the service's Environment
// REG_MULTI_SZ value, which the SCM reads when launching the service
// process.
func setServiceEnvironment(name string, env []string) error {
	if len(env) == 0 {
		return nil
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\`+name,
		registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open service registry key: %w", err)
	}
	defer k.Close()
	return k.SetStringsValue("Environment", env)
}
