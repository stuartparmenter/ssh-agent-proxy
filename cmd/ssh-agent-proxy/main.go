// ssh-agent-proxy is a tiny HTTP server that forwards SSHSIG sign
// requests to a local ssh-agent. It exposes POST /sign and
// GET /publickey on a loopback address and is intended to be used as a
// git signing backend from inside a container (see
// scripts/ssh-agent-proxy-sign.sh).
//
// The proxy holds no private key material itself: the key stays inside
// whatever ssh-agent it's pointed at (typically 1Password Desktop,
// but any agent-protocol implementation works).
//
// Environment variables:
//
//	SSH_AGENT_PROXY_ADDR        listen address (default 127.0.0.1:7221)
//	SSH_AGENT_PROXY_NAMESPACE   SSHSIG namespace (default "git")
//	SSH_AGENT_PROXY_UPSTREAM       agent path (Unix socket or Windows named
//	                          pipe). Defaults: $SSH_AUTH_SOCK on Unix,
//	                          \\.\pipe\openssh-ssh-agent on Windows.
//	SSH_AGENT_PROXY_PUBKEY      optional: restrict signing to a specific
//	                          public key (OpenSSH authorized_keys
//	                          format line). If unset, the first key
//	                          advertised by the agent is used.
//	SSH_AGENT_PROXY_PUBKEY_FILE optional: path to a file containing the
//	                          pubkey line. Ignored if
//	                          SSH_AGENT_PROXY_PUBKEY is set.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/stuartparmenter/ssh-agent-proxy/sshsig"
)

const (
	defaultAddr      = "127.0.0.1:7221"
	defaultNamespace = "git"
	maxRequestBody   = 16 << 20 // 16 MiB
)

// Config holds the proxy's runtime configuration.
type Config struct {
	Addr      string        // listen address
	Namespace string        // SSHSIG namespace
	AgentPath string        // agent endpoint (Unix socket or Windows pipe)
	Pubkey    ssh.PublicKey // optional: restrict to this specific key
}

// SignerSource produces a fresh ssh.Signer on demand. Handlers call
// this on every request so nothing caches key material across
// requests. The returned cleanup func must be invoked (typically via
// defer) to release any resources — e.g. the underlying agent
// connection for AgentSource. It is always non-nil so callers can
// defer it unconditionally.
type SignerSource interface {
	Signer(ctx context.Context) (ssh.Signer, func(), error)
}

// loadConfig reads Config from environment variables. It does not dial
// the agent — that happens on the first /sign request.
func loadConfig() (Config, error) {
	cfg := Config{
		Addr:      envOrDefault("SSH_AGENT_PROXY_ADDR", defaultAddr),
		Namespace: envOrDefault("SSH_AGENT_PROXY_NAMESPACE", defaultNamespace),
		AgentPath: os.Getenv("SSH_AGENT_PROXY_UPSTREAM"),
	}
	if cfg.AgentPath == "" {
		cfg.AgentPath = defaultAgentPath()
	}
	if cfg.AgentPath == "" {
		return cfg, errors.New("no agent path configured: set SSH_AGENT_PROXY_UPSTREAM, SSH_AUTH_SOCK (on Unix), or use the Windows default")
	}

	line, err := loadPubkeyLine()
	if err != nil {
		return cfg, err
	}
	if line != "" {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return cfg, fmt.Errorf("parse SSH_AGENT_PROXY_PUBKEY: %w", err)
		}
		cfg.Pubkey = pub
	}

	return cfg, nil
}

// loadPubkeyLine resolves the pubkey-selection env vars: SSH_AGENT_PROXY_PUBKEY
// takes precedence if set, otherwise SSH_AGENT_PROXY_PUBKEY_FILE is read from
// disk. Returns an empty string if neither is set (meaning "use the first
// key the agent advertises").
func loadPubkeyLine() (string, error) {
	if line := os.Getenv("SSH_AGENT_PROXY_PUBKEY"); line != "" {
		return line, nil
	}
	if path := os.Getenv("SSH_AGENT_PROXY_PUBKEY_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read SSH_AGENT_PROXY_PUBKEY_FILE: %w", err)
		}
		return string(data), nil
	}
	return "", nil
}

func envOrDefault(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func main() {
	// Apply process hardening before anything else — we want mitigations
	// in place before we even parse args, so the brief window during
	// startup is also protected.
	hardenProcess()

	// Subcommand dispatch (Windows service management). On non-Windows
	// platforms runServiceCmd returns a clear "not supported" error.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install", "uninstall":
			if err := runServiceCmd(os.Args[1], os.Args[2:]); err != nil {
				log.Fatalf("%s: %v", os.Args[1], err)
			}
			return
		}
	}

	// If we were launched by the Windows service control manager, hand
	// off to the svc dispatcher. Otherwise fall through to interactive
	// mode, which handles Ctrl-C and SIGTERM via signal.NotifyContext.
	if isWindowsService() {
		runAsWindowsService()
		return
	}

	if err := run(context.Background()); err != nil {
		log.Fatalf("ssh-agent-proxy: %v", err)
	}
}

func run(parentCtx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(parentCtx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	src, err := newAgentSource(cfg)
	if err != nil {
		return fmt.Errorf("agent source: %w", err)
	}
	log.Printf("signing via agent at %s", cfg.AgentPath)
	if cfg.Pubkey != nil {
		log.Printf("restricted to pubkey: %s",
			strings.TrimSpace(string(ssh.MarshalAuthorizedKey(cfg.Pubkey))))
	}

	srv := newServer(cfg.Addr, src, cfg.Namespace)

	listener, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.Addr, err)
	}
	log.Printf("listening on %s (namespace %q)", listener.Addr(), cfg.Namespace)

	errCh := make(chan error, 1)
	go func() {
		if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown signal received")
	case err := <-errCh:
		return err
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// newServer builds the signing HTTP server with sensible timeouts.
func newServer(addr string, src SignerSource, namespace string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", signHandler(src, namespace))
	mux.HandleFunc("/publickey", pubkeyHandler(src))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok\n")
	})

	return &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}

// signHandler reads the raw request body and returns an armored SSHSIG
// signature over it. The agent connection used to produce the signature
// is opened fresh per request and closed as soon as the handler returns.
func signHandler(src SignerSource, namespace string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBody))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if len(body) == 0 {
			http.Error(w, "empty request body", http.StatusBadRequest)
			return
		}

		signer, cleanup, err := src.Signer(r.Context())
		if err != nil {
			log.Printf("signer fetch: %v", err)
			http.Error(w, "signer unavailable", http.StatusServiceUnavailable)
			return
		}
		defer cleanup()

		sig, err := sshsig.Sign(signer, namespace, body)
		if err != nil {
			log.Printf("sign error: %v", err)
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-ssh-signature")
		_, _ = w.Write(sig)
	}
}

// pubkeyHandler returns the OpenSSH-format public key line for the
// currently-selected key. Like /sign, it re-asks the agent on every
// request so the container-side shim always sees the live public key.
func pubkeyHandler(src SignerSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		signer, cleanup, err := src.Signer(r.Context())
		if err != nil {
			log.Printf("signer fetch: %v", err)
			http.Error(w, "signer unavailable", http.StatusServiceUnavailable)
			return
		}
		defer cleanup()

		line := ssh.MarshalAuthorizedKey(signer.PublicKey())

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(line)
	}
}
