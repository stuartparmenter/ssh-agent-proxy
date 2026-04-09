//go:build unix

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/stuartparmenter/ssh-agent-proxy/sshsig"
)

// startTestAgent launches a private ssh-agent with its own socket and
// loads a freshly-generated Ed25519 key. The test is skipped if
// ssh-agent, ssh-add, or ssh-keygen is unavailable on this host.
func startTestAgent(t *testing.T) (sockPath string, keyPath string) {
	t.Helper()
	for _, tool := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}

	dir := t.TempDir()
	sock := filepath.Join(dir, "agent.sock")

	out, err := exec.Command("ssh-agent", "-a", sock).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-agent: %v\n%s", err, out)
	}

	// Parse PID *before* registering cleanup so a parse failure still
	// tries to kill the agent via the Env-reported PID if any lines of
	// output contained it. Then register cleanup as the very next step
	// so any subsequent t.Fatalf still tears the agent down.
	pidRe := regexp.MustCompile(`SSH_AGENT_PID=(\d+)`)
	m := pidRe.FindStringSubmatch(string(out))
	var pid string
	if len(m) == 2 {
		pid = m[1]
	}
	t.Cleanup(func() {
		if pid == "" {
			return
		}
		_ = exec.Command("kill", pid).Run()
	})
	if pid == "" {
		t.Fatalf("could not find SSH_AGENT_PID in ssh-agent output:\n%s", out)
	}

	// Wait briefly for the socket to appear. ssh-agent usually creates
	// it before returning, but be defensive.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	keyPath = filepath.Join(dir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-f", keyPath, "-N", "").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}

	addCmd := exec.Command("ssh-add", keyPath)
	addCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock)
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, out)
	}

	return sock, keyPath
}

// TestAgentSource_LiveAgent exercises the full AgentSource path against
// a real ssh-agent and verifies the resulting signature with
// ssh-keygen -Y check-novalidate.
func TestAgentSource_LiveAgent(t *testing.T) {
	sockPath, _ := startTestAgent(t)

	src, err := newAgentSource(Config{
		AgentPath: sockPath,
		Namespace: "git",
	})
	if err != nil {
		t.Fatalf("newAgentSource: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	signer, cleanup, err := src.Signer(ctx)
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer cleanup()

	if got := signer.PublicKey().Type(); got != ssh.KeyAlgoED25519 {
		t.Fatalf("unexpected key type: %s", got)
	}

	msg := []byte("AgentSource live test\n")
	sig, err := sshsig.Sign(signer, "git", msg)
	if err != nil {
		t.Fatalf("sshsig.Sign: %v", err)
	}
	if !bytes.HasPrefix(sig, []byte("-----BEGIN SSH SIGNATURE-----")) {
		t.Fatalf("bad armor prefix:\n%s", sig)
	}

	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skipf("ssh-keygen unavailable for signature verification: %v", err)
	}
	dir := t.TempDir()
	sigPath := filepath.Join(dir, "msg.sig")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatalf("write sig: %v", err)
	}
	cmd := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", "git", "-s", sigPath)
	cmd.Stdin = bytes.NewReader(msg)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("ssh-keygen -Y check-novalidate rejected agent signature: %v\nstdout: %s\nstderr: %s",
			err, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "Good") {
		t.Fatalf("ssh-keygen did not report Good signature:\n%s", out.String())
	}
}

// TestAgentSource_PubkeySelection verifies that when a specific public
// key is configured, AgentSource picks it out of a multi-key agent.
func TestAgentSource_PubkeySelection(t *testing.T) {
	sockPath, firstKey := startTestAgent(t)

	dir := t.TempDir()
	secondKey := filepath.Join(dir, "id_ed25519_2")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-f", secondKey, "-N", "").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	addCmd := exec.Command("ssh-add", secondKey)
	addCmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sockPath)
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add second: %v\n%s", err, out)
	}

	firstPubBytes, err := os.ReadFile(firstKey + ".pub")
	if err != nil {
		t.Fatalf("read first pub: %v", err)
	}
	firstPub, _, _, _, err := ssh.ParseAuthorizedKey(firstPubBytes)
	if err != nil {
		t.Fatalf("parse first pub: %v", err)
	}

	src, err := newAgentSource(Config{AgentPath: sockPath, Pubkey: firstPub})
	if err != nil {
		t.Fatalf("newAgentSource: %v", err)
	}

	signer, cleanup, err := src.Signer(context.Background())
	if err != nil {
		t.Fatalf("Signer: %v", err)
	}
	defer cleanup()

	if !bytes.Equal(signer.PublicKey().Marshal(), firstPub.Marshal()) {
		t.Fatalf("Signer returned wrong key; selection did not take effect")
	}
}

// TestAgentSource_WrongPubkey makes sure the "configured pubkey not in
// agent" error path is clean and doesn't leak a connection.
func TestAgentSource_WrongPubkey(t *testing.T) {
	sockPath, _ := startTestAgent(t)

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}

	src, err := newAgentSource(Config{AgentPath: sockPath, Pubkey: pub})
	if err != nil {
		t.Fatalf("newAgentSource: %v", err)
	}
	if _, _, err := src.Signer(context.Background()); err == nil {
		t.Fatal("expected error when configured pubkey is not in agent")
	}
}

// TestAgentSource_NoAgent verifies the error path when the socket
// doesn't exist (agent not running). Dialing a nonexistent Unix
// socket returns "connect: no such file or directory" from the
// syscall, which is a clear enough signal.
func TestAgentSource_NoAgent(t *testing.T) {
	dir := t.TempDir()
	src, err := newAgentSource(Config{AgentPath: filepath.Join(dir, "nope.sock")})
	if err != nil {
		t.Fatalf("newAgentSource should defer socket check to dial time: %v", err)
	}
	if _, _, err := src.Signer(context.Background()); err == nil {
		t.Fatal("expected error when agent socket does not exist")
	}
}

// TestAgentSource_NotASocket verifies we get a useful error when the
// agent path points at a regular file. The error comes from the
// kernel's connect(2) call, which refuses with ECONNREFUSED.
func TestAgentSource_NotASocket(t *testing.T) {
	dir := t.TempDir()
	regularFile := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(regularFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	src, err := newAgentSource(Config{AgentPath: regularFile})
	if err != nil {
		t.Fatalf("newAgentSource should defer socket check to dial time: %v", err)
	}
	if _, _, err := src.Signer(context.Background()); err == nil {
		t.Fatal("expected dial error for non-socket path")
	}
}
