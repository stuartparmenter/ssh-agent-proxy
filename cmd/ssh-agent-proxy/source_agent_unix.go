//go:build unix

package main

import (
	"context"
	"errors"
	"net"
	"os"
)

// defaultAgentPath returns the path we dial when SSH_AGENT_PROXY_UPSTREAM is
// unset. On Unix we honor $SSH_AUTH_SOCK: whatever the user already
// points their shell at (1Password Desktop's socket, stock openssh-
// agent, gpg-agent, etc.) is what we sign through. Returns an empty
// string if unset, in which case loadConfig() errors out.
func defaultAgentPath() string {
	return os.Getenv("SSH_AUTH_SOCK")
}

// newAgentSource constructs an AgentSource that dials a Unix-domain
// socket. Compiled on linux, darwin, and the BSDs. We do not stat the
// path here — DialContext will surface a useful error on non-existent
// or non-socket paths, and statting first would open a TOCTOU window
// anyway.
func newAgentSource(cfg Config) (*AgentSource, error) {
	if cfg.AgentPath == "" {
		return nil, errors.New("no agent socket path configured")
	}
	var dialer net.Dialer
	path := cfg.AgentPath
	dial := func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, "unix", path)
	}
	return newAgentSourceWithDialer(path, cfg.Pubkey, dial), nil
}
