//go:build windows

package main

import (
	"context"
	"errors"
	"net"

	"github.com/Microsoft/go-winio"
)

// windowsDefaultPipe is where 1Password Desktop (and the built-in
// Windows OpenSSH agent) exposes the SSH agent protocol when the
// "Use SSH agent" option is enabled in 1Password's Developer settings.
const windowsDefaultPipe = `\\.\pipe\openssh-ssh-agent`

// defaultAgentPath returns the pipe we dial when SSH_AGENT_PROXY_UPSTREAM
// is unset. We default to the standard OpenSSH agent pipe name, which
// is what 1Password Desktop uses when "Use SSH agent" is turned on.
func defaultAgentPath() string {
	return windowsDefaultPipe
}

// newAgentSource constructs an AgentSource that dials a Windows named
// pipe via github.com/Microsoft/go-winio. That package is pure Go — it
// talks directly to the NT object manager, no CGO.
func newAgentSource(cfg Config) (*AgentSource, error) {
	if cfg.AgentPath == "" {
		return nil, errors.New("no agent pipe path configured")
	}
	path := cfg.AgentPath
	dial := func(ctx context.Context) (net.Conn, error) {
		return winio.DialPipeContext(ctx, path)
	}
	return newAgentSourceWithDialer(path, cfg.Pubkey, dial), nil
}
