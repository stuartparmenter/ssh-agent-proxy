package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// AgentSource is a SignerSource that forwards sign operations to a
// local ssh-agent. It holds no key material of its own; the private
// key lives wherever the agent keeps it.
//
// Each call to Signer() dials the agent, lists its keys, picks the
// configured one, and returns a signer along with a cleanup func that
// closes the connection.
type AgentSource struct {
	// dial opens a new connection to the ssh-agent. Platform-specific:
	// net.Dialer.DialContext for Unix sockets, winio.DialPipeContext
	// for Windows named pipes.
	dial func(ctx context.Context) (net.Conn, error)

	// name is a human-readable label for the agent endpoint, used in
	// log messages and wrapped errors.
	name string

	// pubkey, if non-nil, restricts the source to a specific key in
	// the agent. When nil, the first key advertised by the agent is
	// used.
	pubkey ssh.PublicKey
}

// newAgentSourceWithDialer builds an AgentSource around an explicit
// dialer. Used by the platform-specific factories in
// source_agent_{unix,windows}.go.
func newAgentSourceWithDialer(name string, pubkey ssh.PublicKey, dial func(context.Context) (net.Conn, error)) *AgentSource {
	return &AgentSource{dial: dial, name: name, pubkey: pubkey}
}

// agentStepTimeout bounds each individual agent operation (dial, list,
// sign). A hung agent on the other end of a Unix socket or named pipe
// shouldn't pin a goroutine until the HTTP write timeout fires.
const agentStepTimeout = 5 * time.Second

// Signer dials the agent, selects the target key, and returns an
// ssh.Signer whose Sign() calls flow through the agent connection. The
// returned cleanup closes the connection; callers MUST call it (via
// defer) or the socket/pipe handle leaks.
func (s *AgentSource) Signer(ctx context.Context) (ssh.Signer, func(), error) {
	dialCtx, dialCancel := context.WithTimeout(ctx, agentStepTimeout)
	defer dialCancel()

	conn, err := s.dial(dialCtx)
	if err != nil {
		return nil, noopCleanup, fmt.Errorf("dial %s: %w", s.name, err)
	}
	cleanup := func() { _ = conn.Close() }

	// Bound the LIST round-trip too — this catches agents that accept
	// the connection but never respond.
	if dl, ok := ctx.Deadline(); !ok || time.Until(dl) > agentStepTimeout {
		_ = conn.SetDeadline(time.Now().Add(agentStepTimeout))
	}

	client := agent.NewClient(conn)

	keys, err := client.List()
	if err != nil {
		cleanup()
		return nil, noopCleanup, fmt.Errorf("list agent keys: %w", err)
	}
	if len(keys) == 0 {
		cleanup()
		return nil, noopCleanup, errors.New("agent has no keys loaded (is the desktop app unlocked and SSH-agent integration enabled?)")
	}

	selected, err := pickKey(keys, s.pubkey)
	if err != nil {
		cleanup()
		return nil, noopCleanup, err
	}

	pub, err := ssh.ParsePublicKey(selected.Blob)
	if err != nil {
		cleanup()
		return nil, noopCleanup, fmt.Errorf("parse selected agent key: %w", err)
	}

	// Clear the LIST deadline so Sign() gets its own full budget. We
	// re-arm a deadline inside Sign() if we want per-call bounding.
	_ = conn.SetDeadline(time.Time{})

	return &agentBackedSigner{client: client, pub: pub, conn: conn}, cleanup, nil
}

// noopCleanup is the cleanup func returned alongside errors and by
// sources that have no resource to release.
func noopCleanup() {}

// pickKey selects the agent key to use. If want is non-nil, returns
// the key whose wire-format bytes match it; otherwise returns the
// first key the agent advertises.
func pickKey(keys []*agent.Key, want ssh.PublicKey) (*agent.Key, error) {
	if want == nil {
		return keys[0], nil
	}
	target := want.Marshal()
	for _, k := range keys {
		if bytes.Equal(k.Blob, target) {
			return k, nil
		}
	}
	return nil, fmt.Errorf("configured public key not found in agent (%d keys available)", len(keys))
}

// agentBackedSigner implements ssh.Signer and ssh.AlgorithmSigner by
// forwarding Sign operations to the underlying ssh-agent. The caller
// owns the agent connection (via the cleanup func returned from
// AgentSource.Signer); this type only uses it to arm a per-call
// deadline.
type agentBackedSigner struct {
	client agent.ExtendedAgent
	pub    ssh.PublicKey
	conn   net.Conn
}

func (s *agentBackedSigner) PublicKey() ssh.PublicKey {
	return s.pub
}

// Sign delegates to SignWithAlgorithm with an empty algorithm, which
// picks the sensible default per key type (SHA-512 for RSA to avoid
// the agent's SHA-1 fallback, native signing for ed25519 / ecdsa).
func (s *agentBackedSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(rand, data, "")
}

// SignWithAlgorithm maps the standard ssh algorithm names to the
// corresponding agent.SignatureFlags, bounds the operation with a
// per-call deadline, and verifies the agent returned the signature
// flavor we asked for — a malicious or buggy agent must not be able
// to silently downgrade an rsa-sha2-512 request to ssh-rsa (SHA-1).
func (s *agentBackedSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	if s.conn != nil {
		_ = s.conn.SetDeadline(time.Now().Add(agentStepTimeout))
		defer func() { _ = s.conn.SetDeadline(time.Time{}) }()
	}

	var (
		sig     *ssh.Signature
		err     error
		wantFmt string
	)
	switch algorithm {
	case "":
		if s.pub.Type() == ssh.KeyAlgoRSA {
			wantFmt = ssh.KeyAlgoRSASHA512
			sig, err = s.client.SignWithFlags(s.pub, data, agent.SignatureFlagRsaSha512)
		} else {
			wantFmt = s.pub.Type()
			sig, err = s.client.Sign(s.pub, data)
		}
	case ssh.KeyAlgoRSASHA512:
		wantFmt = ssh.KeyAlgoRSASHA512
		sig, err = s.client.SignWithFlags(s.pub, data, agent.SignatureFlagRsaSha512)
	case ssh.KeyAlgoRSASHA256:
		wantFmt = ssh.KeyAlgoRSASHA256
		sig, err = s.client.SignWithFlags(s.pub, data, agent.SignatureFlagRsaSha256)
	default:
		// ed25519, ecdsa-sha2-*, ssh-rsa, etc: agents identify keys by
		// wire blob, not flavor; the default Sign() path handles them.
		wantFmt = algorithm
		sig, err = s.client.Sign(s.pub, data)
	}
	if err != nil {
		return nil, err
	}

	// Defend against a misbehaving agent that ignores SignatureFlags
	// and hands back a weaker signature than requested (e.g. SHA-1
	// ssh-rsa when we asked for rsa-sha2-512). For ECDSA and Ed25519
	// the algorithm string equals the key type so this is a no-op in
	// the common path; for RSA it's the real check.
	if s.pub.Type() == ssh.KeyAlgoRSA && sig.Format != wantFmt {
		return nil, fmt.Errorf("agent returned signature format %q, wanted %q", sig.Format, wantFmt)
	}
	return sig, nil
}

var (
	_ ssh.Signer          = (*agentBackedSigner)(nil)
	_ ssh.AlgorithmSigner = (*agentBackedSigner)(nil)
)
