// op-sign-proxy is a tiny HTTP server that signs arbitrary bytes with an
// SSH private key resolved from 1Password. It exposes POST /sign and
// GET /publickey on a loopback address, and is intended to be used as a
// git signing backend from inside a container (see scripts/op-git-sign.sh).
//
// Key lifecycle: the private key is fetched from 1Password on *every*
// request. It is never cached across requests and never stored on disk.
// This gives zero-lag key rotation — rotate the key in 1Password and the
// very next /sign request uses the new key, with no proxy restart and no
// background refresh logic — at the cost of one 1Password SDK round-trip
// per request.
//
// Note: because the 1Password Go SDK returns secret values as Go strings
// (which are immutable), we cannot explicitly zero the raw PEM bytes after
// use. "Don't hold in memory" is therefore best-effort: no caches, no
// long-lived references, GC reclaims the key material as soon as the
// request handler returns. If that is not strong enough for your threat
// model, you want a hardware token or a memory-locked agent, not this.
//
// Environment variables:
//
//	OP_SERVICE_ACCOUNT_TOKEN  1Password service-account token (required)
//	OP_SSH_KEY_REF            op://vault/item/field reference to the private
//	                          key, e.g. op://Personal/Git Signing/private key
//	                          (required)
//	OP_SIGN_PROXY_ADDR        listen address (default 127.0.0.1:7221)
//	OP_SIGN_PROXY_NAMESPACE   SSHSIG namespace (default "git")
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
	"sync"
	"syscall"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
	"golang.org/x/crypto/ssh"

	"github.com/stuartparmenter/op-sign-proxy/sshsig"
)

const (
	defaultAddr      = "127.0.0.1:7221"
	defaultNamespace = "git"
	integrationName  = "op-sign-proxy"
	integrationVer   = "v0.1.0"
	maxRequestBody   = 16 << 20 // 16 MiB, plenty for a git commit payload
)

// SignerSource produces a fresh ssh.Signer on demand. Handlers call this
// on every request so that nothing caches the private key across requests.
type SignerSource interface {
	Signer(ctx context.Context) (ssh.Signer, error)
}

// RefSwitcher is a SignerSource whose backing secret reference can be
// swapped at runtime. Implementations must validate the new reference
// (resolve + parse) before committing the swap, so a failed call leaves
// the previous reference in place. The /ref HTTP handler is only
// registered if the active source satisfies this interface.
type RefSwitcher interface {
	SignerSource
	SetRef(ctx context.Context, newRef string) error
	Ref() string
}

// OnePasswordSource resolves the SSH private key from 1Password on every
// call. The underlying SDK client is reused (constructing one is expensive
// — it loads a WASM module via wazero) but no key material is retained.
type OnePasswordSource struct {
	// mu serializes Resolve calls because the 1Password SDK wraps a
	// wazero-hosted WASM module and we don't want to rely on the upstream
	// SDK being safe for concurrent use. For a personal signing proxy the
	// contention cost is negligible.
	mu     sync.Mutex
	client *onepassword.Client
	ref    string
}

// newOnePasswordSource creates the SDK client. It does *not* touch the
// secret reference — the first actual fetch happens on the first request.
// Constructing the client validates the service-account token format and
// initializes the WASM runtime; failures here indicate bad config or a
// broken install rather than a missing/wrong secret reference.
func newOnePasswordSource(ctx context.Context, token, ref string) (*OnePasswordSource, error) {
	client, err := onepassword.NewClient(ctx,
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(integrationName, integrationVer),
	)
	if err != nil {
		return nil, fmt.Errorf("1password client: %w", err)
	}
	return &OnePasswordSource{client: client, ref: ref}, nil
}

// Signer fetches the private key from 1Password, parses it, and returns an
// ssh.Signer. Nothing is cached: every call produces a fresh fetch and a
// fresh Signer. The caller is expected to use the returned signer
// immediately and drop the reference so GC can reclaim the key material.
func (s *OnePasswordSource) Signer(ctx context.Context) (ssh.Signer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pem, err := s.client.Secrets().Resolve(ctx, s.ref)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", s.ref, err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(pem))
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	return signer, nil
}

// Ref returns the current secret reference.
func (s *OnePasswordSource) Ref() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ref
}

// SetRef validates newRef by doing one fresh resolve + parse against it,
// then commits the swap — atomically with respect to concurrent Signer()
// calls, since both paths hold s.mu for the entire resolve-and-commit
// window. If validation fails the stored reference is untouched, so a
// bad POST /ref never leaves the proxy in a half-broken state. The
// parsed signer is discarded after validation (we don't cache signers,
// by design).
func (s *OnePasswordSource) SetRef(ctx context.Context, newRef string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pem, err := s.client.Secrets().Resolve(ctx, newRef)
	if err != nil {
		return fmt.Errorf("resolve %s: %w", newRef, err)
	}
	if _, err := ssh.ParsePrivateKey([]byte(pem)); err != nil {
		return fmt.Errorf("parse private key at %s: %w", newRef, err)
	}

	prev := s.ref
	s.ref = newRef
	log.Printf("secret reference swapped: %q → %q", prev, newRef)
	return nil
}

func main() {
	if err := run(); err != nil {
		log.Fatalf("op-sign-proxy: %v", err)
	}
}

func run() error {
	// Apply process hardening before touching any sensitive config. On
	// Linux this disables core dumps, blocks non-root ptrace/memread,
	// and mlocks our pages; on other platforms it's a no-op.
	hardenProcess()

	token := os.Getenv("OP_SERVICE_ACCOUNT_TOKEN")
	if token == "" {
		return errors.New("OP_SERVICE_ACCOUNT_TOKEN is not set")
	}
	ref := os.Getenv("OP_SSH_KEY_REF")
	if ref == "" {
		return errors.New("OP_SSH_KEY_REF is not set (e.g. op://Vault/Item/private key)")
	}

	addr := os.Getenv("OP_SIGN_PROXY_ADDR")
	if addr == "" {
		addr = defaultAddr
	}
	namespace := os.Getenv("OP_SIGN_PROXY_NAMESPACE")
	if namespace == "" {
		namespace = defaultNamespace
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Build the SDK client at startup so WASM init failures or obviously
	// malformed tokens are caught before we start listening. We do NOT
	// fetch the actual secret here — that happens per request.
	src, err := newOnePasswordSource(ctx, token, ref)
	if err != nil {
		return fmt.Errorf("1password source: %w", err)
	}
	log.Printf("1password client ready; key %q will be fetched on every request", ref)

	srv := newServer(addr, src, namespace)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("listening on %s (namespace %q)", listener.Addr(), namespace)

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

// newServer builds the signing HTTP server with sensible timeouts. If
// the provided SignerSource also satisfies RefSwitcher, POST /ref is
// registered for runtime secret-reference swapping.
func newServer(addr string, src SignerSource, namespace string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/sign", signHandler(src, namespace))
	mux.HandleFunc("/publickey", pubkeyHandler(src))
	if rs, ok := src.(RefSwitcher); ok {
		mux.HandleFunc("/ref", refHandler(rs))
	}
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
// signature over it. The signing key is fetched fresh from the source on
// every request and dropped as soon as the handler returns.
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

		signer, err := src.Signer(r.Context())
		if err != nil {
			log.Printf("signer fetch: %v", err)
			http.Error(w, "signer unavailable", http.StatusServiceUnavailable)
			return
		}

		sig, err := sshsig.Sign(signer, namespace, body)
		if err != nil {
			log.Printf("sign error: %v", err)
			http.Error(w, "sign failed", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/x-ssh-signature")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(sig)))
		_, _ = w.Write(sig)
	}
}

// refHandler implements POST /ref: accept a new op:// reference in the
// request body, validate it via the RefSwitcher (which does a fresh
// resolve + parse), and on success respond with the new public key in
// OpenSSH authorized_keys format. Validation failures return 400 with
// the 1Password error text; successful swaps log the transition on the
// proxy side. This endpoint is only registered if the SignerSource is a
// RefSwitcher — the test-only staticSigner does not provide it.
//
// Security note: this endpoint is loopback-only and unauthenticated,
// same trust boundary as /sign. Any process that can already steal
// signatures can also point us at a different item in the same vault;
// it cannot point us at items the service account can't read, since the
// swap is validated by actually resolving the new reference.
func refHandler(rs RefSwitcher) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<12))
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		newRef := strings.TrimSpace(string(body))
		if newRef == "" {
			http.Error(w, "empty reference", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(newRef, "op://") {
			http.Error(w, "reference must start with op://", http.StatusBadRequest)
			return
		}

		if err := rs.SetRef(r.Context(), newRef); err != nil {
			log.Printf("ref swap rejected: %v", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Return the new public key so the caller can confirm the swap
		// landed on the key they expected.
		signer, err := rs.Signer(r.Context())
		if err != nil {
			log.Printf("post-swap signer fetch: %v", err)
			http.Error(w, "signer unavailable after swap", http.StatusServiceUnavailable)
			return
		}
		line := ssh.MarshalAuthorizedKey(signer.PublicKey())
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(line)))
		_, _ = w.Write(line)
	}
}

// pubkeyHandler returns the OpenSSH-format public key line for the current
// 1Password-resolved signing key. Like /sign, it re-fetches on every
// request so the container-side shim always sees the live public key and
// can rotate its cache automatically.
func pubkeyHandler(src SignerSource) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		signer, err := src.Signer(r.Context())
		if err != nil {
			log.Printf("signer fetch: %v", err)
			http.Error(w, "signer unavailable", http.StatusServiceUnavailable)
			return
		}

		line := ssh.MarshalAuthorizedKey(signer.PublicKey())

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(line)))
		if r.Method == http.MethodHead {
			return
		}
		_, _ = w.Write(line)
	}
}
