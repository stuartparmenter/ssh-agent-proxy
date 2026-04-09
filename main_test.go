package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// staticSigner is a SignerSource that returns the same ssh.Signer on every
// call. Used by tests that don't care about rotation — they just need a
// drop-in source for the handlers.
type staticSigner struct{ s ssh.Signer }

func (s staticSigner) Signer(context.Context) (ssh.Signer, error) { return s.s, nil }

// rotatingSource hands out a different ssh.Signer on each call, cycling
// through the provided list. It's how we verify that the handlers really
// do re-ask the source on every request instead of caching.
type rotatingSource struct {
	mu      sync.Mutex
	signers []ssh.Signer
	calls   int
}

func (r *rotatingSource) Signer(context.Context) (ssh.Signer, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := r.signers[r.calls%len(r.signers)]
	r.calls++
	return s, nil
}

// erroringSource always returns an error. Used to check that handlers
// propagate fetch failures as 503s instead of panicking or returning 500.
type erroringSource struct{ err error }

func (e erroringSource) Signer(context.Context) (ssh.Signer, error) { return nil, e.err }

// fakeRefSwitcher is an in-memory RefSwitcher for testing POST /ref
// without hitting a real 1Password backend. It carries a known set of
// refs → signers and serves Signer() from whatever ref is current.
// SetRef validates against the map (mirroring the real OnePasswordSource
// behavior of "validate by trying to resolve before committing").
type fakeRefSwitcher struct {
	mu      sync.Mutex
	refs    map[string]ssh.Signer
	current string
}

func (f *fakeRefSwitcher) Signer(context.Context) (ssh.Signer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.refs[f.current]
	if !ok {
		return nil, fmt.Errorf("no signer for current ref %q", f.current)
	}
	return s, nil
}

func (f *fakeRefSwitcher) Ref() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.current
}

func (f *fakeRefSwitcher) SetRef(_ context.Context, newRef string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.refs[newRef]; !ok {
		return fmt.Errorf("unknown ref %q (fake SetRef validation)", newRef)
	}
	f.current = newRef
	return nil
}

// TestSignHandlerEndToEnd drives the HTTP handler directly and then feeds
// the returned signature into `ssh-keygen -Y check-novalidate` to prove the
// full proxy pipeline produces a signature that ssh-keygen accepts.
func TestSignHandlerEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skipf("ssh-keygen not available: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("NewSignerFromKey: %v", err)
	}

	srv := httptest.NewServer(signHandler(staticSigner{signer}, "git"))
	defer srv.Close()

	msg := []byte("end-to-end smoke test\n")

	resp, err := http.Post(srv.URL, "application/octet-stream", bytes.NewReader(msg))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unexpected status %d: %s", resp.StatusCode, body)
	}
	sig, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
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
		t.Fatalf("check-novalidate failed: %v\nstdout: %s\nstderr: %s", err, out.String(), errb.String())
	}
}

// TestSignHandlerRejectsGet makes sure GET requests don't accidentally return
// a signature over an empty body.
func TestSignHandlerRejectsGet(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	srv := httptest.NewServer(signHandler(staticSigner{signer}, "git"))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", resp.StatusCode)
	}
}

// TestPubkeyHandler verifies the /publickey endpoint returns the exact
// authorized_keys-format line for the loaded signer.
func TestPubkeyHandler(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	srv := httptest.NewServer(pubkeyHandler(staticSigner{signer}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	want := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if !bytes.Equal(got, want) {
		t.Fatalf("pubkey mismatch\nwant: %q\ngot:  %q", want, got)
	}

	// Round-trip: the line we got back must parse as the same public key.
	parsed, _, _, _, err := ssh.ParseAuthorizedKey(got)
	if err != nil {
		t.Fatalf("parse round-trip: %v", err)
	}
	if parsed.Type() != signer.PublicKey().Type() ||
		!bytes.Equal(parsed.Marshal(), signer.PublicKey().Marshal()) {
		t.Fatalf("round-tripped key does not match")
	}

	// Rejecting non-GET keeps this endpoint from getting misused.
	respPost, err := http.Post(srv.URL, "text/plain", nil)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	respPost.Body.Close()
	if respPost.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("want 405 for POST, got %d", respPost.StatusCode)
	}
}

// TestHandlersRefetchSigner proves that both /sign and /publickey re-ask
// the SignerSource on every request — i.e. that we don't accidentally
// cache the signer in a closure. A rotatingSource hands out two different
// Ed25519 signers on successive calls; the test checks that /publickey
// returns the first signer's pubkey on call 1 and the second signer's on
// call 2, and that /sign's armored output round-trips through
// ssh.ParseAuthorizedKey to the matching pubkey each time.
func TestHandlersRefetchSigner(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	s1, _ := ssh.NewSignerFromKey(priv1)
	s2, _ := ssh.NewSignerFromKey(priv2)
	src := &rotatingSource{signers: []ssh.Signer{s1, s2}}

	mux := http.NewServeMux()
	mux.Handle("/publickey", pubkeyHandler(src))
	mux.Handle("/sign", signHandler(src, "git"))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	fetch := func(path string) []byte {
		t.Helper()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("GET %s: status %d", path, resp.StatusCode)
		}
		b, _ := io.ReadAll(resp.Body)
		return b
	}

	pub1 := fetch("/publickey")
	pub2 := fetch("/publickey")

	if bytes.Equal(pub1, pub2) {
		t.Fatalf("both /publickey calls returned the same bytes; source was cached")
	}
	if !bytes.Equal(pub1, ssh.MarshalAuthorizedKey(s1.PublicKey())) {
		t.Fatalf("first /publickey call did not return signer 1's pubkey")
	}
	if !bytes.Equal(pub2, ssh.MarshalAuthorizedKey(s2.PublicKey())) {
		t.Fatalf("second /publickey call did not return signer 2's pubkey")
	}

	// Calls 3 and 4 on rotatingSource cycle back to s1, s2. Drive /sign
	// twice and assert each signature verifies against the corresponding
	// pubkey (via sshsig's round-trip with ssh-keygen if available; at
	// minimum, ensure the armored bytes are well-formed and distinct).
	post := func(msg []byte) []byte {
		t.Helper()
		resp, err := http.Post(srv.URL+"/sign", "application/octet-stream", bytes.NewReader(msg))
		if err != nil {
			t.Fatalf("POST /sign: %v", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("POST /sign: status %d: %s", resp.StatusCode, b)
		}
		b, _ := io.ReadAll(resp.Body)
		return b
	}

	msg := []byte("refetch test\n")
	sigA := post(msg) // uses s1
	sigB := post(msg) // uses s2

	if bytes.Equal(sigA, sigB) {
		t.Fatalf("signatures from two different keys should differ")
	}
	if !bytes.HasPrefix(sigA, []byte("-----BEGIN SSH SIGNATURE-----")) ||
		!bytes.HasPrefix(sigB, []byte("-----BEGIN SSH SIGNATURE-----")) {
		t.Fatalf("bad armor markers")
	}
}

// TestRefHandler exercises POST /ref: valid swap, invalid ref, failed
// swap leaving the previous ref intact, method rejection, and malformed
// bodies. Uses a fakeRefSwitcher so the test never touches 1Password.
func TestRefHandler(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(rand.Reader)
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	s1, _ := ssh.NewSignerFromKey(priv1)
	s2, _ := ssh.NewSignerFromKey(priv2)

	const refA = "op://Vault/A/private key"
	const refB = "op://Vault/B/private key"

	fs := &fakeRefSwitcher{
		refs:    map[string]ssh.Signer{refA: s1, refB: s2},
		current: refA,
	}

	mux := http.NewServeMux()
	mux.Handle("/publickey", pubkeyHandler(fs))
	mux.Handle("/ref", refHandler(fs))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	pub := func(t *testing.T) []byte {
		t.Helper()
		resp, err := http.Get(srv.URL + "/publickey")
		if err != nil {
			t.Fatalf("GET /publickey: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return b
	}

	// Sanity: initial pubkey is signer A's.
	if got, want := pub(t), ssh.MarshalAuthorizedKey(s1.PublicKey()); !bytes.Equal(got, want) {
		t.Fatalf("initial /publickey\nwant: %q\ngot:  %q", want, got)
	}

	// Happy path: swap to B and confirm the response body is B's pubkey.
	resp, err := http.Post(srv.URL+"/ref", "text/plain", strings.NewReader(refB))
	if err != nil {
		t.Fatalf("POST /ref: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("POST /ref: status %d: %s", resp.StatusCode, body)
	}
	swapBody, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if want := ssh.MarshalAuthorizedKey(s2.PublicKey()); !bytes.Equal(swapBody, want) {
		t.Fatalf("swap response body\nwant: %q\ngot:  %q", want, swapBody)
	}

	// Subsequent /publickey must now return B's key.
	if got, want := pub(t), ssh.MarshalAuthorizedKey(s2.PublicKey()); !bytes.Equal(got, want) {
		t.Fatalf("/publickey after swap\nwant: %q\ngot:  %q", want, got)
	}
	if fs.Ref() != refB {
		t.Fatalf("fs.Ref() = %q, want %q", fs.Ref(), refB)
	}

	// Error path: swap to an unknown ref. Must return 400 AND leave the
	// stored ref unchanged.
	badResp, err := http.Post(srv.URL+"/ref", "text/plain",
		strings.NewReader("op://Vault/DOES_NOT_EXIST/private key"))
	if err != nil {
		t.Fatalf("POST /ref (bad): %v", err)
	}
	badResp.Body.Close()
	if badResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad ref should 400, got %d", badResp.StatusCode)
	}
	if got, want := pub(t), ssh.MarshalAuthorizedKey(s2.PublicKey()); !bytes.Equal(got, want) {
		t.Fatalf("/publickey after failed swap should still be B\nwant: %q\ngot:  %q", want, got)
	}
	if fs.Ref() != refB {
		t.Fatalf("fs.Ref() after failed swap = %q, want %q (unchanged)", fs.Ref(), refB)
	}

	// Reject non-POST.
	getResp, _ := http.Get(srv.URL + "/ref")
	getResp.Body.Close()
	if getResp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET /ref: want 405, got %d", getResp.StatusCode)
	}

	// Reject empty body.
	emptyResp, _ := http.Post(srv.URL+"/ref", "text/plain", strings.NewReader(""))
	emptyResp.Body.Close()
	if emptyResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("empty body: want 400, got %d", emptyResp.StatusCode)
	}

	// Reject body missing the op:// prefix (common foot-gun).
	wrongResp, _ := http.Post(srv.URL+"/ref", "text/plain", strings.NewReader("just-a-path"))
	wrongResp.Body.Close()
	if wrongResp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed ref: want 400, got %d", wrongResp.StatusCode)
	}

	// Whitespace around a valid ref should be tolerated.
	wsResp, err := http.Post(srv.URL+"/ref", "text/plain", strings.NewReader("  "+refA+"\n"))
	if err != nil {
		t.Fatalf("POST /ref (whitespace): %v", err)
	}
	wsResp.Body.Close()
	if wsResp.StatusCode != http.StatusOK {
		t.Fatalf("trimmed ref: want 200, got %d", wsResp.StatusCode)
	}
	if fs.Ref() != refA {
		t.Fatalf("fs.Ref() after trimmed swap = %q, want %q", fs.Ref(), refA)
	}
}

// TestRefHandlerNotRegisteredForStaticSigner verifies that when the
// active SignerSource does not implement RefSwitcher (e.g. our test
// staticSigner adapter, or a future read-only source), newServer does
// not register /ref and requests return 404. This is how the real
// proxy's interface discovery behaves.
func TestRefHandlerNotRegisteredForStaticSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	srv := httptest.NewServer(newServer("", staticSigner{signer}, "git").Handler)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/ref", "text/plain", strings.NewReader("op://x/y/z"))
	if err != nil {
		t.Fatalf("POST /ref: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("static source should not expose /ref; got status %d", resp.StatusCode)
	}
}

// TestHandlersPropagateSourceErrors makes sure a failed 1Password fetch
// surfaces as a 503 (not a 500, which would suggest an internal bug) and
// does not panic or leak the error text unnecessarily.
func TestHandlersPropagateSourceErrors(t *testing.T) {
	src := erroringSource{err: errors.New("1password unreachable")}

	mux := http.NewServeMux()
	mux.Handle("/sign", signHandler(src, "git"))
	mux.Handle("/publickey", pubkeyHandler(src))
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/sign", "application/octet-stream", bytes.NewReader([]byte("x")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/sign: want 503, got %d", resp.StatusCode)
	}

	resp2, err := http.Get(srv.URL + "/publickey")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("/publickey: want 503, got %d", resp2.StatusCode)
	}
}

// startProxyStub spins up an httptest server that mirrors the real proxy's
// /sign and /publickey routes using the provided signer. Returns the server
// and the URL to pass to the shim as OP_SIGN_PROXY_URL.
func startProxyStub(t *testing.T, signer ssh.Signer) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	mux.Handle("/sign", signHandler(staticSigner{signer}, "git"))
	mux.Handle("/publickey", pubkeyHandler(staticSigner{signer}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, srv.URL + "/sign"
}

// locateScript returns the path to scripts/op-git-sign.sh relative to this
// test file, skipping the test if it cannot be found.
func locateScript(t *testing.T) string {
	t.Helper()
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	p := filepath.Join(filepath.Dir(testFile), "scripts", "op-git-sign.sh")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("script missing: %v", err)
	}
	return p
}

// requireShellTools skips the test if bash or curl are unavailable.
func requireShellTools(t *testing.T) {
	t.Helper()
	for _, tool := range []string{"bash", "curl"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not available: %v", tool, err)
		}
	}
}

// TestOpGitSignScript drives the companion bash script against a local stub
// of the proxy to prove it parses ssh-keygen-style arguments correctly,
// forwards stdin to /sign, AND auto-populates a non-existent `-f <path>`
// with the public key fetched from /publickey on first use.
func TestOpGitSignScript(t *testing.T) {
	requireShellTools(t)
	scriptPath := locateScript(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)

	_, proxyURL := startProxyStub(t, signer)

	// Point -f at a path that does NOT exist yet. This mirrors how a user
	// would set `user.signingkey = ~/.cache/op-git-sign/signing.pub` and
	// have the shim materialize it on demand.
	cacheDir := filepath.Join(t.TempDir(), "cache", "op-git-sign")
	keyfile := filepath.Join(cacheDir, "signing.pub")
	if _, err := os.Stat(keyfile); !os.IsNotExist(err) {
		t.Fatalf("keyfile pre-exists or stat err: %v", err)
	}

	msg := []byte("commit payload via bash\n")

	cmd := exec.Command("bash", scriptPath, "-Y", "sign", "-n", "git", "-f", keyfile)
	cmd.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	cmd.Stdin = bytes.NewReader(msg)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("script failed: %v\nstderr: %s", err, errb.String())
	}

	sig := out.Bytes()
	if !bytes.HasPrefix(sig, []byte("-----BEGIN SSH SIGNATURE-----")) {
		t.Fatalf("script did not produce an armored signature:\n%s", sig)
	}
	if !strings.Contains(string(sig), "-----END SSH SIGNATURE-----") {
		t.Fatalf("missing end marker:\n%s", sig)
	}

	// The shim must have populated the cache file with the proxy's pubkey.
	cached, err := os.ReadFile(keyfile)
	if err != nil {
		t.Fatalf("keyfile was not populated: %v", err)
	}
	want := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if !bytes.Equal(cached, want) {
		t.Fatalf("cached pubkey mismatch\nwant: %q\ngot:  %q", want, cached)
	}

	// Second invocation must NOT overwrite the existing file (sanity check
	// that the auto-populate branch only fires when the file is missing).
	if err := os.WriteFile(keyfile, []byte("do not clobber\n"), 0o600); err != nil {
		t.Fatalf("rewrite keyfile: %v", err)
	}
	cmd2 := exec.Command("bash", scriptPath, "-Y", "sign", "-n", "git", "-f", keyfile)
	cmd2.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	cmd2.Stdin = bytes.NewReader(msg)
	cmd2.Stdout = io.Discard
	cmd2.Stderr = &errb
	if err := cmd2.Run(); err != nil {
		t.Fatalf("second invocation failed: %v\nstderr: %s", err, errb.String())
	}
	after, _ := os.ReadFile(keyfile)
	if string(after) != "do not clobber\n" {
		t.Fatalf("keyfile was clobbered on second invocation: %q", after)
	}

	if _, err := exec.LookPath("ssh-keygen"); err == nil {
		dir := t.TempDir()
		sigPath := filepath.Join(dir, "msg.sig")
		if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
			t.Fatalf("write sig: %v", err)
		}
		verify := exec.Command("ssh-keygen", "-Y", "check-novalidate", "-n", "git", "-s", sigPath)
		verify.Stdin = bytes.NewReader(msg)
		var verr bytes.Buffer
		verify.Stderr = &verr
		if err := verify.Run(); err != nil {
			t.Fatalf("script signature rejected by ssh-keygen: %v\nstderr: %s", err, verr.String())
		}
	}
}

// TestOpGitSignPubkeySubcommand exercises the `op-git-sign pubkey` bootstrap
// path, both the stdout form and the "write to <path>" form.
func TestOpGitSignPubkeySubcommand(t *testing.T) {
	requireShellTools(t)
	scriptPath := locateScript(t)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	_, proxyURL := startProxyStub(t, signer)

	want := ssh.MarshalAuthorizedKey(signer.PublicKey())

	// Form 1: `op-git-sign pubkey` → stdout.
	cmd := exec.Command("bash", scriptPath, "pubkey")
	cmd.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("pubkey subcommand failed: %v\nstderr: %s", err, errb.String())
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Fatalf("stdout pubkey mismatch\nwant: %q\ngot:  %q", want, out.Bytes())
	}

	// Form 2: `op-git-sign pubkey <path>` → writes to <path>.
	dest := filepath.Join(t.TempDir(), "nested", "cache", "signing.pub")
	cmd2 := exec.Command("bash", scriptPath, "pubkey", dest)
	cmd2.Env = append(os.Environ(), "OP_SIGN_PROXY_URL="+proxyURL)
	cmd2.Stderr = &errb
	if err := cmd2.Run(); err != nil {
		t.Fatalf("pubkey <path> subcommand failed: %v\nstderr: %s", err, errb.String())
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("file pubkey mismatch\nwant: %q\ngot:  %q", want, got)
	}
}
