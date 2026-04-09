# op-sign-proxy

A tiny localhost HTTP proxy that signs arbitrary bytes with an SSH
private key fetched from [1Password](https://1password.com) on **every
request**, implementing the
[SSHSIG](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
wire format in pure Go.

The intended use case: **sign git commits from inside a container
without ever giving the container access to the private key**. The
proxy runs on the host (or in your WSL2 distro), resolves the key from
a 1Password service account every time it needs to sign, and exposes a
loopback endpoint that the container calls through a small
`gpg.ssh.program` shim.

```
          ┌──────────────────────┐           ┌────────────────────────────┐
          │   host / WSL2 side   │           │      container side        │
          │                      │           │                            │
 1Password│  op-sign-proxy       │  HTTP     │  git commit -S             │
 ─────────┤  :7221 /sign         │◄──────────┤  gpg.ssh.program =         │
 vault    │       /publickey     │           │    op-git-sign.sh          │
       ◄──┼─  (fetch per req)    │           │                            │
          │       /ref           │           │                            │
          └──────────────────────┘           └────────────────────────────┘
```

- **`/sign`** — `POST` raw bytes, get an armored
  `-----BEGIN SSH SIGNATURE-----` back with namespace `git`.
  Byte-identical to `ssh-keygen -Y sign` for deterministic schemes
  (Ed25519, RSA `rsa-sha2-512`). The private key is resolved from
  1Password fresh on every call — nothing is cached across requests,
  and rotating the key in 1Password takes effect immediately.
- **`/publickey`** — `GET` the OpenSSH-format public key line for
  the key 1Password is currently serving. Lets the container-side shim
  fetch and cache the pubkey on demand so **no specific key is baked
  into the container** (see [Dynamic public key](#dynamic-public-key)).
- **`/ref`** — `POST` a new `op://vault/item/field` reference (plain
  text body) to swap the proxy to a different 1Password item at
  runtime, without a restart. The swap is validated before committing;
  a bad reference leaves the previous one in place. Response body is
  the new public key line on success.
- **`/healthz`** — liveness probe.

The private key is **never cached in memory across requests** and
**never written to disk**. Combined with Linux/macOS process hardening
(`mlockall`, `PR_SET_DUMPABLE=0` / `PT_DENY_ATTACH`, `RLIMIT_CORE=0`)
this narrows the window where a local attacker could see it to a
single in-flight request. See [Security notes](#security-notes) for
what this does and does not protect.

---

## Repo layout

| Path | What |
|---|---|
| `main.go` | HTTP server, 1Password SDK wiring, graceful shutdown |
| `sshsig/` | Pure-Go SSHSIG wire-format + OpenSSH armor implementation |
| `scripts/op-git-sign.sh` | Container-side `gpg.ssh.program` shim |
| `contrib/systemd/op-sign-proxy.service` | systemd **user** unit |
| `contrib/systemd/env.example` | Example `EnvironmentFile` template |
| `sshsig/sshsig_test.go` | Byte-for-byte equality tests vs. `ssh-keygen -Y sign` |
| `main_test.go` | HTTP + shell-shim integration tests |

---

## Build

```sh
make build                # → ./bin/op-sign-proxy
make install              # → ~/.local/bin/op-sign-proxy (override BINDIR=…)
```

Or, without the Makefile:

```sh
go build ./...
go install .              # drops op-sign-proxy in $(go env GOBIN) or ~/go/bin
```

Go 1.25+ (as pinned in `go.mod`) and an internet connection for the
1Password WASM blob on first build. No CGo.

Run `make` with no arguments to list all targets.

## Test

```sh
make check                # go vet + go test
# or:
go test ./...
```

Tests that compare against `ssh-keygen -Y sign` auto-skip if
`openssh-client` isn't installed, so they're safe in minimal CI images.

---

## Configure

The proxy reads two required environment variables:

| Var | Meaning |
|---|---|
| `OP_SERVICE_ACCOUNT_TOKEN` | 1Password service-account token (`ops_…`). Create one at <https://developer.1password.com/docs/service-accounts/>. |
| `OP_SSH_KEY_REF` | Secret reference to the private-key field, e.g. `op://Personal/Git Signing/private key`. |

And two optional ones:

| Var | Default | Meaning |
|---|---|---|
| `OP_SIGN_PROXY_ADDR` | `127.0.0.1:7221` | Listen address. |
| `OP_SIGN_PROXY_NAMESPACE` | `git` | SSHSIG namespace. Leave alone for git signing. |

### 1Password item setup

1. In 1Password, create an **SSH Key** item in a vault your service account
   can read. Either import an existing Ed25519 / RSA key or let 1Password
   generate a new one.
2. Create a service account with read access to that vault only, and grab
   the `ops_…` token.
3. Build the secret reference: `op://<vault>/<item>/<field>`. For a stock
   SSH-Key item the field is `private key`.

### Run it once to verify

```sh
export OP_SERVICE_ACCOUNT_TOKEN=ops_eyJ…
export OP_SSH_KEY_REF='op://Personal/Git Signing/private key'
op-sign-proxy
# listening on 127.0.0.1:7221 (namespace "git")
```

Quick smoke test from another shell:

```sh
curl -s http://127.0.0.1:7221/publickey
# ssh-ed25519 AAAA… op-sign-proxy

printf 'hello\n' | curl -s --data-binary @- http://127.0.0.1:7221/sign
# -----BEGIN SSH SIGNATURE-----
# …
# -----END SSH SIGNATURE-----
```

---

## Run it as a systemd user service (Linux / WSL2)

The proxy is personal (your token, your key, loopback only), so it belongs
as a **user** service, not a system-wide one. No root needed.

### One-time WSL2 prerequisites

Skip this section on a normal Linux box.

1. **Enable systemd in WSL2.** Edit `/etc/wsl.conf` inside the distro:

   ```ini
   [boot]
   systemd=true
   ```

   Then from PowerShell / cmd on the Windows side: `wsl --shutdown`, and
   re-open your WSL shell. Verify with `systemctl --user status`.

2. **Enable lingering for your user** so the service keeps running after
   you close your WSL terminal:

   ```sh
   sudo loginctl enable-linger "$USER"
   ```

   Without this, user services die when the last session exits, which is
   the #1 footgun running systemd user units under WSL2.

### Install

The `Makefile` wraps all of this up:

```sh
make install-systemd      # build + install binary + drop unit + drop env template
$EDITOR ~/.config/op-sign-proxy/env
systemctl --user enable --now op-sign-proxy.service
make status               # or: make logs   (tails the journal)
```

`install-systemd` is idempotent and will **not** clobber an existing
`~/.config/op-sign-proxy/env` — it only drops the template on first run,
so re-running it to update the binary or unit file is safe. To remove:

```sh
make uninstall-systemd    # stops, disables, removes unit. Env file preserved.
```

Under the hood, the steps it performs are:

```sh
# 1. Binary
go build -o ~/.local/bin/op-sign-proxy .

# 2. Config (token + secret reference, 0600)
install -d -m 0700 ~/.config/op-sign-proxy
install -m 0600 contrib/systemd/env.example ~/.config/op-sign-proxy/env
$EDITOR ~/.config/op-sign-proxy/env

# 3. Unit file
install -d ~/.config/systemd/user
install -m 0644 contrib/systemd/op-sign-proxy.service \
    ~/.config/systemd/user/op-sign-proxy.service

# 4. Enable + start
systemctl --user daemon-reload
systemctl --user enable --now op-sign-proxy.service
systemctl --user status op-sign-proxy.service

# Logs
journalctl --user -u op-sign-proxy.service -f
```

The included unit file turns on a reasonable systemd sandbox
(`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges`,
`SystemCallFilter=@system-service`, etc.). **`MemoryDenyWriteExecute` is
intentionally disabled** because the 1Password SDK JIT-compiles a WASM
module via wazero and needs `PROT_EXEC` mmap; enabling MDWX will make the
service die with a SIGSYS during `NewClient`.

---

## Container side

### Install the shim

```dockerfile
# Dockerfile (dev container)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl openssh-client ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY scripts/op-git-sign.sh /usr/local/bin/op-git-sign
RUN chmod +x /usr/local/bin/op-git-sign
```

`openssh-client` is only needed if you also want to **verify** SSH
signatures inside the container (the shim delegates `-Y verify` /
`check-novalidate` to the real `ssh-keygen`). If you only ever sign, you
can drop it.

### Git config

```sh
git config --global gpg.format      ssh
git config --global gpg.ssh.program /usr/local/bin/op-git-sign
git config --global user.signingkey "$HOME/.cache/op-git-sign/signing.pub"
git config --global commit.gpgsign  true
git config --global tag.gpgsign     true
```

Note what's **not** here: a literal `ssh-ed25519 AAAA…` public key. See
[Dynamic public key](#dynamic-public-key) below.

### Networking

The proxy binds `127.0.0.1:7221` on the host. The simplest way for a
container to reach it is:

```sh
docker run --network host …
```

If you need a bridge network instead, bind the proxy to `0.0.0.0:7221`
(`OP_SIGN_PROXY_ADDR=0.0.0.0:7221`) and run containers with
`--add-host=host.docker.internal:host-gateway`, then set
`OP_SIGN_PROXY_URL=http://host.docker.internal:7221/sign` inside the
container. Be aware that `0.0.0.0` exposes the signing endpoint to
anything else that can route to the host — prefer `--network host` when
you can.

On WSL2 specifically, Docker Desktop on Windows and native Docker-in-WSL
both treat the WSL2 distro as the host for `host.docker.internal`
purposes, so the same two approaches apply.

### Dynamic public key

Normally `user.signingkey` has to be a literal public key or a path to
one, which is annoying for containers: the image either hardcodes the key
(breaks on rotation) or you bind-mount a file from the host.

`op-sign-proxy` and `op-git-sign` cooperate to avoid that:

1. The proxy exposes `GET /publickey`, returning the OpenSSH-format line
   for the key it loaded from 1Password.
2. `op-git-sign`, when git hands it `-f <path>` for a path that **does
   not exist yet**, fetches `/publickey` and writes the result to that
   path before signing.
3. Setting `user.signingkey = ~/.cache/op-git-sign/signing.pub` therefore
   Just Works on a fresh container: the first `git commit -S` materializes
   the cache file transparently.
4. If you rotate the key in 1Password, `rm ~/.cache/op-git-sign/signing.pub`
   on each container and it will re-sync on next commit.

If you'd rather bootstrap explicitly (e.g. to populate
`gpg.ssh.allowedSignersFile` too), the shim has a subcommand:

```sh
op-git-sign pubkey
# ssh-ed25519 AAAA… op-sign-proxy

op-git-sign pubkey ~/.config/git/allowed_signers.key   # write to a file
```

---

## How it compares to `ssh-keygen`

The `sshsig` package is a self-contained reimplementation of
[`PROTOCOL.sshsig`](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
plus OpenSSH's 70-column base64 armor (`sshbuf_dtob64`). The test suite
asserts **byte-for-byte equality** with `ssh-keygen -Y sign -n git` for:

- Ed25519 keys (deterministic by construction)
- RSA-2048 keys with `rsa-sha2-512` / PKCS#1 v1.5 (also deterministic)

For other/nondeterministic algorithms we fall back to a
`ssh-keygen -Y check-novalidate` round-trip to prove ssh-keygen accepts
our output. The key-type branch in `sshsig.Sign` explicitly uses
`AlgorithmSigner.SignWithAlgorithm(…, ssh.KeyAlgoRSASHA512)` for RSA to
avoid golang.org/x/crypto/ssh's SHA-1 default, which ssh-keygen would
reject.

---

## Security notes

### Threat model

**Defends against:**

- An attacker with remote network access. The proxy binds `127.0.0.1`
  only; nothing listens on an external interface.
- Another unprivileged local process (not your user) scraping the key
  from `/proc/$pid/mem` or attaching via `ptrace`. On Linux we call
  `prctl(PR_SET_DUMPABLE, 0)` early in `main`, which makes the process
  undebuggable except by root and makes `/proc/$pid/mem` root-only.
  On macOS we call `ptrace(PT_DENY_ATTACH, 0, 0, 0)` for the same
  effect (officially deprecated but still functional).
- Key material ending up in a swap file. On Linux and macOS we
  `mlockall(MCL_CURRENT | MCL_FUTURE)` at startup, so no page of this
  process can be paged to disk. The systemd user unit sets
  `LimitMEMLOCK=infinity` so this doesn't silently fall back to "swap
  protection off".
- Key material ending up in a core dump. We drop `RLIMIT_CORE=0`
  ourselves, `PR_SET_DUMPABLE=0` disables kernel-triggered dumps, and
  the systemd unit also sets `LimitCORE=0` — triple belt-and-suspenders.
- Re-gaining privileges on exec. We set `PR_SET_NO_NEW_PRIVS=1` on
  Linux and the systemd unit sets `NoNewPrivileges=true`.
- Key rotation drift: the proxy **re-fetches the private key from
  1Password on every `/sign` and `/publickey` request**. There is no
  in-memory cache of the signer across requests. Rotating the key in
  1Password takes effect on the very next request, at the cost of one
  SDK round-trip per sign.
- The container seeing the key. The container never receives the
  private key; it only ever sees signatures (and, optionally, the
  public key line fetched from `/publickey`).

**Does NOT defend against:**

- Root on the same host. Root can read `/proc/$pid/mem`, load a kernel
  module, use EndpointSecurity on macOS, or trace syscalls regardless
  of any userspace mitigation.
- Another process running as your own user. It can already call
  `/sign` and get arbitrary signatures. Same trust boundary as
  `ssh-agent`.
- The 1Password SDK's internal memory. The SDK returns secrets as Go
  `string` values, which are immutable; we cannot zero the PEM bytes
  after use, and the SDK may hold its own copies inside its wazero
  runtime. "Key not held in memory across requests" means "we, the
  proxy, do not keep a reference" — it does not mean the bytes have
  been scrubbed from every address the runtime ever put them in.
- Hardware attacks (cold-boot, DMA, physical access).
- A compromised 1Password service account token. Anyone with the token
  can read the same secret the proxy reads, with or without the proxy.

### Config hygiene

- The service-account token lives in `~/.config/op-sign-proxy/env` at
  mode 0600. systemd reads it before the service starts; the service
  itself runs with `ProtectHome=read-only` and never writes to disk.
- Don't check the env file into git. Don't log its contents. Don't
  export `OP_SERVICE_ACCOUNT_TOKEN` in your interactive shell unless
  you also scope it with a subshell — children inherit it.

### Authentication on the HTTP endpoints

The proxy does not implement per-request authentication or rate
limiting. Any local process running as your user can call `/sign`,
`/publickey`, or `/ref` without a token. This is the same trust
boundary as `ssh-agent`, and for a personal signing proxy on a dev
machine it is the right tradeoff.

If you need stronger isolation:

- Run the proxy on a Unix socket you bind-mount selectively into
  containers (`OP_SIGN_PROXY_ADDR` is currently TCP-only; you'd need
  a small patch).
- Put a minimal bearer-token check in front of `/sign` and `/ref`.
- Use the `POST /ref` endpoint to ensure the proxy is only pointing at
  the key you intend — a compromised local process can swap it to
  another item in the same vault, but cannot point it at items the
  service account can't read (the swap validates by actually
  resolving the new reference first).

### Runtime secret-reference swap

`POST /ref` accepts a plain-text body with a new `op://vault/item/field`
reference. The swap is atomic with respect to in-flight `/sign`
requests (both paths serialize on the same mutex) and validates the
new reference by doing a fresh resolve+parse before committing. On
success the response body is the new public key line. On failure the
previous reference is untouched.

```sh
curl --silent --fail \
    --data "op://Personal/Git Signing (new)/private key" \
    http://127.0.0.1:7221/ref
# ssh-ed25519 AAAA… op-sign-proxy
```

This is the rotation escape hatch for scenarios where you create the
new key alongside the old one in a different item, validate it, and
then want to flip the proxy to it without a restart.
