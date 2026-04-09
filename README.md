# ssh-agent-proxy

A tiny localhost HTTP proxy that forwards SSHSIG sign requests to a
local ssh-agent. It exists so you can sign git commits from inside a
container (or any sandbox that can't bind-mount Unix sockets) while
the private key stays in whatever agent holds it on the host —
1Password Desktop, the stock OpenSSH agent, gpg-agent with SSH
support, yubikey-agent, anything that speaks the agent protocol.

## Why

Two problems compose badly:

1. **SSH keys in 1Password Desktop on Windows live behind a named
   pipe** (`\\.\pipe\openssh-ssh-agent`), not a Unix socket. A WSL2
   process can't open the pipe directly without a Windows-side
   helper.
2. **Sandboxed container runtimes like `docker sbx` can't bind-mount
   arbitrary Unix sockets** from the host into the workload. Even on
   a pure Linux box with a normal ssh-agent socket, you can't just
   forward it into a sandbox the usual way.

The common answer is "run a signing HTTP oracle on the host that
talks to the agent, and have the container hit it over HTTP" —
every sandbox leaves outbound network open. This repo is that oracle.

```
          ┌──────────────────────┐           ┌────────────────────────────┐
          │       host side      │           │     container / sandbox    │
          │                      │           │                            │
 agent ◄──┤  ssh-agent-proxy     │  HTTP     │  git commit -S             │
          │   :7221 /sign        │◄──────────┤   gpg.ssh.program =        │
          │        /publickey    │           │     ssh-agent-proxy-sign   │
          │        /healthz      │           │                            │
          └──────────────────────┘           └────────────────────────────┘
```

The proxy holds **no private key material** of its own. Every `/sign`
and `/publickey` request opens a fresh connection to the configured
agent, lets the agent do the cryptographic work, then closes the
connection. Key rotation in the upstream agent takes effect on the
very next request, with no proxy restart.

## Endpoints

- **`POST /sign`** — body is raw bytes to sign, response is an armored
  `-----BEGIN SSH SIGNATURE-----` block with namespace `git`.
  Byte-identical to `ssh-keygen -Y sign -n git` for deterministic
  signature schemes (Ed25519 and RSA `rsa-sha2-512`).
- **`GET /publickey`** — OpenSSH authorized_keys-format line for the
  key the proxy will sign with. The container-side shim uses this to
  auto-populate `user.signingkey` so you don't have to bake a specific
  key into the container image.
- **`GET /healthz`** — liveness probe.

## Backend / agent paths

The proxy dials whichever ssh-agent you point it at. Defaults per
platform:

| Platform | Default agent path | Override env var |
|---|---|---|
| Linux / macOS | `$SSH_AUTH_SOCK` | `SSH_AGENT_PROXY_UPSTREAM` |
| Windows | `\\.\pipe\openssh-ssh-agent` | `SSH_AGENT_PROXY_UPSTREAM` |

On Linux 1Password Desktop typically exposes its socket at
`~/.1password/agent.sock`; on macOS
`~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock`;
on Windows the standard OpenSSH agent named pipe is where 1Password
(and the Windows OpenSSH service) both listen. If you're happy with
whatever `SSH_AUTH_SOCK` already points at, leave
`SSH_AGENT_PROXY_UPSTREAM` unset and the proxy honors it.

## Environment variables

| Var | Default | Purpose |
|---|---|---|
| `SSH_AGENT_PROXY_ADDR` | `127.0.0.1:7221` | HTTP listen address |
| `SSH_AGENT_PROXY_NAMESPACE` | `git` | SSHSIG namespace |
| `SSH_AGENT_PROXY_UPSTREAM` | (see above) | Upstream agent path |
| `SSH_AGENT_PROXY_PUBKEY` | unset | Literal authorized_keys line; if set, pin signing to this specific key from the agent |
| `SSH_AGENT_PROXY_PUBKEY_FILE` | unset | Path to a file containing the pubkey line (ignored if `SSH_AGENT_PROXY_PUBKEY` is set) |

If neither `SSH_AGENT_PROXY_PUBKEY` nor `SSH_AGENT_PROXY_PUBKEY_FILE`
is set, the proxy uses the first key the agent advertises.

## Build

With make (Linux / macOS):

```sh
make build                 # ./bin/ssh-agent-proxy
make build-windows         # ./bin/ssh-agent-proxy.exe  (cross-compile)
make build-darwin          # ./bin/ssh-agent-proxy-darwin
make build-all             # all three

make install               # install to ~/.local/bin (override BINDIR=…)
make check                 # go vet + go test
```

Without make (Windows or anywhere with just `go`):

```powershell
go build -o ssh-agent-proxy.exe .\cmd\ssh-agent-proxy
# or, to install into %USERPROFILE%\go\bin:
go install .\cmd\ssh-agent-proxy
```

```sh
# Linux / macOS without make:
go build -o ssh-agent-proxy ./cmd/ssh-agent-proxy
# or:
go install ./cmd/ssh-agent-proxy
```

Pure Go, no CGo, no MinGW, no build-tag gymnastics. Requires
Go 1.25+ (pinned in `go.mod`). Cross-compiles work from any host
to any target.

## Run it interactively

```sh
# Point at your local ssh-agent and start the proxy
export SSH_AUTH_SOCK=$HOME/.1password/agent.sock   # or whatever
./bin/ssh-agent-proxy
# listening on 127.0.0.1:7221 (namespace "git")
```

Quick smoke test from another shell:

```sh
curl -s http://127.0.0.1:7221/publickey
# ssh-ed25519 AAAA… user@host

printf 'hello\n' | curl -s --data-binary @- http://127.0.0.1:7221/sign
# -----BEGIN SSH SIGNATURE-----
# …
# -----END SSH SIGNATURE-----
```

## Run as a systemd user service (Linux / WSL2 / macOS)

### WSL2 one-time prerequisites

Skip if you're not on WSL2.

1. Enable systemd in `/etc/wsl.conf`:
   ```ini
   [boot]
   systemd=true
   ```
   Then `wsl --shutdown` from PowerShell / cmd and re-open your shell.

2. Enable lingering so user services survive closing your last WSL
   terminal:
   ```sh
   sudo loginctl enable-linger "$USER"
   ```

### Install

```sh
make install-systemd       # build + install + drop unit + drop env template
$EDITOR ~/.config/ssh-agent-proxy/env        # point SSH_AUTH_SOCK or SSH_AGENT_PROXY_UPSTREAM
systemctl --user enable --now ssh-agent-proxy.service
make status                # or: make logs
```

`install-systemd` is idempotent and preserves the existing env file
on re-runs. The shipped unit enables a comprehensive systemd sandbox
(`ProtectSystem=strict`, `ProtectHome=read-only`, `NoNewPrivileges`,
`LockPersonality`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`,
`LimitMEMLOCK=infinity`, `LimitCORE=0`, and the rest of the usual
hardening set).

To remove:

```sh
make uninstall-systemd     # preserves ~/.config/ssh-agent-proxy/env
```

## Run as a Windows service

```powershell
# In PowerShell, as Administrator
# Set whichever env vars you want baked into the service
$env:SSH_AGENT_PROXY_UPSTREAM = "\\.\pipe\openssh-ssh-agent"
$env:SSH_AGENT_PROXY_PUBKEY_FILE = "$env:USERPROFILE\.ssh\git_signing.pub"

# Install (runs as the current user by default — required to reach
# per-user agent pipes like 1Password Desktop's)
.\ssh-agent-proxy.exe install

# It will prompt for your Windows password so the SCM can launch the
# service as your account. Pass -password on the command line instead
# if you're automating.

sc start ssh-agent-proxy
```

Flags on `install`:

- `-user DOMAIN\user` — override the run-as user (default: current
  user from `USERDOMAIN\USERNAME`)
- `-password PASS` — password for `-user`; prompted on stdin if
  omitted
- `-system` — install as `LocalSystem` instead. Only works if the
  upstream agent's named pipe is accessible to SYSTEM (1Password
  Desktop's pipe typically is **not**, because it lives in the user
  session).

The service logs to `%LOCALAPPDATA%\ssh-agent-proxy\service.log`
(per-user, ACLed to the run-as account).

Uninstall with `.\ssh-agent-proxy.exe uninstall`.

## Use it from a container

### Install the shim

```dockerfile
COPY scripts/ssh-agent-proxy-sign.sh /usr/local/bin/ssh-agent-proxy-sign
RUN chmod +x /usr/local/bin/ssh-agent-proxy-sign && \
    apt-get update && apt-get install -y --no-install-recommends \
        curl openssh-client ca-certificates && \
    rm -rf /var/lib/apt/lists/*
```

`openssh-client` is needed only if you also want to *verify*
signatures inside the container — the shim delegates `-Y verify` /
`-Y check-novalidate` to the real `ssh-keygen`. If you only sign, you
can drop it.

### Git config

```sh
git config --global gpg.format      ssh
git config --global gpg.ssh.program /usr/local/bin/ssh-agent-proxy-sign
git config --global user.signingkey ~/.cache/ssh-agent-proxy-sign/signing.pub
git config --global commit.gpgsign  true
git config --global tag.gpgsign     true
```

Note that `user.signingkey` points at a path that **doesn't exist
yet**. The shim auto-populates it from the proxy's `/publickey`
endpoint on first use, so the container never needs to bake in a
specific public key. To pick up a rotated key, `rm` the cache file
and it refreshes on the next commit.

### Networking

The proxy binds `127.0.0.1:7221` on the host. Simplest container
networking:

```sh
docker run --network host …
```

If your runtime can't do `--network host` (e.g. `docker sbx`), bind
the proxy to `0.0.0.0:7221` with
`SSH_AGENT_PROXY_ADDR=0.0.0.0:7221` and give the container a
host-gateway hop:

```sh
docker run --add-host=host.docker.internal:host-gateway \
    -e SSH_AGENT_PROXY_URL=http://host.docker.internal:7221/sign \
    …
```

Be aware that binding `0.0.0.0` exposes the signing endpoint to
anything that can reach the host interface. The trust boundary is
"any local process as your user can request signatures", same as
`ssh-agent`.

### Shim environment variables (container side)

| Var | Default | Purpose |
|---|---|---|
| `SSH_AGENT_PROXY_URL` | `http://127.0.0.1:7221/sign` | Sign endpoint URL |
| `SSH_AGENT_PROXY_PUBKEY_URL` | derived from `SSH_AGENT_PROXY_URL` | Public-key endpoint URL |
| `SSH_AGENT_PROXY_CURL` | `curl` | Override the curl binary |

## How the signing works under the hood

`sshsig/` is a from-scratch, pure-Go implementation of OpenSSH's
[SSHSIG wire format](https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.sshsig)
plus the 70-column PEM-like armor. Given any `ssh.Signer`, it
produces an armored signature byte-identical to what `ssh-keygen -Y
sign -n git` would have produced for deterministic signature schemes
(Ed25519, and RSA with `rsa-sha2-512` / PKCS#1 v1.5). There are
byte-equality tests against `ssh-keygen` in `sshsig/sshsig_test.go`.

The `ssh.Signer` we feed it is an `agentBackedSigner` wrapping a
`golang.org/x/crypto/ssh/agent.ExtendedAgent` client. For RSA keys
we force the `rsa-sha2-512` flag and verify the agent honored it —
a misbehaving agent that tried to downgrade to SHA-1 would be
rejected rather than returning a signature that modern verifiers
won't accept.

## Security notes

### Threat model

**Defends against:**

- Another unprivileged process on the same host scraping
  `/proc/$pid/mem` or attaching via `ptrace` (Linux:
  `prctl(PR_SET_DUMPABLE, 0)`; macOS: `ptrace(PT_DENY_ATTACH)`;
  Windows: process mitigation policies + strict handle checks).
- Transient buffers ending up in a swap file (Linux and macOS:
  `mlockall(MCL_CURRENT|MCL_FUTURE)`; the systemd user unit sets
  `LimitMEMLOCK=infinity` so this doesn't silently fall back to
  "swap protection off").
- Transient buffers ending up in a core dump (Linux and macOS:
  `RLIMIT_CORE=0` + `PR_SET_DUMPABLE=0`; systemd unit: `LimitCORE=0`;
  Windows: `SetErrorMode` + crash-dump suppression).
- Re-gaining privileges on exec (`PR_SET_NO_NEW_PRIVS=1` on Linux,
  `NoNewPrivileges=true` in the systemd unit, no setuid-alike on the
  other platforms).
- Rotation drift. The proxy does not cache the signer across
  requests. Rotate the key in the upstream agent and the very next
  sign uses the new key.
- The container seeing the private key. It doesn't, ever. The
  container sees only signatures and (optionally) the public key.

**Does NOT defend against:**

- Root on the same host. Root can read `/proc/$pid/mem`, load a
  kernel module, use EndpointSecurity on macOS, or enable
  `SeDebugPrivilege` on Windows. Userspace mitigations don't hold
  against the kernel.
- A compromised upstream agent. The proxy trusts the agent to return
  honest signatures; we sanity-check the returned signature format
  against what we requested, but we can't tell whether the agent is
  signing with the right private key.
- Other processes running as your own user. Any of them can already
  call `/sign` or talk to the agent directly. Same trust boundary as
  `ssh-agent`.
- Hardware attacks (cold boot, DMA, physical access).
- The internals of the ssh-agent process, wherever it is.

### Config hygiene

- On Linux/macOS, `~/.config/ssh-agent-proxy/env` should be 0600 and
  under `ProtectHome=read-only` in the systemd unit. Don't check it
  into dotfiles git.
- On Windows, the install subcommand persists env vars into the
  service's `HKLM\SYSTEM\CurrentControlSet\Services\ssh-agent-proxy\Environment`
  REG_MULTI_SZ. The registry key is ACLed the same way the rest of
  the service's config is — only Administrators and SYSTEM can
  rewrite it.
- Service logs land in `%LOCALAPPDATA%\ssh-agent-proxy\service.log`
  rather than `%ProgramData%`, which keeps them out of the
  world-readable default.

### HTTP authentication

There is none. Any local process running as your user can call
`/sign` and get signatures, just like any local process can use
`ssh-agent`. For stronger isolation, bind the proxy to a Unix socket
you bind-mount selectively into containers (requires a small patch —
`SSH_AGENT_PROXY_ADDR` is TCP-only today) or put a bearer token in
front of `/sign` and `/publickey`.

## Repo layout

| Path | What |
|---|---|
| `cmd/ssh-agent-proxy/main.go` | Config loading, HTTP server, signal handling |
| `cmd/ssh-agent-proxy/source_agent.go` | Generic `AgentSource` + `agentBackedSigner` |
| `cmd/ssh-agent-proxy/source_agent_unix.go` | Unix socket dialer (linux / darwin / bsd) |
| `cmd/ssh-agent-proxy/source_agent_windows.go` | Windows named-pipe dialer (go-winio) |
| `cmd/ssh-agent-proxy/service_windows.go` | Windows service install/uninstall + `svc.Run` handler |
| `cmd/ssh-agent-proxy/service_other.go` | No-op stubs for non-Windows |
| `cmd/ssh-agent-proxy/hardening_{linux,darwin,windows,other}.go` | Per-platform process hardening |
| `sshsig/` | Pure-Go SSHSIG wire format + OpenSSH armor |
| `scripts/ssh-agent-proxy-sign.sh` | Container-side `gpg.ssh.program` shim |
| `contrib/systemd/ssh-agent-proxy.service` | systemd **user** unit |
| `contrib/systemd/env.example` | `EnvironmentFile=` template |

## Tests

```sh
make check       # go vet + go test ./...
```

Twelve tests cover the HTTP handlers, the shim script end-to-end,
live-ssh-agent integration for `AgentSource` (including pubkey
selection and error paths), and the `sshsig` package's byte-equality
claims against real `ssh-keygen`. Tests that shell out to
`ssh-keygen`, `ssh-agent`, or `ssh-add` skip themselves when those
binaries aren't installed, so the suite runs in minimal CI images.
