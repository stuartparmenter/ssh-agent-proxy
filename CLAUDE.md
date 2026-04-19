# CLAUDE.md

## Project

ssh-agent-proxy — a localhost HTTP signing proxy backed by any ssh-agent.
Written in Rust (edition 2024). Single binary, no runtime dependencies.

## Build & test

```sh
cargo build --release          # Linux
cargo test                     # requires ssh-keygen for SSHSIG byte-equality tests
cargo clippy -- -D warnings    # lint
cargo fmt -- --check           # format check
make build-windows             # cross-compile (needs mingw)
```

## Architecture

- `src/main.rs` — entry point, tokio runtime, signal handling, service dispatch
- `src/server.rs` — axum HTTP handlers (/sign, /publickey, /healthz)
- `src/config.rs` — env var config loading
- `src/sshsig.rs` — SSHSIG wire format (must produce output byte-identical to ssh-keygen)
- `src/agent.rs` — minimal SSH agent protocol client (LIST + SIGN only)
- `src/agent_source.rs` — dials agent per request, key selection, RSA sha2-512 upgrade
- `src/wire.rs` — shared SSH string read/write primitives
- `src/dialer_{unix,windows}.rs` — platform-specific agent connection
- `src/hardening_{linux,macos,windows}.rs` — process hardening (prctl, mlockall, etc.)
- `src/tray_windows.rs` — Windows tray icon + menu + message loop
- `src/autostart_windows.rs` — HKCU Run-key management
- `build.rs` + `assets/icon.{ico,rc}` — embeds the Win32 icon resource
- `wix/ssh-agent-proxy.wxs` — MSI installer definition (WiX v4+)

## Key design decisions

- Fresh agent connection per HTTP request — no caching, no key material held between requests
- `AgentBackedSigner` uses `Mutex` (not `RefCell`) for interior mutability because axum handlers require `Send`
- Signature format anti-downgrade check on ALL key types, not just RSA
- `DefaultBodyLimit` enforced at the axum layer, not just in-handler
- Platform code uses `#[cfg(target_os)]` / `#[cfg(unix)]` / `#[cfg(windows)]`
- Windows is a GUI-subsystem binary (`windows_subsystem = "windows"`); `--console` attaches to the parent console for debugging
- Default Windows run mode is a tray app — tokio runtime runs on a worker thread so the main thread can pump Win32 messages
- `run()` takes an `Arc<Notify>` so the tray's Exit menu can trigger graceful shutdown alongside the existing ctrl_c/SIGTERM paths

## Testing

The SSHSIG byte-equality tests are the most important — they prove the wire format
is correct by comparing against `ssh-keygen -Y sign` output. If those pass, the
signing pipeline is correct.

## Cross-compilation

Windows cross-compile from Linux requires `x86_64-pc-windows-gnu` target and
`gcc-mingw-w64-x86-64`. Native Windows builds use MSVC and avoid Smart App Control
issues that MinGW binaries can trigger.
