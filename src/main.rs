#![cfg_attr(windows, windows_subsystem = "windows")]

mod agent;
mod agent_source;
mod config;
mod server;
mod sshsig;
mod wire;

#[cfg(unix)]
mod dialer_unix;
#[cfg(windows)]
mod dialer_windows;

#[cfg(target_os = "linux")]
mod hardening_linux;
#[cfg(target_os = "macos")]
mod hardening_macos;
#[cfg(target_os = "windows")]
mod hardening_windows;

#[cfg(windows)]
mod autostart_windows;
#[cfg(windows)]
mod bind_address_windows;
#[cfg(windows)]
mod registry_windows;
#[cfg(windows)]
mod tray_windows;

use std::sync::Arc;
use tokio::sync::Notify;

#[cfg(windows)]
pub(crate) const APP_SLUG: &str = "ssh-agent-proxy";

pub(crate) fn harden_process() {
    #[cfg(target_os = "linux")]
    hardening_linux::harden();
    #[cfg(target_os = "macos")]
    hardening_macos::harden();
    #[cfg(target_os = "windows")]
    hardening_windows::harden();
}

fn main() {
    #[cfg(windows)]
    {
        let console_mode = std::env::args().any(|a| a == "--console");
        if console_mode {
            attach_parent_console();
            env_logger::init();
            harden_process();
            run_blocking();
        } else if let Err(e) = tray_windows::run_tray() {
            log::error!("tray: {e}");
            std::process::exit(1);
        }
    }

    #[cfg(not(windows))]
    {
        env_logger::init();
        harden_process();
        run_blocking();
    }
}

fn run_blocking() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to build tokio runtime");
    let shutdown = Arc::new(Notify::new());
    if let Err(e) = rt.block_on(run(shutdown)) {
        log::error!("ssh-agent-proxy: {e}");
        std::process::exit(1);
    }
}

pub(crate) async fn run(
    shutdown: Arc<Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let cfg = config::Config::from_env()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    let dialer: Box<dyn agent_source::AgentDialer> = {
        #[cfg(unix)]
        {
            Box::new(dialer_unix::UnixDialer::new(cfg.agent_path.clone()))
        }
        #[cfg(windows)]
        {
            Box::new(dialer_windows::NamedPipeDialer::new(cfg.agent_path.clone()))
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err("no agent dialer available on this platform".into());
        }
    };

    let source = agent_source::AgentSource::new(dialer, cfg.pubkey.clone());

    log::info!("signing via agent at {}", cfg.agent_path);
    if let Some(ref pk) = cfg.pubkey
        && let Ok(line) = config::marshal_authorized_key(pk)
    {
        log::info!("restricted to pubkey: {}", line.trim());
    }

    let state = Arc::new(server::AppState {
        source,
        namespace: cfg.namespace.clone(),
    });

    let app = server::router(state);
    let listener = bind_with_fallback(&cfg.addr).await?;
    log::info!(
        "listening on {} (namespace {:?})",
        listener.local_addr()?,
        cfg.namespace
    );

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal(shutdown))
        .await?;

    Ok(())
}

/// Bind the listener, falling back to loopback on the same port if the
/// requested address is unavailable (e.g. Tailscale mode selected but the
/// interface isn't up yet, or the bind failed with `EADDRNOTAVAIL`).
async fn bind_with_fallback(addr: &str) -> std::io::Result<tokio::net::TcpListener> {
    match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => Ok(l),
        Err(e) => {
            let fallback = fallback_addr(addr);
            if fallback == addr {
                return Err(e);
            }
            log::warn!("bind {addr} failed ({e}); falling back to {fallback}");
            tokio::net::TcpListener::bind(&fallback)
                .await
                .map_err(|e2| {
                    log::error!("fallback bind to {fallback} also failed: {e2}");
                    e2
                })
        }
    }
}

fn fallback_addr(addr: &str) -> String {
    let port = addr
        .parse::<std::net::SocketAddr>()
        .map(|sa| sa.port())
        .unwrap_or(config::DEFAULT_PORT);
    format!("127.0.0.1:{port}")
}

async fn shutdown_signal(tray: Arc<Notify>) {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { log::info!("received SIGINT, shutting down"); }
            _ = sigterm.recv() => { log::info!("received SIGTERM, shutting down"); }
            _ = tray.notified() => { log::info!("tray exit, shutting down"); }
        }
    }

    #[cfg(not(unix))]
    {
        tokio::select! {
            result = ctrl_c => {
                result.expect("failed to install CTRL+C handler");
                log::info!("received shutdown signal");
            }
            _ = tray.notified() => { log::info!("tray exit, shutting down"); }
        }
    }
}

/// Reattach a GUI-subsystem process to its parent console so `println!` /
/// `eprintln!` show up in the terminal the user launched us from. Silently
/// no-ops if there is no parent console (e.g. launched from Explorer).
#[cfg(windows)]
fn attach_parent_console() {
    use windows_sys::Win32::System::Console::{ATTACH_PARENT_PROCESS, AttachConsole};
    // Rust's stdout/stderr call `GetStdHandle` lazily per write, so we don't
    // need to reopen CONOUT$ — once the console is attached, subsequent prints
    // pick up the fresh handles automatically.
    unsafe {
        let _ = AttachConsole(ATTACH_PARENT_PROCESS);
    }
}
