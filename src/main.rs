mod agent;
mod agent_source;
mod config;
mod server;
mod sshsig;

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

use std::sync::Arc;

fn harden_process() {
    #[cfg(target_os = "linux")]
    hardening_linux::harden();
    #[cfg(target_os = "macos")]
    hardening_macos::harden();
    #[cfg(target_os = "windows")]
    hardening_windows::harden();
}

#[tokio::main]
async fn main() {
    env_logger::init();
    harden_process();

    if let Err(e) = run().await {
        log::error!("ssh-agent-proxy: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = config::Config::from_env().map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;

    let dialer: Box<dyn agent_source::AgentDialer> = {
        #[cfg(unix)]
        {
            Box::new(dialer_unix::UnixDialer::new(cfg.agent_path.clone()))
        }
        #[cfg(windows)]
        {
            Box::new(dialer_windows::NamedPipeDialer::new(
                cfg.agent_path.clone(),
            ))
        }
        #[cfg(not(any(unix, windows)))]
        {
            return Err("no agent dialer available on this platform".into());
        }
    };

    let source = agent_source::AgentSource::new(dialer, cfg.pubkey.clone());

    log::info!("signing via agent at {}", cfg.agent_path);
    if let Some(ref pk) = cfg.pubkey {
        if let Ok(line) = config::marshal_authorized_key(pk) {
            log::info!("restricted to pubkey: {}", line.trim());
        }
    }

    let state = Arc::new(server::AppState {
        source,
        namespace: cfg.namespace.clone(),
    });

    let app = server::router(state);
    let listener = tokio::net::TcpListener::bind(&cfg.addr).await?;
    log::info!("listening on {} (namespace {:?})", cfg.addr, cfg.namespace);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();

    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => { log::info!("received SIGINT, shutting down"); }
            _ = sigterm.recv() => { log::info!("received SIGTERM, shutting down"); }
        }
    }

    #[cfg(not(unix))]
    {
        ctrl_c.await.expect("failed to install CTRL+C handler");
        log::info!("received shutdown signal");
    }
}
