//! Windows tray app: runs the HTTP signing server on a worker-thread tokio
//! runtime while the main thread drives a Win32 message loop for the tray icon.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Notify;
use tray_icon::menu::{
    CheckMenuItem, Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem, Submenu,
};
use tray_icon::{Icon, TrayIconBuilder};
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, MSG, PostQuitMessage, TranslateMessage,
};

use crate::bind_address_windows::{self, BindMode};
use crate::{APP_SLUG, autostart_windows};

/// Max time to wait for in-flight requests to finish after the user picks
/// Exit. The process exits regardless once this elapses; any stuck server
/// thread is killed by process teardown.
const SHUTDOWN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Copy, Clone)]
enum LoopExit {
    Normal,
    Restart,
}

pub fn run_tray() -> Result<(), Box<dyn std::error::Error>> {
    init_tray_logging()?;
    crate::harden_process();

    let exe = std::env::current_exe()?;

    // Resolve once up front: the spawned tokio thread, the tray tooltip,
    // and the submenu labels all need this state.
    let env_override = std::env::var("SSH_AGENT_PROXY_ADDR")
        .ok()
        .filter(|s| !s.is_empty());
    let current_mode = bind_address_windows::read_mode();
    let tailscale_ip = bind_address_windows::tailscale_ip();
    let effective_addr = env_override
        .clone()
        .unwrap_or_else(|| bind_address_windows::resolve(current_mode, tailscale_ip));

    // Tokio runtime lives on a worker thread so the main thread can own the
    // Win32 message pump (tray-icon's hidden window must be created on the
    // thread that dispatches messages for it).
    let shutdown = Arc::new(Notify::new());
    let server_shutdown = shutdown.clone();
    let server_thread = std::thread::Builder::new()
        .name("tokio-runtime".into())
        .spawn(move || -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|e| e.to_string())?;
            rt.block_on(crate::run(server_shutdown))
                .map_err(|e| e.to_string())
        })?;

    let (items, menu) = build_menu(&exe, env_override.is_some(), current_mode, tailscale_ip)?;

    let icon = load_tray_icon();
    let _tray = TrayIconBuilder::new()
        .with_tooltip(format!("{APP_SLUG} ({effective_addr})"))
        .with_icon(icon)
        .with_menu(Box::new(menu))
        .build()?;

    let exit = run_message_loop(&items, &exe, &effective_addr, tailscale_ip);

    shutdown.notify_waiters();
    wait_for_server(server_thread);

    if matches!(exit, LoopExit::Restart) {
        log::info!("restarting to apply new bind address");
        if let Err(e) = std::process::Command::new(&exe).spawn() {
            log::error!("failed to respawn: {e}");
        }
    }
    Ok(())
}

struct MenuItems {
    autostart: CheckMenuItem,
    bind_localhost: CheckMenuItem,
    bind_all: CheckMenuItem,
    bind_tailscale: CheckMenuItem,
    restart: MenuItem,
    exit: MenuItem,
}

fn build_menu(
    exe: &std::path::Path,
    env_override: bool,
    current_mode: BindMode,
    tailscale_ip: Option<std::net::Ipv4Addr>,
) -> Result<(MenuItems, Menu), tray_icon::menu::Error> {
    let autostart_on = match autostart_windows::is_enabled(exe) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("could not read autostart state: {e}");
            false
        }
    };

    let bind_localhost = CheckMenuItem::with_id(
        "bind-localhost",
        "Localhost only (127.0.0.1)",
        !env_override,
        current_mode == BindMode::Localhost,
        None,
    );
    let bind_all = CheckMenuItem::with_id(
        "bind-all",
        "All interfaces (0.0.0.0)",
        !env_override,
        current_mode == BindMode::All,
        None,
    );
    let tailscale_label = match tailscale_ip {
        Some(ip) => format!("Tailscale ({ip})"),
        None => "Tailscale (not detected)".to_string(),
    };
    let bind_tailscale = CheckMenuItem::with_id(
        "bind-tailscale",
        &tailscale_label,
        !env_override && tailscale_ip.is_some(),
        current_mode == BindMode::Tailscale,
        None,
    );

    let bind_submenu = Submenu::with_id(
        "bind-submenu",
        if env_override {
            "Bind address (SSH_AGENT_PROXY_ADDR overrides)"
        } else {
            "Bind address"
        },
        true,
    );
    bind_submenu.append(&bind_localhost)?;
    bind_submenu.append(&bind_all)?;
    bind_submenu.append(&bind_tailscale)?;

    let restart = MenuItem::with_id("restart", "Restart to apply", false, None);
    let autostart = CheckMenuItem::with_id("autostart", "Start at login", true, autostart_on, None);
    let exit = MenuItem::with_id("exit", "Exit", true, None);

    let menu = Menu::new();
    menu.append(&bind_submenu)?;
    menu.append(&restart)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&autostart)?;
    menu.append(&PredefinedMenuItem::separator())?;
    menu.append(&exit)?;

    Ok((
        MenuItems {
            autostart,
            bind_localhost,
            bind_all,
            bind_tailscale,
            restart,
            exit,
        },
        menu,
    ))
}

fn run_message_loop(
    items: &MenuItems,
    exe: &std::path::Path,
    effective_addr: &str,
    tailscale_ip: Option<std::net::Ipv4Addr>,
) -> LoopExit {
    let menu_events = MenuEvent::receiver();
    let mut exit = LoopExit::Normal;
    unsafe {
        let mut msg: MSG = std::mem::zeroed();
        while GetMessageW(&mut msg, std::ptr::null_mut(), 0, 0) > 0 {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);

            while let Ok(event) = menu_events.try_recv() {
                if event.id == *items.autostart.id() {
                    handle_autostart_toggle(&items.autostart, exe);
                } else if let Some(mode) = bind_mode_for_id(&event.id, items) {
                    handle_bind_change(items, mode, effective_addr, tailscale_ip);
                } else if event.id == *items.restart.id() {
                    log::info!("restart requested from tray");
                    exit = LoopExit::Restart;
                    PostQuitMessage(0);
                } else if event.id == *items.exit.id() {
                    log::info!("exit requested from tray");
                    PostQuitMessage(0);
                }
            }
        }
    }
    exit
}

fn bind_mode_for_id(id: &MenuId, items: &MenuItems) -> Option<BindMode> {
    if id == items.bind_localhost.id() {
        Some(BindMode::Localhost)
    } else if id == items.bind_all.id() {
        Some(BindMode::All)
    } else if id == items.bind_tailscale.id() {
        Some(BindMode::Tailscale)
    } else {
        None
    }
}

fn handle_bind_change(
    items: &MenuItems,
    mode: BindMode,
    effective_addr: &str,
    tailscale_ip: Option<std::net::Ipv4Addr>,
) {
    if let Err(e) = bind_address_windows::write_mode(mode) {
        log::error!("persisting bind mode failed: {e}");
        // Revert the radio state — re-read registry to reflect reality.
        sync_bind_checkboxes(items, bind_address_windows::read_mode());
        return;
    }
    sync_bind_checkboxes(items, mode);
    let new_addr = bind_address_windows::resolve(mode, tailscale_ip);
    items.restart.set_enabled(new_addr != effective_addr);
    log::info!("bind mode = {mode:?}, new addr = {new_addr}, effective = {effective_addr}");
}

fn sync_bind_checkboxes(items: &MenuItems, mode: BindMode) {
    items
        .bind_localhost
        .set_checked(mode == BindMode::Localhost);
    items.bind_all.set_checked(mode == BindMode::All);
    items
        .bind_tailscale
        .set_checked(mode == BindMode::Tailscale);
}

fn handle_autostart_toggle(autostart: &CheckMenuItem, exe: &std::path::Path) {
    let checked = autostart.is_checked();
    let result = if checked {
        autostart_windows::enable(exe)
    } else {
        autostart_windows::disable()
    };
    if let Err(e) = result {
        log::error!("autostart toggle failed: {e}");
        autostart.set_checked(!checked);
    } else {
        log::info!(
            "autostart {} ({})",
            if checked { "enabled" } else { "disabled" },
            exe.display()
        );
    }
}

fn wait_for_server(server_thread: std::thread::JoinHandle<Result<(), String>>) {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(server_thread.join());
    });
    match rx.recv_timeout(SHUTDOWN_TIMEOUT) {
        Ok(Ok(Ok(()))) => {}
        Ok(Ok(Err(e))) => log::error!("server exited with error: {e}"),
        Ok(Err(_)) => log::error!("server thread panicked"),
        Err(_) => log::warn!("server shutdown timed out after {SHUTDOWN_TIMEOUT:?}; forcing exit"),
    }
}

/// Prefers the embedded Win32 icon resource so the same art appears in
/// Explorer and Task Manager; falls back to a solid-colour placeholder if
/// the resource is missing (e.g. build ran without `embed-resource`).
fn load_tray_icon() -> Icon {
    if let Ok(icon) = Icon::from_resource(1, None) {
        return icon;
    }
    log::warn!("no embedded icon resource; falling back to placeholder");
    let size: u32 = 32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for _ in 0..(size * size) {
        rgba.extend_from_slice(&[0x22, 0x55, 0xaa, 0xff]);
    }
    Icon::from_rgba(rgba, size, size).expect("placeholder icon must be valid")
}

fn init_tray_logging() -> Result<(), Box<dyn std::error::Error>> {
    let local_app_data =
        std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let log_dir = PathBuf::from(local_app_data).join(APP_SLUG);
    std::fs::create_dir_all(&log_dir)?;
    let log_path = log_dir.join("tray.log");

    let target = Box::new(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)?,
    );

    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Pipe(target))
        .init();
    Ok(())
}
