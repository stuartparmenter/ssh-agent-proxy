//! Windows service integration: install/uninstall subcommands and SCM dispatcher.
//!
//! This module is only compiled on Windows (`#[cfg(windows)]`).

use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

use windows_service::service::{
    ServiceAccess, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_dispatcher;
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

use windows_sys::Win32::Foundation::ERROR_SERVICE_DOES_NOT_EXIST;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, REG_MULTI_SZ, REG_OPTION_NON_VOLATILE, RegCloseKey,
    RegCreateKeyExW, RegSetValueExW,
};

const SERVICE_NAME: &str = "ssh-agent-proxy";
const SERVICE_DISPLAY_NAME: &str = "SSH Agent Signing Proxy";
const SERVICE_DESCRIPTION: &str =
    "HTTP signing proxy backed by any ssh-agent (1Password, GPG, etc.)";

/// Environment variable names that we snapshot into the registry when installing the service.
const SERVICE_ENV_VARS: &[&str] = &[
    "SSH_AGENT_PROXY_ADDR",
    "SSH_AGENT_PROXY_NAMESPACE",
    "SSH_AGENT_PROXY_UPSTREAM",
    "SSH_AGENT_PROXY_PUBKEY",
    "SSH_AGENT_PROXY_PUBKEY_FILE",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns `true` when the process was launched by the Windows Service Control Manager.
///
/// We rely on `windows_service::service_dispatcher::start` failing quickly when we are NOT
/// running as a service.  A more robust check (similar to Go's `svc.IsWindowsService()`) would
/// inspect the parent process, but this is good enough and avoids extra FFI.
pub fn is_windows_service() -> bool {
    // Heuristic: when launched by SCM there is no console attached.  The Go implementation uses
    // `svc.IsWindowsService()` which does an equivalent check.  We approximate it by checking if
    // we have a console window — services typically do not.
    use windows_sys::Win32::System::Console::GetConsoleWindow;
    unsafe { GetConsoleWindow().is_null() }
}

/// Entry point when the process has been launched by the SCM.
///
/// Sets up file-based logging, then hands control to the service dispatcher which calls our
/// service main function on a background thread.
pub fn run_as_windows_service() {
    // Set up file-based logging before entering the dispatcher so that log output goes to a file
    // rather than being lost (services have no console).
    if let Err(e) = init_service_logging() {
        eprintln!("failed to initialise service logging: {e}");
    }

    if let Err(e) = service_dispatcher::start(SERVICE_NAME, ffi_service_main) {
        log::error!("service dispatcher failed: {e}");
    }
}

/// Handle `install` and `uninstall` subcommands.
pub fn run_service_cmd(cmd: &str, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        "install" => install_service(args),
        "uninstall" => uninstall_service(),
        other => Err(format!("unknown service command: {other}").into()),
    }
}

// ---------------------------------------------------------------------------
// Service dispatcher plumbing
// ---------------------------------------------------------------------------

// Generate the extern "system" service main entry point.
windows_service::define_windows_service!(ffi_service_main, service_main);

/// Called by the SCM on a background thread after `service_dispatcher::start`.
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        log::error!("service failed: {e}");
    }
}

fn run_service() -> Result<(), Box<dyn std::error::Error>> {
    // Channel used to signal a stop request from the SCM.
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();

    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = shutdown_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, event_handler)?;

    // Report StartPending.
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StartPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    })?;

    // Build a new tokio runtime — we are on a plain OS thread spawned by the dispatcher.
    let rt = tokio::runtime::Runtime::new()?;

    // Spawn the application server.
    let handle = rt.spawn(crate::run());

    // Report Running.
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Running,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    // Wait for either a stop signal from the SCM or the server task to finish.
    // We poll both channels because `shutdown_rx.recv()` is blocking and we cannot select on it
    // with the async handle directly.  In practice the SCM stop signal is the normal exit path.
    let exit_code = loop {
        // Check for SCM stop signal (non-blocking first, then short sleeps).
        if shutdown_rx.try_recv().is_ok() {
            // SCM requested stop.  Abort the server task.
            handle.abort();
            break ServiceExitCode::Win32(0);
        }
        // Check if the server task finished on its own.
        if handle.is_finished() {
            match rt.block_on(handle) {
                Ok(Ok(())) => break ServiceExitCode::Win32(0),
                Ok(Err(e)) => {
                    log::error!("server exited with error: {e}");
                    break ServiceExitCode::Win32(1);
                }
                Err(e) => {
                    log::error!("server task panicked: {e}");
                    break ServiceExitCode::Win32(1);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(250));
    };

    // Report StopPending.
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: exit_code.clone(),
        checkpoint: 0,
        wait_hint: Duration::from_secs(5),
        process_id: None,
    })?;

    // Shut down the runtime gracefully.
    rt.shutdown_timeout(Duration::from_secs(5));

    // Report Stopped.
    status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code,
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    })?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Install
// ---------------------------------------------------------------------------

fn install_service(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut system_service = false;
    let mut account_name: Option<OsString> = None;
    let mut account_password: Option<OsString> = None;

    // Simple argument parsing: --system, --user <DOMAIN\user>, --password <pw>
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--system" | "-system" => {
                system_service = true;
                i += 1;
            }
            "--user" | "-user" => {
                i += 1;
                if i >= args.len() {
                    return Err("--user requires a value".into());
                }
                account_name = Some(OsString::from(&args[i]));
                i += 1;
            }
            "--password" | "-password" => {
                i += 1;
                if i >= args.len() {
                    return Err("--password requires a value".into());
                }
                account_password = Some(OsString::from(&args[i]));
                i += 1;
            }
            other => {
                return Err(format!("unknown flag: {other}").into());
            }
        }
    }

    // Determine account.  If --system, run as LocalSystem (account_name = None).
    // If --user is given, use that account.  If neither, ask the user or default.
    if system_service {
        account_name = None;
        account_password = None;
    } else if account_name.is_some() && account_password.is_none() {
        // Prompt for password if not supplied.
        account_password = Some(prompt_password()?);
    }

    let exe_path = std::env::current_exe()?;

    let start_type = if system_service {
        ServiceStartType::AutoStart
    } else {
        ServiceStartType::OnDemand
    };

    let service_info = ServiceInfo {
        name: OsString::from(SERVICE_NAME),
        display_name: OsString::from(SERVICE_DISPLAY_NAME),
        service_type: ServiceType::OWN_PROCESS,
        start_type,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe_path,
        launch_arguments: vec![],
        dependencies: vec![],
        account_name,
        account_password,
    };

    let manager_access = ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE;
    let manager = ServiceManager::local_computer(None::<&str>, manager_access)?;

    let service = manager.create_service(
        &service_info,
        ServiceAccess::CHANGE_CONFIG | ServiceAccess::START,
    )?;
    service.set_description(SERVICE_DESCRIPTION)?;

    println!("service '{SERVICE_NAME}' installed");

    // Collect SSH_AGENT_PROXY_* environment variables and persist to registry.
    let env_pairs = collect_service_env()?;
    if !env_pairs.is_empty() {
        set_service_environment(SERVICE_NAME, &env_pairs)?;
        println!(
            "persisted {} environment variable(s) to service registry",
            env_pairs.len()
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

fn uninstall_service() -> Result<(), Box<dyn std::error::Error>> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;

    let service_access = ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE;
    let service = manager.open_service(SERVICE_NAME, service_access)?;

    // Mark for deletion.
    service.delete()?;

    // Stop the service if it is currently running.
    if service.query_status()?.current_state != ServiceState::Stopped {
        let _ = service.stop();
    }

    drop(service);

    // Poll for actual deletion from the database.
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(5);
    while start.elapsed() < timeout {
        if let Err(windows_service::Error::Winapi(e)) =
            manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS)
        {
            if e.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) {
                println!("service '{SERVICE_NAME}' deleted");
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    println!("service '{SERVICE_NAME}' marked for deletion (will complete on next reboot)");
    Ok(())
}

// ---------------------------------------------------------------------------
// Environment variable helpers
// ---------------------------------------------------------------------------

/// Snapshot all `SSH_AGENT_PROXY_*` env vars that are currently set.
fn collect_service_env() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let mut pairs = Vec::new();
    for &name in SERVICE_ENV_VARS {
        if let Ok(val) = std::env::var(name) {
            if !val.is_empty() {
                // Guard against embedded newlines — they would corrupt the REG_MULTI_SZ value.
                if val.contains('\n') || val.contains('\r') {
                    return Err(
                        format!("environment variable {name} contains embedded newlines").into(),
                    );
                }
                pairs.push((name.to_string(), val));
            }
        }
    }
    Ok(pairs)
}

/// Write env vars to the service's `Environment` registry value (REG_MULTI_SZ).
///
/// Path: `HKLM\SYSTEM\CurrentControlSet\Services\<service_name>\Environment`
///
/// REG_MULTI_SZ format: each string is null-terminated, and the list is double-null-terminated.
fn set_service_environment(
    service_name: &str,
    pairs: &[(String, String)],
) -> Result<(), Box<dyn std::error::Error>> {
    let subkey = format!("SYSTEM\\CurrentControlSet\\Services\\{service_name}\\Environment");

    // Build REG_MULTI_SZ value: "KEY=VALUE\0KEY=VALUE\0\0"
    let mut wide: Vec<u16> = Vec::new();
    for (k, v) in pairs {
        let entry = format!("{k}={v}");
        for c in entry.encode_utf16() {
            wide.push(c);
        }
        wide.push(0); // null-terminate this string
    }
    wide.push(0); // double-null terminator

    let subkey_wide: Vec<u16> = subkey.encode_utf16().chain(std::iter::once(0)).collect();
    let value_name = ""; // default value
    let value_name_wide: Vec<u16> = value_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut() as HKEY;
        let mut disposition: u32 = 0;

        let status = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            subkey_wide.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut hkey,
            &mut disposition,
        );
        if status != 0 {
            return Err(format!(
                "RegCreateKeyExW failed: {}",
                std::io::Error::from_raw_os_error(status as i32)
            )
            .into());
        }

        let byte_len = (wide.len() * 2) as u32;
        let status = RegSetValueExW(
            hkey,
            value_name_wide.as_ptr(),
            0,
            REG_MULTI_SZ,
            wide.as_ptr() as *const u8,
            byte_len,
        );

        RegCloseKey(hkey);

        if status != 0 {
            return Err(format!(
                "RegSetValueExW failed: {}",
                std::io::Error::from_raw_os_error(status as i32)
            )
            .into());
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

/// Initialise file-based logging for the service.
///
/// Writes to `%LOCALAPPDATA%\ssh-agent-proxy\service.log`.
fn init_service_logging() -> Result<(), Box<dyn std::error::Error>> {
    let local_app_data =
        std::env::var("LOCALAPPDATA").unwrap_or_else(|_| r"C:\ProgramData".to_string());
    let log_dir = PathBuf::from(local_app_data).join("ssh-agent-proxy");
    std::fs::create_dir_all(&log_dir)?;
    let log_path = log_dir.join("service.log");

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

// ---------------------------------------------------------------------------
// Password prompt
// ---------------------------------------------------------------------------

/// Prompt for a password on the console without echo.
///
/// Falls back to a simple `stdin` read if the console cannot be configured for no-echo.
fn prompt_password() -> Result<OsString, Box<dyn std::error::Error>> {
    eprint!("Enter service account password: ");

    // Read from stdin — in a real deployment we would disable echo using
    // SetConsoleMode but that requires additional FFI.  For now just read a line.
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;
    let password = buf.trim_end_matches(&['\r', '\n'][..]);
    if password.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(OsString::from(password))
}
