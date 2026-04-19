//! Per-user autostart via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//!
//! Paths containing spaces MUST be wrapped in double quotes — Windows does
//! not auto-quote Run-key command lines, so `C:\Program Files\...\app.exe`
//! would otherwise be parsed as `C:\Program.exe` with `Files\...` as args.

use std::io;
use std::path::Path;

use crate::APP_SLUG;
use crate::registry_windows::{delete_hkcu_value, read_hkcu_sz, write_hkcu_sz};

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const VALUE_NAME: &str = APP_SLUG;

fn command_line(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

/// True when the Run value exists and matches the command line we would
/// write for `current_exe`. A mismatch (e.g. the install path changed) is
/// treated as "not enabled" so the caller can re-enable and overwrite.
pub fn is_enabled(current_exe: &Path) -> io::Result<bool> {
    match read_hkcu_sz(RUN_KEY, VALUE_NAME)? {
        Some(stored) => Ok(stored == command_line(current_exe)),
        None => Ok(false),
    }
}

pub fn enable(current_exe: &Path) -> io::Result<()> {
    write_hkcu_sz(RUN_KEY, VALUE_NAME, &command_line(current_exe))
}

pub fn disable() -> io::Result<()> {
    delete_hkcu_value(RUN_KEY, VALUE_NAME)
}
