//! Per-user autostart via `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`.
//!
//! Paths containing spaces MUST be wrapped in double quotes — Windows does
//! not auto-quote Run-key command lines, so `C:\Program Files\...\app.exe`
//! would otherwise be parsed as `C:\Program.exe` with `Files\...` as args.

use std::io;
use std::path::Path;

use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW,
    RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

use crate::APP_SLUG;

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
pub const VALUE_NAME: &str = APP_SLUG;

fn command_line(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Returns `true` if the Run value exists and matches the command line we would
/// write for `current_exe`. A mismatch (e.g. the install path changed) is
/// treated as "not enabled" so the caller can re-enable and overwrite.
pub fn is_enabled(current_exe: &Path) -> io::Result<bool> {
    let subkey = wide(RUN_KEY);
    let value = wide(VALUE_NAME);

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        );
        if status != 0 {
            if status as u32 == ERROR_FILE_NOT_FOUND {
                return Ok(false);
            }
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let mut buf = [0u16; 1024];
        let mut len: u32 = (buf.len() * 2) as u32;
        let mut ty: u32 = 0;
        let status = RegQueryValueExW(
            hkey,
            value.as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr() as *mut u8,
            &mut len,
        );
        RegCloseKey(hkey);

        if status as u32 == ERROR_FILE_NOT_FOUND {
            return Ok(false);
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if ty != REG_SZ {
            return Ok(false);
        }

        // len is bytes including trailing NUL; convert to UTF-16 chars and trim NUL(s).
        let chars = (len as usize) / 2;
        let slice = &buf[..chars];
        let trimmed = match slice.iter().position(|&c| c == 0) {
            Some(n) => &slice[..n],
            None => slice,
        };
        let stored = String::from_utf16_lossy(trimmed);
        Ok(stored == command_line(current_exe))
    }
}

/// Write the Run value so Windows launches the proxy at the next logon.
pub fn enable(current_exe: &Path) -> io::Result<()> {
    let subkey = wide(RUN_KEY);
    let value = wide(VALUE_NAME);
    let data_str = command_line(current_exe);
    let data = wide(&data_str);

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let byte_len = (data.len() * 2) as u32;
        let status = RegSetValueExW(
            hkey,
            value.as_ptr(),
            0,
            REG_SZ,
            data.as_ptr() as *const u8,
            byte_len,
        );
        RegCloseKey(hkey);

        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}

/// Remove the Run value. Missing value is not an error.
pub fn disable() -> io::Result<()> {
    let subkey = wide(RUN_KEY);
    let value = wide(VALUE_NAME);

    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }

        let status = RegDeleteValueW(hkey, value.as_ptr());
        RegCloseKey(hkey);

        if status != 0 && status as u32 != ERROR_FILE_NOT_FOUND {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
    }
    Ok(())
}
