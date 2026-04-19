//! Thin `HKCU` registry helpers shared by the autostart and bind-address
//! modules. Each function owns its own key handle lifetime so callers never
//! touch raw HKEYs or run their own `unsafe` blocks.

use std::io;

use windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND;
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_OPTION_NON_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
};

/// UTF-16 null-terminated wide string for Win32 W-suffix APIs.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read an `HKCU\<subkey>\<value>` `REG_SZ`. Missing key or missing value →
/// `Ok(None)`. Wrong value type is treated as missing so callers can fall
/// back cleanly without distinguishing "never set" from "corrupted".
pub fn read_hkcu_sz(subkey: &str, value: &str) -> io::Result<Option<String>> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            KEY_QUERY_VALUE,
            &mut hkey,
        );
        if status as u32 == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let mut buf = [0u16; 1024];
        let mut len: u32 = (buf.len() * 2) as u32;
        let mut ty: u32 = 0;
        let status = RegQueryValueExW(
            hkey,
            value_w.as_ptr(),
            std::ptr::null_mut(),
            &mut ty,
            buf.as_mut_ptr() as *mut u8,
            &mut len,
        );
        RegCloseKey(hkey);
        if status as u32 == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if ty != REG_SZ {
            return Ok(None);
        }
        let chars = (len as usize) / 2;
        let trimmed = match buf[..chars].iter().position(|&c| c == 0) {
            Some(n) => &buf[..n],
            None => &buf[..chars],
        };
        Ok(Some(String::from_utf16_lossy(trimmed)))
    }
}

/// Write `HKCU\<subkey>\<value>` as `REG_SZ`. Creates the subkey if absent.
pub fn write_hkcu_sz(subkey: &str, value: &str, data: &str) -> io::Result<()> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    let data_w = wide(data);
    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut hkey,
            std::ptr::null_mut(),
        );
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let byte_len = (data_w.len() * 2) as u32;
        let status = RegSetValueExW(
            hkey,
            value_w.as_ptr(),
            0,
            REG_SZ,
            data_w.as_ptr() as *const u8,
            byte_len,
        );
        RegCloseKey(hkey);
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}

/// Delete a value under `HKCU\<subkey>`. Missing value is not an error.
pub fn delete_hkcu_value(subkey: &str, value: &str) -> io::Result<()> {
    let subkey_w = wide(subkey);
    let value_w = wide(value);
    unsafe {
        let mut hkey: HKEY = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            subkey_w.as_ptr(),
            0,
            KEY_SET_VALUE,
            &mut hkey,
        );
        if status as u32 == ERROR_FILE_NOT_FOUND {
            return Ok(());
        }
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        let status = RegDeleteValueW(hkey, value_w.as_ptr());
        RegCloseKey(hkey);
        if status != 0 && status as u32 != ERROR_FILE_NOT_FOUND {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        Ok(())
    }
}
