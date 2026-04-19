//! Tray-managed bind address: a small Windows-only preference stored in
//! `HKCU\Software\ssh-agent-proxy\BindMode` that selects between
//! loopback, all interfaces, or the local Tailscale IP.
//!
//! The `SSH_AGENT_PROXY_ADDR` env var overrides this entirely when set,
//! so power users keep full control.

use std::net::Ipv4Addr;

use windows_sys::Win32::Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetIpAddrTable, MIB_IPADDRROW_XP, MIB_IPADDRTABLE,
};

use crate::config::DEFAULT_PORT;
use crate::registry_windows::{read_hkcu_sz, write_hkcu_sz};

const CONFIG_KEY: &str = r"Software\ssh-agent-proxy";
const VALUE_NAME: &str = "BindMode";

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BindMode {
    Localhost,
    All,
    Tailscale,
}

impl BindMode {
    fn as_str(self) -> &'static str {
        match self {
            BindMode::Localhost => "localhost",
            BindMode::All => "all",
            BindMode::Tailscale => "tailscale",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "localhost" => Some(BindMode::Localhost),
            "all" => Some(BindMode::All),
            "tailscale" => Some(BindMode::Tailscale),
            _ => None,
        }
    }
}

/// Read the persisted mode. Missing key / value / unknown string → Localhost.
pub fn read_mode() -> BindMode {
    match read_hkcu_sz(CONFIG_KEY, VALUE_NAME) {
        Ok(Some(s)) => BindMode::from_str(&s).unwrap_or(BindMode::Localhost),
        Ok(None) => BindMode::Localhost,
        Err(e) => {
            log::warn!("could not read bind mode: {e}");
            BindMode::Localhost
        }
    }
}

pub fn write_mode(mode: BindMode) -> std::io::Result<()> {
    write_hkcu_sz(CONFIG_KEY, VALUE_NAME, mode.as_str())
}

/// Resolve a mode (optionally paired with a pre-detected Tailscale IP) into
/// a `host:port` bind string. Tailscale mode falls back to loopback when
/// no CGNAT-range IP is present.
pub fn resolve(mode: BindMode, tailscale_ip: Option<Ipv4Addr>) -> String {
    let ip: Ipv4Addr = match mode {
        BindMode::Localhost => Ipv4Addr::LOCALHOST,
        BindMode::All => Ipv4Addr::UNSPECIFIED,
        BindMode::Tailscale => tailscale_ip.unwrap_or_else(|| {
            log::warn!(
                "Tailscale mode selected but no 100.64.0.0/10 address found; falling back to loopback"
            );
            Ipv4Addr::LOCALHOST
        }),
    };
    format!("{ip}:{DEFAULT_PORT}")
}

/// Best local IPv4 address in the 100.64.0.0/10 CGNAT range (Tailscale's
/// default). Returns `None` if no such address exists on this host.
pub fn tailscale_ip() -> Option<Ipv4Addr> {
    let mut size: u32 = 0;
    unsafe {
        // First call with NULL to learn the required buffer size. Ignore the
        // returned status — a non-zero size is what matters.
        GetIpAddrTable(std::ptr::null_mut(), &mut size, 0);
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let table = buf.as_mut_ptr() as *mut MIB_IPADDRTABLE;
    unsafe {
        let status = GetIpAddrTable(table, &mut size, 0);
        if status != NO_ERROR && status != ERROR_INSUFFICIENT_BUFFER {
            return None;
        }
        let count = (*table).dwNumEntries as usize;
        let rows = std::slice::from_raw_parts(
            std::ptr::addr_of!((*table).table) as *const MIB_IPADDRROW_XP,
            count,
        );
        for row in rows {
            // dwAddr is network byte order; to_le_bytes on little-endian
            // Windows yields the wire-order octets directly.
            let bytes = row.dwAddr.to_le_bytes();
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            if is_cgnat(ip) {
                return Some(ip);
            }
        }
    }
    None
}

/// 100.64.0.0/10 — Carrier-Grade NAT range, which Tailscale uses by default.
fn is_cgnat(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 0x40
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgnat_detection() {
        assert!(is_cgnat(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(is_cgnat(Ipv4Addr::new(100, 127, 255, 255)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 63, 0, 0)));
        assert!(!is_cgnat(Ipv4Addr::new(100, 128, 0, 0)));
        assert!(!is_cgnat(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_cgnat(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn mode_roundtrip() {
        for m in [BindMode::Localhost, BindMode::All, BindMode::Tailscale] {
            assert_eq!(BindMode::from_str(m.as_str()), Some(m));
        }
    }
}
