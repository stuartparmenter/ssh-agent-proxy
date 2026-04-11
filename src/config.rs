use std::fs;

const DEFAULT_ADDR: &str = "127.0.0.1:7221";
const DEFAULT_NAMESPACE: &str = "git";

pub struct Config {
    pub addr: String,
    pub namespace: String,
    pub agent_path: String,
    pub pubkey: Option<Vec<u8>>, // wire-format bytes of the required key
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        let addr = env_or_default("SSH_AGENT_PROXY_ADDR", DEFAULT_ADDR);
        let namespace = env_or_default("SSH_AGENT_PROXY_NAMESPACE", DEFAULT_NAMESPACE);

        let agent_path = std::env::var("SSH_AGENT_PROXY_UPSTREAM")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(default_agent_path)
            .ok_or_else(|| {
                "no agent path: set SSH_AGENT_PROXY_UPSTREAM or SSH_AUTH_SOCK".to_string()
            })?;

        let pubkey_line = load_pubkey_line()?;
        let pubkey = match pubkey_line {
            Some(line) => Some(parse_authorized_key(&line)?),
            None => None,
        };

        Ok(Config {
            addr,
            namespace,
            agent_path,
            pubkey,
        })
    }
}

fn env_or_default(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn load_pubkey_line() -> Result<Option<String>, String> {
    if let Ok(line) = std::env::var("SSH_AGENT_PROXY_PUBKEY")
        && !line.is_empty()
    {
        return Ok(Some(line));
    }
    if let Ok(path) = std::env::var("SSH_AGENT_PROXY_PUBKEY_FILE")
        && !path.is_empty()
    {
        let data = fs::read_to_string(&path)
            .map_err(|e| format!("read SSH_AGENT_PROXY_PUBKEY_FILE: {e}"))?;
        return Ok(Some(data));
    }
    Ok(None)
}

/// Parse "ssh-ed25519 AAAA... comment" -> wire-format bytes (base64 decode the second field)
fn parse_authorized_key(line: &str) -> Result<Vec<u8>, String> {
    let mut parts = line.trim().splitn(3, ' ');
    let _algo = parts.next();
    let b64 = parts.next().ok_or("invalid authorized_keys format")?;
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("parse pubkey: {e}"))
}

/// Format wire-format key bytes -> "ssh-ed25519 AAAA...\n" (authorized_keys line)
pub fn marshal_authorized_key(wire: &[u8]) -> Result<String, String> {
    if wire.len() < 4 {
        return Err("key too short".into());
    }
    let type_len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
    if wire.len() < 4 + type_len {
        return Err("key truncated".into());
    }
    let key_type = std::str::from_utf8(&wire[4..4 + type_len]).map_err(|_| "invalid key type")?;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(wire);
    Ok(format!("{key_type} {b64}\n"))
}

// Platform-specific default agent path
#[cfg(unix)]
fn default_agent_path() -> Option<String> {
    crate::dialer_unix::default_agent_path()
}

#[cfg(windows)]
fn default_agent_path() -> Option<String> {
    crate::dialer_windows::default_agent_path()
}

#[cfg(not(any(unix, windows)))]
fn default_agent_path() -> Option<String> {
    None
}
