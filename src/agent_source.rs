use std::io::{self, Read, Write};
use std::sync::Mutex;

use thiserror::Error;

use crate::agent::{AgentClient, AgentError, AgentKey, SSH_AGENT_RSA_SHA2_512};
use crate::sshsig;
use crate::wire;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const KEY_ALGO_RSA: &str = "ssh-rsa";
const KEY_ALGO_RSA_SHA2_512: &str = "rsa-sha2-512";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SourceError {
    #[error("dial {name}: {source}")]
    Dial { name: String, source: io::Error },

    #[error("list agent keys: {0}")]
    List(AgentError),

    #[error("agent has no keys loaded")]
    NoKeys,

    #[error("configured public key not found in agent ({count} keys available)")]
    KeyNotFound { count: usize },

    #[error("parse key type: {0}")]
    ParseKey(String),

    #[error("agent returned signature format {got:?}, wanted {want:?}")]
    SignatureDowngrade { got: String, want: String },
}

// ---------------------------------------------------------------------------
// Stream / dialer traits
// ---------------------------------------------------------------------------

/// Trait alias for streams that support both read and write.
pub(crate) trait ReadWriteStream: Read + Write + Send {}
impl<T: Read + Write + Send> ReadWriteStream for T {}

/// Trait for platform-specific connection opening. Each platform (Unix, Windows)
/// provides its own implementation that dials the SSH agent socket / pipe.
pub(crate) trait AgentDialer: Send + Sync {
    /// Open a new connection to the SSH agent.
    fn dial(&self) -> Result<Box<dyn ReadWriteStream>, io::Error>;
    /// Human-readable name for error messages (e.g. the socket path).
    fn name(&self) -> &str;
}

// ---------------------------------------------------------------------------
// AgentSource
// ---------------------------------------------------------------------------

/// Produces a fresh `sshsig::Signer` backed by the SSH agent on every call.
///
/// Each HTTP request should get its own signer so the underlying stream is
/// never shared across threads.
pub struct AgentSource {
    dialer: Box<dyn AgentDialer>,
    /// Wire-format bytes of the required key, or `None` to use the first key.
    pubkey: Option<Vec<u8>>,
}

impl AgentSource {
    /// Create a new `AgentSource`.
    ///
    /// * `dialer` - platform-specific strategy for connecting to the agent.
    /// * `pubkey` - if `Some`, the wire-format public key blob that must be
    ///   present in the agent. If `None`, the first key listed is used.
    pub fn new(dialer: Box<dyn AgentDialer>, pubkey: Option<Vec<u8>>) -> Self {
        Self { dialer, pubkey }
    }

    /// Connect to the agent and return a signer for the configured key.
    pub fn signer(&self) -> Result<Box<dyn sshsig::Signer + Send>, SourceError> {
        // 1. Dial the agent.
        let stream = self.dialer.dial().map_err(|e| SourceError::Dial {
            name: self.dialer.name().to_string(),
            source: e,
        })?;

        // 2. Create an agent client and list keys.
        let mut client = AgentClient::new(stream);
        let keys = client.list_identities().map_err(SourceError::List)?;

        // 3. Pick the target key.
        let chosen = pick_key(&keys, self.pubkey.as_deref())?;

        // 4. Extract key type from the wire blob.
        let key_type = extract_key_type(&chosen.blob)?;

        // 5. Build the signer.
        let signer = AgentBackedSigner {
            client: Mutex::new(client),
            pub_key: sshsig::SshPublicKey {
                wire: chosen.blob.clone(),
            },
            key_type,
        };

        Ok(Box::new(signer))
    }
}

// ---------------------------------------------------------------------------
// AgentBackedSigner
// ---------------------------------------------------------------------------

/// A `sshsig::Signer` that delegates to an SSH agent connection.
///
/// Uses `Mutex` for interior mutability because `sshsig::Signer::sign`
/// takes `&self` but `AgentClient::sign` needs `&mut self`. Each HTTP
/// request gets its own signer, so contention is not a concern.
struct AgentBackedSigner {
    client: Mutex<AgentClient<Box<dyn ReadWriteStream>>>,
    pub_key: sshsig::SshPublicKey,
    key_type: String,
}

impl sshsig::Signer for AgentBackedSigner {
    fn public_key(&self) -> &sshsig::SshPublicKey {
        &self.pub_key
    }

    fn sign(
        &self,
        data: &[u8],
    ) -> Result<sshsig::SshSignature, Box<dyn std::error::Error + Send + Sync>> {
        let mut client = self.client.lock().unwrap();

        // For RSA keys, force rsa-sha2-512 via the flag.
        let (flags, want_fmt) = if self.key_type == KEY_ALGO_RSA {
            (SSH_AGENT_RSA_SHA2_512, KEY_ALGO_RSA_SHA2_512)
        } else {
            (0, self.key_type.as_str())
        };

        let sig = client.sign(&self.pub_key.wire, data, flags)?;

        // Anti-downgrade: verify the agent returned the expected signature
        // format. For RSA this prevents SHA-1 fallback; for other key types
        // it catches a misbehaving agent returning a mismatched algorithm.
        if sig.format != want_fmt {
            return Err(Box::new(SourceError::SignatureDowngrade {
                got: sig.format,
                want: want_fmt.to_string(),
            }));
        }

        Ok(sshsig::SshSignature {
            format: sig.format,
            blob: sig.blob,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract the key algorithm name from an SSH wire-format public key blob.
///
/// The first field of every SSH public key blob is an SSH-string containing
/// the algorithm name (e.g. "ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp256").
fn extract_key_type(blob: &[u8]) -> Result<String, SourceError> {
    let (type_bytes, _) =
        wire::read_string(blob, 0).map_err(|e| SourceError::ParseKey(e.0.to_string()))?;
    std::str::from_utf8(type_bytes)
        .map(|s| s.to_owned())
        .map_err(|e| SourceError::ParseKey(format!("key type is not valid UTF-8: {e}")))
}

/// Select a key from the agent's key list.
///
/// * If `want` is `None`, returns the first key.
/// * If `want` is `Some(blob)`, returns the key whose blob matches exactly.
fn pick_key<'a>(keys: &'a [AgentKey], want: Option<&[u8]>) -> Result<&'a AgentKey, SourceError> {
    if keys.is_empty() {
        return Err(SourceError::NoKeys);
    }

    match want {
        None => Ok(&keys[0]),
        Some(blob) => keys
            .iter()
            .find(|k| k.blob == blob)
            .ok_or(SourceError::KeyNotFound { count: keys.len() }),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an SSH wire-format key type string.
    fn make_wire_key_type(algo: &str) -> Vec<u8> {
        let mut blob = Vec::new();
        blob.extend_from_slice(&(algo.len() as u32).to_be_bytes());
        blob.extend_from_slice(algo.as_bytes());
        // Append some dummy key data after the algorithm name.
        blob.extend_from_slice(&[0u8; 32]);
        blob
    }

    fn make_agent_key(algo: &str, comment: &str) -> AgentKey {
        AgentKey {
            blob: make_wire_key_type(algo),
            comment: comment.to_string(),
        }
    }

    #[test]
    fn test_extract_key_type() {
        let blob = make_wire_key_type("ssh-ed25519");
        let kt = extract_key_type(&blob).unwrap();
        assert_eq!(kt, "ssh-ed25519");
    }

    #[test]
    fn test_extract_key_type_rsa() {
        let blob = make_wire_key_type("ssh-rsa");
        let kt = extract_key_type(&blob).unwrap();
        assert_eq!(kt, "ssh-rsa");
    }

    #[test]
    fn test_extract_key_type_short() {
        // Too short to even contain a length prefix.
        let blob = vec![0u8; 2];
        let result = extract_key_type(&blob);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, SourceError::ParseKey(_)),
            "expected ParseKey, got: {err}"
        );
    }

    #[test]
    fn test_extract_key_type_truncated() {
        // Length says 100 bytes but blob is only 10 bytes total.
        let mut blob = Vec::new();
        blob.extend_from_slice(&100u32.to_be_bytes());
        blob.extend_from_slice(&[0u8; 6]);
        let result = extract_key_type(&blob);
        assert!(result.is_err());
    }

    #[test]
    fn test_pick_key_first() {
        let keys = vec![
            make_agent_key("ssh-ed25519", "first"),
            make_agent_key("ssh-rsa", "second"),
        ];
        let chosen = pick_key(&keys, None).unwrap();
        assert_eq!(chosen.comment, "first");
    }

    #[test]
    fn test_pick_key_match() {
        let keys = vec![
            make_agent_key("ssh-ed25519", "first"),
            make_agent_key("ssh-rsa", "second"),
        ];
        let target_blob = keys[1].blob.clone();
        let chosen = pick_key(&keys, Some(&target_blob)).unwrap();
        assert_eq!(chosen.comment, "second");
    }

    #[test]
    fn test_pick_key_not_found() {
        let keys = vec![
            make_agent_key("ssh-ed25519", "first"),
            make_agent_key("ssh-rsa", "second"),
        ];
        let bogus = vec![0xFFu8; 20];
        let result = pick_key(&keys, Some(&bogus));
        assert!(result.is_err());
        match result.unwrap_err() {
            SourceError::KeyNotFound { count } => assert_eq!(count, 2),
            other => panic!("expected KeyNotFound, got: {other}"),
        }
    }

    #[test]
    fn test_pick_key_empty() {
        let keys: Vec<AgentKey> = vec![];
        let result = pick_key(&keys, None);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SourceError::NoKeys));
    }
}
