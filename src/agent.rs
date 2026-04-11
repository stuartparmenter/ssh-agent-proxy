use std::io::{self, Read, Write};

use thiserror::Error;

use crate::wire;

// SSH agent protocol message types
const SSH_AGENT_FAILURE: u8 = 5;
const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Sign flag: request RSA SHA-512 signature.
pub(crate) const SSH_AGENT_RSA_SHA2_512: u32 = 0x04;

/// Maximum response size (256 KiB).
const MAX_RESPONSE_SIZE: u32 = 256 * 1024;

/// A public key returned by the agent.
#[derive(Debug)]
pub struct AgentKey {
    /// Wire-format public key blob.
    pub blob: Vec<u8>,
    /// Comment associated with the key (e.g. "user@host").
    #[allow(dead_code)]
    pub comment: String,
}

/// A signature returned by the agent.
pub struct AgentSignature {
    /// Signature algorithm, e.g. "ssh-ed25519".
    pub format: String,
    /// Raw signature bytes.
    pub blob: Vec<u8>,
}

/// Errors from the SSH agent client.
#[derive(Debug, Error)]
pub enum AgentError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("agent returned failure")]
    AgentFailure,

    #[error("unexpected response type: {0}")]
    UnexpectedResponse(u8),

    #[error("malformed response: {0}")]
    Malformed(String),
}

/// Minimal SSH agent protocol client.
///
/// Generic over the underlying stream so it works with Unix sockets,
/// Windows named pipes, or mock streams in tests.
pub struct AgentClient<S> {
    stream: S,
}

impl<S: Read + Write> AgentClient<S> {
    /// Create a new agent client wrapping the given stream.
    pub fn new(stream: S) -> Self {
        AgentClient { stream }
    }

    /// List all identities (public keys) held by the agent.
    pub fn list_identities(&mut self) -> Result<Vec<AgentKey>, AgentError> {
        // Send REQUEST_IDENTITIES: just the message type byte, no body.
        self.send_message(&[SSH_AGENTC_REQUEST_IDENTITIES])?;

        let response = self.recv_message()?;
        if response.is_empty() {
            return Err(AgentError::Malformed("empty response".into()));
        }

        let msg_type = response[0];
        if msg_type == SSH_AGENT_FAILURE {
            return Err(AgentError::AgentFailure);
        }
        if msg_type != SSH_AGENT_IDENTITIES_ANSWER {
            return Err(AgentError::UnexpectedResponse(msg_type));
        }

        parse_identities_answer(&response[1..])
    }

    /// Request the agent to sign `data` using the key identified by `key_blob`.
    pub fn sign(
        &mut self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<AgentSignature, AgentError> {
        // Build SIGN_REQUEST payload: type + string(key_blob) + string(data) + u32(flags)
        let mut payload = Vec::new();
        payload.push(SSH_AGENTC_SIGN_REQUEST);
        wire::write_string(&mut payload, key_blob);
        wire::write_string(&mut payload, data);
        payload.extend_from_slice(&flags.to_be_bytes());

        self.send_message(&payload)?;

        let response = self.recv_message()?;
        if response.is_empty() {
            return Err(AgentError::Malformed("empty response".into()));
        }

        let msg_type = response[0];
        if msg_type == SSH_AGENT_FAILURE {
            return Err(AgentError::AgentFailure);
        }
        if msg_type != SSH_AGENT_SIGN_RESPONSE {
            return Err(AgentError::UnexpectedResponse(msg_type));
        }

        parse_sign_response(&response[1..])
    }

    /// Send a framed message: 4-byte big-endian length prefix + payload.
    fn send_message(&mut self, payload: &[u8]) -> Result<(), AgentError> {
        let len = payload.len() as u32;
        self.stream.write_all(&len.to_be_bytes())?;
        self.stream.write_all(payload)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Receive a framed message: read 4-byte length, then the payload.
    fn recv_message(&mut self) -> Result<Vec<u8>, AgentError> {
        let mut len_buf = [0u8; 4];
        self.stream.read_exact(&mut len_buf)?;
        let len = u32::from_be_bytes(len_buf);

        if len > MAX_RESPONSE_SIZE {
            return Err(AgentError::Malformed(format!(
                "response too large: {len} bytes (max {MAX_RESPONSE_SIZE})"
            )));
        }

        let mut buf = vec![0u8; len as usize];
        self.stream.read_exact(&mut buf)?;
        Ok(buf)
    }
}

fn read_string(data: &[u8], offset: usize) -> Result<(&[u8], usize), AgentError> {
    wire::read_string(data, offset).map_err(|e| AgentError::Malformed(e.0.to_string()))
}

/// Parse an IDENTITIES_ANSWER body (after the message type byte).
fn parse_identities_answer(data: &[u8]) -> Result<Vec<AgentKey>, AgentError> {
    if data.len() < 4 {
        return Err(AgentError::Malformed("identities answer too short".into()));
    }

    let nkeys = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    let mut keys = Vec::with_capacity(nkeys.min(64));
    let mut offset = 4;

    for _ in 0..nkeys {
        let (blob, next) = read_string(data, offset)?;
        offset = next;
        let (comment_bytes, next) = read_string(data, offset)?;
        offset = next;
        keys.push(AgentKey {
            blob: blob.to_vec(),
            comment: String::from_utf8_lossy(comment_bytes).into_owned(),
        });
    }

    Ok(keys)
}

/// Parse a SIGN_RESPONSE body (after the message type byte).
/// The body is: string(signature_blob), where signature_blob = string(format) + string(sig_bytes).
fn parse_sign_response(data: &[u8]) -> Result<AgentSignature, AgentError> {
    let (sig_blob, _) = read_string(data, 0)?;

    // Inside the signature blob: string(format) + string(sig_bytes)
    let (format_bytes, offset) = read_string(sig_blob, 0)?;
    let (sig_bytes, _) = read_string(sig_blob, offset)?;

    Ok(AgentSignature {
        format: String::from_utf8_lossy(format_bytes).into_owned(),
        blob: sig_bytes.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh_string(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        wire::write_string(&mut out, data);
        out
    }

    #[test]
    fn test_parse_identities_answer_empty() {
        // Build an IDENTITIES_ANSWER body with nkeys=0
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes()); // nkeys = 0

        let keys = parse_identities_answer(&body).unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_parse_identities_answer_one_key() {
        let key_blob =
            b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let comment = b"test-key";

        // Build the body after the message type byte: nkeys=1, string(key_blob), string(comment)
        let mut body = Vec::new();
        body.extend_from_slice(&1u32.to_be_bytes()); // nkeys = 1
        body.extend_from_slice(&ssh_string(key_blob));
        body.extend_from_slice(&ssh_string(comment));

        let keys = parse_identities_answer(&body).unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].blob, key_blob);
        assert_eq!(keys[0].comment, "test-key");
    }

    #[test]
    fn test_parse_sign_response() {
        let format = b"ssh-ed25519";
        let sig_bytes = b"SIGDATA1234567890123456789012345678901234567890123456789012345678";

        // Build the inner signature blob: string(format) + string(sig_bytes)
        let mut sig_blob = Vec::new();
        sig_blob.extend_from_slice(&ssh_string(format));
        sig_blob.extend_from_slice(&ssh_string(sig_bytes));

        // Build the outer body after the message type byte: string(sig_blob)
        let body = ssh_string(&sig_blob);

        let sig = parse_sign_response(&body).unwrap();
        assert_eq!(sig.format, "ssh-ed25519");
        assert_eq!(sig.blob, sig_bytes);
    }
}
