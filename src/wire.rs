//! SSH wire-format primitives shared by the agent protocol and SSHSIG modules.

/// Write an SSH-string (4-byte big-endian length prefix + payload) into `buf`.
pub fn write_string(buf: &mut Vec<u8>, data: &[u8]) {
    buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
    buf.extend_from_slice(data);
}

/// Read an SSH-string from `data` at `offset`. Returns `(bytes, new_offset)`.
pub fn read_string(data: &[u8], offset: usize) -> Result<(&[u8], usize), WireError> {
    if offset + 4 > data.len() {
        return Err(WireError("truncated string length"));
    }
    let len = u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    let start = offset + 4;
    let end = start + len;
    if end > data.len() {
        return Err(WireError("truncated string data"));
    }
    Ok((&data[start..end], end))
}

/// Error from wire-format parsing.
#[derive(Debug)]
pub struct WireError(pub &'static str);

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for WireError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let mut buf = Vec::new();
        write_string(&mut buf, b"hello");

        let (result, end) = read_string(&buf, 0).unwrap();
        assert_eq!(result, b"hello");
        assert_eq!(end, buf.len());
    }

    #[test]
    fn test_length_prefix() {
        let mut buf = Vec::new();
        write_string(&mut buf, b"hello");
        assert_eq!(&buf[0..4], &[0, 0, 0, 5]);
        assert_eq!(&buf[4..], b"hello");
    }
}
