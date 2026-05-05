use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;

use crate::wire;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const HASH_SHA512: &str = "sha512";
pub const HASH_SHA256: &str = "sha256";

const MAGIC_PREAMBLE: &[u8] = b"SSHSIG";
const SIG_VERSION: u32 = 1;
const ARMOR_LINE_LEN: usize = 70;
const BEGIN_MARKER: &str = "-----BEGIN SSH SIGNATURE-----";
const END_MARKER: &str = "-----END SSH SIGNATURE-----";

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum Error {
    #[error("empty namespace")]
    EmptyNamespace,
    #[error("unsupported hash algorithm: {0}")]
    UnsupportedHash(String),
    #[error("sign: {0}")]
    Sign(String),
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Raw SSH signature: algorithm format string + raw signature blob.
pub struct SshSignature {
    pub format: String,
    pub blob: Vec<u8>,
}

/// SSH public key in wire format.
pub struct SshPublicKey {
    pub wire: Vec<u8>,
}

/// Trait for anything that can produce SSH signatures (e.g. an ssh-agent).
pub trait Signer {
    fn public_key(&self) -> &SshPublicKey;
    fn sign(&self, data: &[u8]) -> Result<SshSignature, Box<dyn std::error::Error + Send + Sync>>;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hash `message` with the given algorithm name, returning the digest bytes.
fn hash_message(hash_alg: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
    match hash_alg {
        HASH_SHA512 => {
            let mut hasher = Sha512::new();
            hasher.update(message);
            Ok(hasher.finalize().to_vec())
        }
        HASH_SHA256 => {
            let mut hasher = Sha256::new();
            hasher.update(message);
            Ok(hasher.finalize().to_vec())
        }
        other => Err(Error::UnsupportedHash(other.to_string())),
    }
}

/// Build the "signed data" blob that the signer will actually sign.
///
/// Layout (from the OpenSSH SSHSIG spec):
///   MAGIC_PREAMBLE (6 raw bytes, no length prefix)
///   SSH-string(namespace)
///   SSH-string(reserved = "")
///   SSH-string(hash_alg)
///   SSH-string(H(message))
fn build_signed_data(namespace: &str, hash_alg: &str, message_hash: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_PREAMBLE);
    wire::write_string(&mut buf, namespace.as_bytes());
    wire::write_string(&mut buf, b""); // reserved
    wire::write_string(&mut buf, hash_alg.as_bytes());
    wire::write_string(&mut buf, message_hash);
    buf
}

/// Marshal the final SSHSIG envelope (binary, before armoring).
///
/// Layout:
///   MAGIC_PREAMBLE (6 raw bytes)
///   uint32(SIG_VERSION)      -- 4 bytes big-endian, NOT an SSH-string
///   SSH-string(pubkey_wire)
///   SSH-string(namespace)
///   SSH-string(reserved = "")
///   SSH-string(hash_alg)
///   SSH-string(sig_wire)
///
/// where sig_wire is:
///   SSH-string(format) + SSH-string(sig_blob)
fn marshal_signature(
    pubkey: &SshPublicKey,
    namespace: &str,
    hash_alg: &str,
    sig: &SshSignature,
) -> Vec<u8> {
    // Build sig_wire = SSH-string(format) + SSH-string(blob)
    let mut sig_wire = Vec::new();
    wire::write_string(&mut sig_wire, sig.format.as_bytes());
    wire::write_string(&mut sig_wire, &sig.blob);

    let mut buf = Vec::new();
    buf.extend_from_slice(MAGIC_PREAMBLE);
    buf.extend_from_slice(&SIG_VERSION.to_be_bytes());
    wire::write_string(&mut buf, &pubkey.wire);
    wire::write_string(&mut buf, namespace.as_bytes());
    wire::write_string(&mut buf, b""); // reserved
    wire::write_string(&mut buf, hash_alg.as_bytes());
    wire::write_string(&mut buf, &sig_wire);
    buf
}

/// PEM-style armor: base64 with 70-column wrapping and BEGIN/END markers.
fn armor(data: &[u8]) -> Vec<u8> {
    let b64 = STANDARD.encode(data);
    let mut out = String::new();
    out.push_str(BEGIN_MARKER);
    out.push('\n');
    for chunk in b64.as_bytes().chunks(ARMOR_LINE_LEN) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is always valid utf-8"));
        out.push('\n');
    }
    out.push_str(END_MARKER);
    out.push('\n');
    out.into_bytes()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Sign `message` under `namespace` using SHA-512 (the default hash).
pub fn sign(signer: &dyn Signer, namespace: &str, message: &[u8]) -> Result<Vec<u8>, Error> {
    sign_with_hash(signer, namespace, HASH_SHA512, message)
}

/// Sign `message` under `namespace` using the specified hash algorithm.
pub fn sign_with_hash(
    signer: &dyn Signer,
    namespace: &str,
    hash_alg: &str,
    message: &[u8],
) -> Result<Vec<u8>, Error> {
    if namespace.is_empty() {
        return Err(Error::EmptyNamespace);
    }

    // 1. Hash the message.
    let message_hash = hash_message(hash_alg, message)?;

    // 2. Build the blob that the signer will sign.
    let signed_data = build_signed_data(namespace, hash_alg, &message_hash);

    // 3. Sign it.
    let sig = signer
        .sign(&signed_data)
        .map_err(|e| Error::Sign(e.to_string()))?;

    // 4. Marshal the full SSHSIG envelope.
    let envelope = marshal_signature(signer.public_key(), namespace, hash_alg, &sig);

    // 5. Armor and return.
    Ok(armor(&envelope))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Dummy signer for tests that don't need real cryptography.
    struct DummySigner {
        pubkey: SshPublicKey,
    }

    impl DummySigner {
        fn new() -> Self {
            Self {
                pubkey: SshPublicKey {
                    wire: vec![0u8; 32],
                },
            }
        }
    }

    impl Signer for DummySigner {
        fn public_key(&self) -> &SshPublicKey {
            &self.pubkey
        }
        fn sign(
            &self,
            _data: &[u8],
        ) -> Result<SshSignature, Box<dyn std::error::Error + Send + Sync>> {
            Ok(SshSignature {
                format: "ssh-ed25519".to_string(),
                blob: vec![0u8; 64],
            })
        }
    }

    #[test]
    fn test_armor_wrap_70() {
        let data = vec![0u8; 140];
        let armored = armor(&data);
        let text = std::str::from_utf8(&armored).unwrap();
        let lines: Vec<&str> = text.lines().collect();

        // First line is BEGIN marker.
        assert_eq!(lines[0], BEGIN_MARKER);
        // Last line is END marker.
        assert_eq!(lines[lines.len() - 1], END_MARKER);

        // All base64 lines except possibly the last one must be exactly 70 chars.
        let b64_lines = &lines[1..lines.len() - 1];
        assert!(
            !b64_lines.is_empty(),
            "should have at least one base64 line"
        );
        for line in &b64_lines[..b64_lines.len() - 1] {
            assert_eq!(
                line.len(),
                70,
                "interior base64 line should be 70 chars, got {}",
                line.len()
            );
        }
    }

    #[test]
    fn test_sign_rejects_empty_namespace() {
        let signer = DummySigner::new();
        let result = sign(&signer, "", b"hello");
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), Error::EmptyNamespace),
            "expected EmptyNamespace error"
        );
    }

    #[test]
    fn test_build_signed_blob_structure() {
        let hash = vec![0u8; 64]; // fake hash
        let blob = build_signed_data("git", HASH_SHA512, &hash);

        // Must start with raw SSHSIG magic (6 bytes, no length prefix).
        assert_eq!(&blob[..6], b"SSHSIG");

        // Next should be SSH-string("git") = [0,0,0,3] + b"git"
        assert_eq!(&blob[6..10], &[0, 0, 0, 3]);
        assert_eq!(&blob[10..13], b"git");
    }

    // -----------------------------------------------------------------------
    // SSHSIG byte-equality tests against ssh-keygen
    // -----------------------------------------------------------------------

    use ed25519_dalek::Signer as DalekSigner;
    use rsa::signature::SignatureEncoding;
    use rsa::traits::PublicKeyParts;

    /// Check whether ssh-keygen is available; return its path or None.
    fn find_ssh_keygen() -> Option<String> {
        std::process::Command::new("ssh-keygen")
            .arg("-Y")
            .arg("sign")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()
            .map(|_| "ssh-keygen".to_string())
    }

    /// Run `ssh-keygen -Y sign -n <namespace> -f <keyfile>` piping `message`
    /// on stdin. Returns the armored signature bytes from stdout.
    fn run_ssh_keygen_sign(key_path: &str, namespace: &str, message: &[u8]) -> Vec<u8> {
        let output = std::process::Command::new("ssh-keygen")
            .args(["-Y", "sign", "-n", namespace, "-f", key_path])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(message)
                    .expect("write stdin");
                child.wait_with_output()
            })
            .expect("ssh-keygen -Y sign failed");

        assert!(
            output.status.success(),
            "ssh-keygen -Y sign failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    }

    /// Run `ssh-keygen -Y check-novalidate` to verify a signature is accepted.
    fn run_ssh_keygen_check(namespace: &str, message: &[u8], signature: &[u8]) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let sig_path = dir.path().join("msg.sig");
        std::fs::write(&sig_path, signature).expect("write sig file");

        let output = std::process::Command::new("ssh-keygen")
            .args([
                "-Y",
                "check-novalidate",
                "-n",
                namespace,
                "-s",
                sig_path.to_str().unwrap(),
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(message)
                    .expect("write stdin");
                child.wait_with_output()
            })
            .expect("ssh-keygen -Y check-novalidate failed");

        assert!(
            output.status.success(),
            "ssh-keygen -Y check-novalidate rejected our signature:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // -- Ed25519 test signer --------------------------------------------------

    /// A Signer backed by a local Ed25519 key for tests.
    struct Ed25519TestSigner {
        signing_key: ed25519_dalek::SigningKey,
        pubkey: SshPublicKey,
    }

    impl Ed25519TestSigner {
        fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
            let verifying_key = signing_key.verifying_key();
            let pk_bytes = verifying_key.to_bytes();

            // SSH wire format: SSH-string("ssh-ed25519") + SSH-string(32-byte key)
            let mut wire = Vec::new();
            wire::write_string(&mut wire, b"ssh-ed25519");
            wire::write_string(&mut wire, &pk_bytes);

            Self {
                signing_key,
                pubkey: SshPublicKey { wire },
            }
        }
    }

    impl super::Signer for Ed25519TestSigner {
        fn public_key(&self) -> &SshPublicKey {
            &self.pubkey
        }

        fn sign(
            &self,
            data: &[u8],
        ) -> Result<SshSignature, Box<dyn std::error::Error + Send + Sync>> {
            let sig = self.signing_key.sign(data);
            Ok(SshSignature {
                format: "ssh-ed25519".to_string(),
                blob: sig.to_bytes().to_vec(),
            })
        }
    }

    /// Write an Ed25519 private key to a temp file in OpenSSH format, returning the path.
    fn write_ed25519_key_file(
        dir: &std::path::Path,
        signing_key: &ed25519_dalek::SigningKey,
    ) -> String {
        use ssh_key::PrivateKey;
        use ssh_key::private::Ed25519Keypair;

        let keypair = Ed25519Keypair::from(signing_key);
        let private_key = PrivateKey::from(keypair);
        let pem = private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("serialize ed25519 key to openssh");

        let key_path = dir.join("id_ed25519");
        std::fs::write(&key_path, pem.as_str()).expect("write key file");

        // Set permissions to 0600 so ssh-keygen will accept it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }

        key_path.to_str().unwrap().to_string()
    }

    // -- RSA test signer ------------------------------------------------------

    /// A Signer backed by a local RSA key for tests.
    struct RsaTestSigner {
        signing_key: rsa::pkcs1v15::SigningKey<rsa::sha2::Sha512>,
        pubkey: SshPublicKey,
    }

    impl RsaTestSigner {
        fn new(private_key: rsa::RsaPrivateKey) -> Self {
            let public_key = private_key.to_public_key();

            // SSH wire format for RSA: SSH-string("ssh-rsa") + SSH-string(e) + SSH-string(n)
            // Both e and n are encoded as mpint (big-endian, with leading zero if MSB set).
            let mut wire = Vec::new();
            wire::write_string(&mut wire, b"ssh-rsa");
            wire::write_string(&mut wire, &to_ssh_mpint(&public_key.e().to_bytes_be()));
            wire::write_string(&mut wire, &to_ssh_mpint(&public_key.n().to_bytes_be()));

            let signing_key = rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha512>::new(private_key);

            Self {
                signing_key,
                pubkey: SshPublicKey { wire },
            }
        }
    }

    /// Convert a big-endian unsigned integer to SSH mpint encoding.
    /// SSH mpint prepends a zero byte if the MSB of the first byte is set.
    fn to_ssh_mpint(bytes: &[u8]) -> Vec<u8> {
        // Strip leading zeros (but keep at least one byte).
        let stripped = match bytes.iter().position(|&b| b != 0) {
            Some(pos) => &bytes[pos..],
            None => &[0],
        };

        if stripped[0] & 0x80 != 0 {
            let mut result = Vec::with_capacity(1 + stripped.len());
            result.push(0);
            result.extend_from_slice(stripped);
            result
        } else {
            stripped.to_vec()
        }
    }

    impl super::Signer for RsaTestSigner {
        fn public_key(&self) -> &SshPublicKey {
            &self.pubkey
        }

        fn sign(
            &self,
            data: &[u8],
        ) -> Result<SshSignature, Box<dyn std::error::Error + Send + Sync>> {
            use rsa::signature::Signer as _;
            let sig = self.signing_key.sign(data);
            Ok(SshSignature {
                format: "rsa-sha2-512".to_string(),
                blob: sig.to_vec(),
            })
        }
    }

    /// Write an RSA private key to a temp file in OpenSSH format, returning the path.
    fn write_rsa_key_file(dir: &std::path::Path, private_key: &rsa::RsaPrivateKey) -> String {
        use ssh_key::PrivateKey;
        use ssh_key::private::RsaKeypair;

        let keypair =
            RsaKeypair::try_from(private_key).expect("convert rsa key to ssh-key keypair");
        let ssh_private_key = PrivateKey::from(keypair);
        let pem = ssh_private_key
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("serialize rsa key to openssh");

        let key_path = dir.join("id_rsa");
        std::fs::write(&key_path, pem.as_str()).expect("write key file");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .expect("chmod 600");
        }

        key_path.to_str().unwrap().to_string()
    }

    // -- The core byte-equality tests -----------------------------------------

    /// Ed25519 is deterministic: same key + same message = same signature.
    /// Our output must be byte-for-byte identical to `ssh-keygen -Y sign`.
    #[test]
    fn test_sign_matches_ssh_keygen_ed25519() {
        if find_ssh_keygen().is_none() {
            eprintln!("SKIPPED: ssh-keygen not available");
            return;
        }

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);

        let signer = Ed25519TestSigner::new(signing_key.clone());

        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = write_ed25519_key_file(dir.path(), &signing_key);

        let namespace = "git";
        let message = b"tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\ncommit body\n";

        let ours = sign(&signer, namespace, message).expect("our sign");
        let theirs = run_ssh_keygen_sign(&key_path, namespace, message);

        assert_eq!(
            ours,
            theirs,
            "Ed25519 signature mismatch\nours:\n{}\ntheirs:\n{}",
            String::from_utf8_lossy(&ours),
            String::from_utf8_lossy(&theirs)
        );
    }

    /// RSA with PKCS#1 v1.5 is also deterministic, so byte equality is expected.
    #[test]
    fn test_sign_matches_ssh_keygen_rsa() {
        if find_ssh_keygen().is_none() {
            eprintln!("SKIPPED: ssh-keygen not available");
            return;
        }

        let private_key =
            rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("generate rsa key");

        let signer = RsaTestSigner::new(private_key.clone());

        let dir = tempfile::tempdir().expect("create tempdir");
        let key_path = write_rsa_key_file(dir.path(), &private_key);

        let namespace = "git";
        let message = b"rsa test payload\n";

        let ours = sign(&signer, namespace, message).expect("our sign");
        let theirs = run_ssh_keygen_sign(&key_path, namespace, message);

        assert_eq!(
            ours,
            theirs,
            "RSA signature mismatch\nours:\n{}\ntheirs:\n{}",
            String::from_utf8_lossy(&ours),
            String::from_utf8_lossy(&theirs)
        );
    }

    /// Verify that ssh-keygen accepts our Ed25519 signatures via check-novalidate.
    /// This catches structural problems in the blob that byte-compare might miss.
    #[test]
    fn test_sign_accepted_by_ssh_keygen_check() {
        if find_ssh_keygen().is_none() {
            eprintln!("SKIPPED: ssh-keygen not available");
            return;
        }

        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
        let signer = Ed25519TestSigner::new(signing_key);

        let namespace = "git";
        let message = b"hello, git signing\n";

        let sig = sign(&signer, namespace, message).expect("our sign");
        run_ssh_keygen_check(namespace, message, &sig);
    }

    /// Verify that ssh-keygen accepts our RSA signatures via check-novalidate.
    #[test]
    fn test_sign_rsa_accepted_by_ssh_keygen_check() {
        if find_ssh_keygen().is_none() {
            eprintln!("SKIPPED: ssh-keygen not available");
            return;
        }

        let private_key =
            rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("generate rsa key");
        let signer = RsaTestSigner::new(private_key);

        let namespace = "git";
        let message = b"rsa check-novalidate test\n";

        let sig = sign(&signer, namespace, message).expect("our sign");
        run_ssh_keygen_check(namespace, message, &sig);
    }
}
