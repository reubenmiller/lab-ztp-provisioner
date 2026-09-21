//! Device identity key — mirrors internal/agent/identity/identity.go.
//!
//! File format depends on the key's crypto suite; it is detected on load:
//! - Ed25519: base64-encoded 64-byte Ed25519 private key (Go format):
//!     bytes[0..32] = 32-byte seed
//!     bytes[32..64] = 32-byte public key (= seed's derived public key)
//! - P-256: base64-encoded PKCS#8 DER (the same shape the server uses for its
//!   own P-256 signing key, and readable with `openssl pkey -inform DER`).
//!
//! The suite is fixed when the key is created. Loading a key of a different
//! suite than requested is an error rather than a silent switch: the server
//! identifies the device by this key, so changing suite is a re-identity.
//!
//! File permissions: 0o600 (read/write owner only).
//! Parent directory created with 0o700 if missing.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use std::path::Path;

use crate::sign::{PrivateKey, PublicKey};
use crate::suite::Suite;

#[derive(Clone)]
pub struct Identity {
    signing_key: PrivateKey,
}

impl Identity {
    /// Load the identity key at `path`, or create one for `suite` if absent.
    pub fn load_or_create(path: &Path, suite: Suite) -> crate::Result<Self> {
        match std::fs::read(path) {
            Ok(contents) => {
                let raw = STANDARD.decode(contents.trim_ascii())?;
                let signing_key = decode_key(&raw)
                    .map_err(|e| format!("identity key at {}: {e}", path.display()))?;
                if signing_key.suite() != suite {
                    return Err(format!(
                        "identity key at {} is for the {} crypto suite but {} was requested; \
                         remove the key (the device will re-enroll as a new identity) \
                         or select the matching suite",
                        path.display(),
                        signing_key.suite(),
                        suite
                    )
                    .into());
                }
                Ok(Self { signing_key })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::create_new(path, suite)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn create_new(path: &Path, suite: Suite) -> crate::Result<Self> {
        // Create parent directory with 0o700
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                create_dir_secure(parent)?;
            }
        }

        let signing_key = PrivateKey::generate(suite);
        let raw: Vec<u8> = match &signing_key {
            PrivateKey::Ed25519(k) => {
                // 64-byte Go-format private key: seed || pubkey
                let mut raw = k.as_bytes().to_vec();
                raw.extend_from_slice(&k.verifying_key().to_bytes());
                raw
            }
            PrivateKey::P256(k) => p256::SecretKey::from(*k.as_nonzero_scalar())
                .to_pkcs8_der()
                .map_err(|e| format!("encode P-256 identity key: {e}"))?
                .as_bytes()
                .to_vec(),
        };

        let encoded = STANDARD.encode(raw);
        write_file_secure(path, encoded.as_bytes())?;

        Ok(Self { signing_key })
    }

    pub fn signing_key(&self) -> &PrivateKey {
        &self.signing_key
    }

    pub fn public_key(&self) -> PublicKey {
        self.signing_key.public_key()
    }

    pub fn suite(&self) -> Suite {
        self.signing_key.suite()
    }
}

/// Decode an identity file's bytes: exactly 64 bytes is the Go Ed25519 format,
/// anything else must be a PKCS#8 P-256 key.
fn decode_key(raw: &[u8]) -> crate::Result<PrivateKey> {
    if raw.len() == 64 {
        let seed: [u8; 32] = raw[..32].try_into().unwrap();
        return Ok(ed25519_dalek::SigningKey::from_bytes(&seed).into());
    }
    p256::ecdsa::SigningKey::from_pkcs8_der(raw)
        .map(PrivateKey::P256)
        .map_err(|e| {
            format!(
                "expected a 64-byte Ed25519 key or a PKCS#8 P-256 key ({} bytes, {e})",
                raw.len()
            )
            .into()
        })
}

#[cfg(unix)]
fn create_dir_secure(path: &Path) -> crate::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .map_err(|e| format!("create dir {}: {e}", path.display()).into())
}

#[cfg(not(unix))]
fn create_dir_secure(path: &Path) -> crate::Result<()> {
    std::fs::create_dir_all(path)
        .map_err(|e| format!("create dir {}: {e}", path.display()).into())
}

#[cfg(unix)]
fn write_file_secure(path: &Path, data: &[u8]) -> crate::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true).mode(0o600);
    let mut f = opts
        .open(path)
        .map_err(|e| format!("create identity file {}: {e}", path.display()))?;
    use std::io::Write;
    f.write_all(data)
        .map_err(|e| format!("write identity file: {e}").into())
}

#[cfg(not(unix))]
fn write_file_secure(path: &Path, data: &[u8]) -> crate::Result<()> {
    std::fs::write(path, data).map_err(|e| e.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn create_and_reload() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");

        let id1 = Identity::load_or_create(&path, Suite::Ed25519X25519).unwrap();
        let pub1 = id1.public_key();

        // Second call should load the same key
        let id2 = Identity::load_or_create(&path, Suite::Ed25519X25519).unwrap();
        assert_eq!(id2.public_key(), pub1);
    }

    #[test]
    fn create_and_reload_p256() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");

        let id1 = Identity::load_or_create(&path, Suite::P256).unwrap();
        assert_eq!(id1.suite(), Suite::P256);
        let id2 = Identity::load_or_create(&path, Suite::P256).unwrap();
        assert_eq!(id2.public_key(), id1.public_key());
    }

    #[test]
    fn suite_mismatch_is_an_error() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("identity.key");
        Identity::load_or_create(&path, Suite::Ed25519X25519).unwrap();
        let err = Identity::load_or_create(&path, Suite::P256).err().unwrap();
        assert!(err.to_string().contains("ed25519-x25519"), "{err}");
    }

    #[test]
    fn creates_parent_dir() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("subdir").join("nested").join("identity.key");
        Identity::load_or_create(&path, Suite::Ed25519X25519).unwrap();
        assert!(path.exists());
    }
}
