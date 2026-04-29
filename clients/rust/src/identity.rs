//! Ed25519 identity key — mirrors internal/agent/identity/identity.go.
//!
//! File format: base64-encoded 64-byte Ed25519 private key (Go format):
//!   bytes[0..32] = 32-byte seed
//!   bytes[32..64] = 32-byte public key (= seed's derived public key)
//!
//! File permissions: 0o600 (read/write owner only).
//! Parent directory created with 0o700 if missing.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::path::Path;

#[derive(Clone)]
pub struct Identity {
    signing_key: SigningKey,
}

impl Identity {
    /// Load or create an identity key at `path`.
    pub fn load_or_create(path: &Path) -> crate::Result<Self> {
        match std::fs::read(path) {
            Ok(contents) => {
                let raw = STANDARD.decode(contents.trim_ascii())?;
                if raw.len() != 64 {
                    return Err(format!(
                        "identity key at {}: expected 64 bytes, got {}",
                        path.display(),
                        raw.len()
                    )
                    .into());
                }
                // Go format: first 32 bytes = seed
                let seed: [u8; 32] = raw[..32].try_into().unwrap();
                Ok(Self {
                    signing_key: SigningKey::from_bytes(&seed),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Self::create_new(path)
            }
            Err(e) => Err(e.into()),
        }
    }

    fn create_new(path: &Path) -> crate::Result<Self> {
        // Create parent directory with 0o700
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                create_dir_secure(parent)?;
            }
        }

        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let seed = signing_key.as_bytes(); // 32-byte seed
        let pub_bytes = signing_key.verifying_key().to_bytes(); // 32-byte pub

        // Construct 64-byte Go-format private key: seed || pubkey
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(seed);
        raw[32..].copy_from_slice(&pub_bytes);

        let encoded = STANDARD.encode(raw);
        write_file_secure(path, encoded.as_bytes())?;

        Ok(Self { signing_key })
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
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

        let id1 = Identity::load_or_create(&path).unwrap();
        let pub1 = id1.verifying_key();

        // Second call should load the same key
        let id2 = Identity::load_or_create(&path).unwrap();
        assert_eq!(id2.verifying_key().as_bytes(), pub1.as_bytes());
    }

    #[test]
    fn creates_parent_dir() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("subdir").join("nested").join("identity.key");
        Identity::load_or_create(&path).unwrap();
        assert!(path.exists());
    }
}
