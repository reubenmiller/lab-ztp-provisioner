//! Payload decryption — matches pkg/protocol/encrypt.go.
//!
//! Two shapes are used on the wire:
//! - [`EncryptedPayload`]  — wraps the whole SignedEnvelope (full bundle encryption).
//!   `ServerKey` = server's ephemeral key-agreement pub.
//! - [`SealedPayload`]    — wraps a single Module's payload.
//!   `EphemeralPub` = server's ephemeral key-agreement pub (different field name, same role).
//!
//! Two algorithms, selected by the payload's own `alg`:
//! - `x25519-chacha20poly1305` — the X25519 shared secret is the AEAD key.
//! - `p256-hkdf-sha256-chacha20poly1305` — P-256 ECDH, then HKDF-SHA256
//!   (empty salt, info `ztp/seal/v1`) derives the AEAD key. A P-256 shared
//!   secret is a field element, not a uniform string, so it is never used
//!   as a key directly.
//!
//! In both cases AEAD tag is appended to the ciphertext (AAD is empty, matching Go).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

use crate::suite::Suite;

pub const ALG: &str = "x25519-chacha20poly1305";
/// Sealing algorithm of [`Suite::P256`].
pub const ALG_P256: &str = "p256-hkdf-sha256-chacha20poly1305";

/// HKDF info binding derived keys to this protocol version. Must match
/// `p256HKDFInfo` in pkg/protocol/encrypt.go.
const P256_HKDF_INFO: &[u8] = b"ztp/seal/v1";

/// A per-attempt ephemeral key-agreement private key. The public half goes in
/// `EnrollRequest.ephemeral_x25519` or `EnrollRequest.ephemeral_p256`.
#[derive(Clone)]
pub enum EphemeralKey {
    X25519([u8; 32]),
    P256(p256::SecretKey),
}

impl EphemeralKey {
    /// Generate a fresh ephemeral key for `suite`.
    pub fn generate(suite: Suite) -> crate::Result<Self> {
        Ok(match suite {
            Suite::Ed25519X25519 => EphemeralKey::X25519(generate_x25519()?.0),
            Suite::P256 => EphemeralKey::P256(p256::SecretKey::random(&mut OsRng)),
        })
    }

    pub fn suite(&self) -> Suite {
        match self {
            EphemeralKey::X25519(_) => Suite::Ed25519X25519,
            EphemeralKey::P256(_) => Suite::P256,
        }
    }

    /// Base64 wire form of the public half: 32 raw X25519 bytes, or a
    /// 65-byte uncompressed P-256 point.
    pub fn public_b64(&self) -> String {
        match self {
            EphemeralKey::X25519(priv_bytes) => {
                STANDARD.encode(PublicKey::from(&StaticSecret::from(*priv_bytes)).as_bytes())
            }
            EphemeralKey::P256(sk) => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                STANDARD.encode(sk.public_key().to_encoded_point(false).as_bytes())
            }
        }
    }

    /// Derive the AEAD key shared with the sender's ephemeral public key,
    /// checking that the payload's algorithm matches this key's suite.
    fn aead_key(&self, alg: &str, peer_pub_b64: &str, field: &str) -> crate::Result<[u8; 32]> {
        match (alg, self) {
            (ALG, EphemeralKey::X25519(priv_bytes)) => {
                Ok(x25519(priv_bytes, &decode32(peer_pub_b64, field)?))
            }
            (ALG_P256, EphemeralKey::P256(sk)) => p256_key(sk, peer_pub_b64, field),
            (ALG, _) | (ALG_P256, _) => Err(format!(
                "payload is sealed with {alg:?} but this agent's ephemeral key is for the {} suite",
                self.suite()
            )
            .into()),
            _ => Err(format!("unsupported alg {alg:?}").into()),
        }
    }
}

/// Generate a fresh X25519 keypair for one enrollment attempt.
///
/// Returns (private_bytes, public_bytes). The private bytes are kept in memory
/// only for the duration of the attempt.
pub fn generate_x25519() -> crate::Result<([u8; 32], [u8; 32])> {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let _public = PublicKey::from(&secret);
    // EphemeralSecret can't give us the private bytes directly (by design),
    // so we store the public key separately and use a StaticSecret internally.
    // For our use case (store priv for the loop duration), we generate the priv
    // using OsRng and derive the public from it.
    let mut priv_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut priv_bytes);
    let static_secret = StaticSecret::from(priv_bytes);
    let pub_key = PublicKey::from(&static_secret);
    Ok((priv_bytes, *pub_key.as_bytes()))
}

// ---- EncryptedPayload -------------------------------------------------------

/// Whole-bundle ciphertext (EnrollResponse.encrypted_bundle).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    pub alg: String,        // "x25519-chacha20poly1305"
    pub server_key: String, // base64 X25519 ephemeral pub (server side)
    pub nonce: String,      // base64 12 bytes
    pub ciphertext: String, // base64 (ciphertext + 16-byte AEAD tag)
}

/// Decrypt an [`EncryptedPayload`] addressed to us using our ephemeral
/// private key.
pub fn open_for_device(device_priv: &EphemeralKey, p: &EncryptedPayload) -> crate::Result<Vec<u8>> {
    let key = device_priv.aead_key(&p.alg, &p.server_key, "server_key")?;
    let nonce_bytes = decode_bytes(&p.nonce, 12, "nonce")?;
    let ct = STANDARD.decode(&p.ciphertext)?;
    aeadOpen(&key, &nonce_bytes, &ct)
}

// ---- SealedPayload ----------------------------------------------------------

/// Per-module ciphertext (Module.sealed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedPayload {
    pub alg: String,          // "x25519-chacha20poly1305"
    pub ephemeral_pub: String, // base64 X25519 ephemeral pub (server side)
    pub nonce: String,        // base64 12 bytes
    pub ciphertext: String,   // base64 (ciphertext + 16-byte AEAD tag)
    pub format: String,       // "json" | "raw"
}

/// Decrypt a [`SealedPayload`] and return `(plaintext, format)`.
pub fn open_sealed_module(device_priv: &EphemeralKey, p: &SealedPayload) -> crate::Result<(Vec<u8>, String)> {
    let key = device_priv.aead_key(&p.alg, &p.ephemeral_pub, "ephemeral_pub")?;
    let nonce_bytes = decode_bytes(&p.nonce, 12, "nonce")?;
    let ct = STANDARD.decode(&p.ciphertext)?;
    let plaintext = aeadOpen(&key, &nonce_bytes, &ct)?;
    Ok((plaintext, p.format.clone()))
}

// ---- primitives -------------------------------------------------------------

fn x25519(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*priv_bytes);
    let their_pub = PublicKey::from(*pub_bytes);
    let shared = secret.diffie_hellman(&their_pub);
    *shared.as_bytes()
}

/// P-256 ECDH against the sender's uncompressed point, then HKDF-SHA256.
fn p256_key(sk: &p256::SecretKey, peer_pub_b64: &str, field: &str) -> crate::Result<[u8; 32]> {
    let peer = STANDARD.decode(peer_pub_b64)?;
    if peer.len() != 65 || peer[0] != 4 {
        return Err(format!(
            "{field}: expected a 65-byte uncompressed P-256 point, got {} bytes",
            peer.len()
        )
        .into());
    }
    let peer = p256::PublicKey::from_sec1_bytes(&peer)
        .map_err(|e| format!("{field}: invalid P-256 point: {e}"))?;
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), peer.as_affine());
    let mut key = [0u8; 32];
    hkdf::Hkdf::<sha2::Sha256>::new(None, shared.raw_secret_bytes())
        .expand(P256_HKDF_INFO, &mut key)
        .map_err(|e| format!("hkdf: {e}"))?;
    Ok(key)
}

#[allow(non_snake_case)]
fn aeadOpen(key: &[u8; 32], nonce: &[u8], ct: &[u8]) -> crate::Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ct).map_err(|e| format!("decrypt: {e}").into())
}

fn decode32(b64: &str, field: &str) -> crate::Result<[u8; 32]> {
    let bytes = STANDARD.decode(b64)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{field}: expected 32 bytes, got {}", bytes.len()).into())
}

fn decode_bytes(b64: &str, expected_len: usize, field: &str) -> crate::Result<Vec<u8>> {
    let bytes = STANDARD.decode(b64)?;
    if bytes.len() != expected_len {
        return Err(format!("{field}: expected {expected_len} bytes, got {}", bytes.len()).into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic seal helper for testing (fixed nonce).
    fn seal_with_fixed_nonce(
        device_pub: &[u8; 32],
        server_priv: &[u8; 32],
        nonce: &[u8; 12],
        plaintext: &[u8],
    ) -> EncryptedPayload {
        let shared = x25519(server_priv, device_pub);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&shared));
        let n = Nonce::from_slice(nonce);
        let ct = cipher.encrypt(n, plaintext).unwrap();

        let server_static = StaticSecret::from(*server_priv);
        let server_pub = PublicKey::from(&server_static);

        EncryptedPayload {
            alg: ALG.to_string(),
            server_key: STANDARD.encode(server_pub.as_bytes()),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(&ct),
        }
    }

    #[test]
    fn open_for_device_roundtrip() {
        let device_priv: [u8; 32] = (1u8..=32).collect::<Vec<_>>().try_into().unwrap();
        let device_static = StaticSecret::from(device_priv);
        let device_pub = *PublicKey::from(&device_static).as_bytes();

        let server_priv: [u8; 32] = {
            let v: Vec<u8> = (1..=32).rev().collect();
            v.try_into().unwrap()
        };
        let nonce = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        let plaintext = b"hello world";

        let ep = seal_with_fixed_nonce(&device_pub, &server_priv, &nonce, plaintext);
        let got = open_for_device(&EphemeralKey::X25519(device_priv), &ep).unwrap();
        assert_eq!(got, plaintext);
    }

    #[test]
    fn wrong_key_fails() {
        let device_priv: [u8; 32] = (1u8..=32).collect::<Vec<_>>().try_into().unwrap();
        let device_static = StaticSecret::from(device_priv);
        let device_pub = *PublicKey::from(&device_static).as_bytes();

        let server_priv: [u8; 32] = {
            let v: Vec<u8> = (1..=32).rev().collect();
            v.try_into().unwrap()
        };
        let nonce = [0u8; 12];
        let ep = seal_with_fixed_nonce(&device_pub, &server_priv, &nonce, b"secret");

        // Use a wrong device key
        let wrong_priv: [u8; 32] = [42u8; 32];
        assert!(open_for_device(&EphemeralKey::X25519(wrong_priv), &ep).is_err());
    }

    /// Server-side P-256 seal, mirroring sealWithSuite in encrypt.go.
    fn seal_p256(device_pub_b64: &str, plaintext: &[u8]) -> SealedPayload {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let server = p256::SecretKey::random(&mut OsRng);
        let key = p256_key(&server, device_pub_b64, "device").unwrap();
        let nonce = [7u8; 12];
        let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .unwrap();
        SealedPayload {
            alg: ALG_P256.to_string(),
            ephemeral_pub: STANDARD.encode(server.public_key().to_encoded_point(false).as_bytes()),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ct),
            format: "raw".to_string(),
        }
    }

    #[test]
    fn p256_sealed_module_roundtrip() {
        let device = EphemeralKey::generate(Suite::P256).unwrap();
        let sealed = seal_p256(&device.public_b64(), b"[c8y]\nurl=x\n");
        let (pt, format) = open_sealed_module(&device, &sealed).unwrap();
        assert_eq!(pt, b"[c8y]\nurl=x\n");
        assert_eq!(format, "raw");

        let other = EphemeralKey::generate(Suite::P256).unwrap();
        assert!(open_sealed_module(&other, &sealed).is_err());
    }

    #[test]
    fn suite_mismatch_is_named() {
        let device = EphemeralKey::generate(Suite::P256).unwrap();
        let sealed = seal_p256(&device.public_b64(), b"x");
        let x = EphemeralKey::generate(Suite::Ed25519X25519).unwrap();
        let err = open_sealed_module(&x, &sealed).unwrap_err().to_string();
        assert!(err.contains("ed25519-x25519"), "{err}");
    }
}
