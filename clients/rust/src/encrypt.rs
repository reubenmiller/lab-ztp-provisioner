//! X25519 + ChaCha20-Poly1305 encryption — matches pkg/protocol/encrypt.go.
//!
//! Two shapes are used on the wire:
//! - [`EncryptedPayload`]  — wraps the whole SignedEnvelope (full bundle encryption).
//!   `ServerKey` = server's ephemeral X25519 pub.
//! - [`SealedPayload`]    — wraps a single Module's payload.
//!   `EphemeralPub` = server's ephemeral X25519 pub (different field name, same role).
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

pub const ALG: &str = "x25519-chacha20poly1305";

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

/// Decrypt an [`EncryptedPayload`] addressed to us using our ephemeral X25519
/// private key.
pub fn open_for_device(device_priv: &[u8; 32], p: &EncryptedPayload) -> crate::Result<Vec<u8>> {
    if p.alg != ALG {
        return Err(format!("unsupported alg {:?}", p.alg).into());
    }
    let srv_pub_bytes = decode32(&p.server_key, "server_key")?;
    let nonce_bytes = decode_bytes(&p.nonce, 12, "nonce")?;
    let ct = STANDARD.decode(&p.ciphertext)?;

    let shared = x25519(device_priv, &srv_pub_bytes);
    aeadOpen(&shared, &nonce_bytes, &ct)
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
pub fn open_sealed_module(device_priv: &[u8; 32], p: &SealedPayload) -> crate::Result<(Vec<u8>, String)> {
    if p.alg != ALG {
        return Err(format!("unsupported alg {:?}", p.alg).into());
    }
    let srv_pub_bytes = decode32(&p.ephemeral_pub, "ephemeral_pub")?;
    let nonce_bytes = decode_bytes(&p.nonce, 12, "nonce")?;
    let ct = STANDARD.decode(&p.ciphertext)?;

    let shared = x25519(device_priv, &srv_pub_bytes);
    let plaintext = aeadOpen(&shared, &nonce_bytes, &ct)?;
    Ok((plaintext, p.format.clone()))
}

// ---- primitives -------------------------------------------------------------

fn x25519(priv_bytes: &[u8; 32], pub_bytes: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*priv_bytes);
    let their_pub = PublicKey::from(*pub_bytes);
    let shared = secret.diffie_hellman(&their_pub);
    *shared.as_bytes()
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
        let got = open_for_device(&device_priv, &ep).unwrap();
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
        assert!(open_for_device(&wrong_priv, &ep).is_err());
    }
}
