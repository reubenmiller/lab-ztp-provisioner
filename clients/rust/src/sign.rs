//! Envelope sign / verify — matches pkg/protocol/sign.go.
//!
//! Signing input = RFC 8785 canonical JSON bytes of the payload struct.
//! The signature covers exactly those bytes (no additional framing).
//!
//! Two algorithms, one per [`Suite`]:
//! - `ed25519` — 32-byte public keys, 64-byte signatures.
//! - `ecdsa-p256-sha256` — uncompressed 65-byte SEC 1 public keys and raw
//!   64-byte `r‖s` signatures (no ASN.1), the forms PSA emits.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer as _, Verifier as _};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::canonical;
use crate::suite::{Suite, ALG_ECDSA_P256, ALG_ED25519};

/// Length of an uncompressed P-256 point: 0x04 tag + two 32-byte coordinates.
const P256_POINT_LEN: usize = 65;

/// Wire-format signed envelope (matches protocol.SignedEnvelope in wire.go).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub protocol_version: String,
    pub key_id: String,
    pub alg: String,       // "ed25519" | "ecdsa-p256-sha256"
    pub payload: String,   // base64(canonical JSON)
    pub signature: String, // base64(signature)
}

/// A signing key under one of the supported suites.
#[derive(Clone)]
pub enum PrivateKey {
    Ed25519(ed25519_dalek::SigningKey),
    P256(p256::ecdsa::SigningKey),
}

impl PrivateKey {
    /// Generate a fresh key for `suite`.
    pub fn generate(suite: Suite) -> Self {
        match suite {
            Suite::Ed25519X25519 => PrivateKey::Ed25519(ed25519_dalek::SigningKey::generate(&mut OsRng)),
            Suite::P256 => PrivateKey::P256(p256::ecdsa::SigningKey::random(&mut OsRng)),
        }
    }

    pub fn suite(&self) -> Suite {
        match self {
            PrivateKey::Ed25519(_) => Suite::Ed25519X25519,
            PrivateKey::P256(_) => Suite::P256,
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(k) => PublicKey::Ed25519(k.verifying_key()),
            PrivateKey::P256(k) => PublicKey::P256(*k.verifying_key()),
        }
    }

    fn sign_bytes(&self, msg: &[u8]) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(k) => k.sign(msg).to_bytes().to_vec(),
            PrivateKey::P256(k) => {
                // SHA-256 digest + RFC 6979 nonce; to_bytes() is raw r‖s.
                let sig: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(k, msg);
                sig.to_bytes().to_vec()
            }
        }
    }
}

impl From<ed25519_dalek::SigningKey> for PrivateKey {
    fn from(k: ed25519_dalek::SigningKey) -> Self {
        PrivateKey::Ed25519(k)
    }
}

impl From<p256::ecdsa::SigningKey> for PrivateKey {
    fn from(k: p256::ecdsa::SigningKey) -> Self {
        PrivateKey::P256(k)
    }
}

/// A verifying key under one of the supported suites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl PublicKey {
    pub fn suite(&self) -> Suite {
        match self {
            PublicKey::Ed25519(_) => Suite::Ed25519X25519,
            PublicKey::P256(_) => Suite::P256,
        }
    }

    /// Raw wire bytes: 32-byte Ed25519 key or 65-byte uncompressed P-256 point.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PublicKey::Ed25519(k) => k.as_bytes().to_vec(),
            PublicKey::P256(k) => k.to_encoded_point(false).as_bytes().to_vec(),
        }
    }

    /// Parse raw wire bytes, choosing the key type by length.
    pub fn from_bytes(b: &[u8]) -> crate::Result<Self> {
        match b.len() {
            32 => {
                let arr: [u8; 32] = b.try_into().unwrap();
                ed25519_dalek::VerifyingKey::from_bytes(&arr)
                    .map(PublicKey::Ed25519)
                    .map_err(|e| format!("invalid Ed25519 public key: {e}").into())
            }
            P256_POINT_LEN if b[0] == 4 => p256::ecdsa::VerifyingKey::from_sec1_bytes(b)
                .map(PublicKey::P256)
                .map_err(|e| format!("invalid P-256 point: {e}").into()),
            n => Err(format!(
                "public key must be a 32-byte Ed25519 key or a {P256_POINT_LEN}-byte \
                 uncompressed P-256 point, got {n} bytes"
            )
            .into()),
        }
    }
}

/// Sign `value` with `key`, returning a [`SignedEnvelope`] whose `alg` follows
/// the key's suite.
///
/// `key_id` is an opaque label for the signer, e.g. `"device"` or `"server"`.
pub fn sign<T: Serialize>(value: &T, key: &PrivateKey, key_id: &str) -> crate::Result<SignedEnvelope> {
    let canon = canonical::canonicalize(value)?;
    let sig = key.sign_bytes(&canon);
    Ok(SignedEnvelope {
        protocol_version: crate::wire::VERSION.to_string(),
        key_id: key_id.to_string(),
        alg: key.suite().sign_alg().to_string(),
        payload: STANDARD.encode(&canon),
        signature: STANDARD.encode(sig),
    })
}

/// Verify the signature on `env` using `pub_key`.
///
/// The algorithm comes from `env.alg`, and must match the pinned key's type:
/// a server that signs under a different suite than the key the device trusts
/// is rejected rather than silently accepted.
///
/// Returns the canonical payload bytes on success so the caller can
/// `serde_json::from_slice` them into the expected type.
pub fn verify(env: &SignedEnvelope, pub_key: &PublicKey) -> crate::Result<Vec<u8>> {
    let alg_suite = Suite::for_sign_alg(&env.alg)?;
    if alg_suite != pub_key.suite() {
        return Err(format!(
            "envelope is signed with {:?} but the trusted server key is for the {} suite \
             (does the server profile's crypto suite match this agent's --crypto-suite?)",
            env.alg,
            pub_key.suite()
        )
        .into());
    }
    let payload = STANDARD.decode(&env.payload)?;
    let sig_bytes = STANDARD.decode(&env.signature)?;
    match (env.alg.as_str(), pub_key) {
        (ALG_ED25519, PublicKey::Ed25519(k)) => {
            let sig_arr: [u8; 64] = sig_bytes
                .as_slice()
                .try_into()
                .map_err(|_| "signature must be 64 bytes")?;
            let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
            k.verify(&payload, &sig)
                .map_err(|e| -> crate::Error { format!("invalid signature: {e}").into() })?;
        }
        (ALG_ECDSA_P256, PublicKey::P256(k)) => {
            if sig_bytes.len() != 64 {
                return Err(format!(
                    "expected a 64-byte raw P-256 signature, got {} bytes",
                    sig_bytes.len()
                )
                .into());
            }
            let sig = p256::ecdsa::Signature::from_slice(&sig_bytes)
                .map_err(|e| format!("invalid signature: {e}"))?;
            p256::ecdsa::signature::Verifier::verify(k, &payload, &sig)
                .map_err(|e| -> crate::Error { format!("invalid signature: {e}").into() })?;
        }
        _ => unreachable!("alg/key suite checked above"),
    }
    Ok(payload)
}

/// Decode the payload from `env` **without** verifying the signature.
///
/// Only for TOFU / BLE mode where the server pubkey is not yet known.
/// Logs a warning so the caller is reminded that trust is not established.
pub fn decode_payload_unverified(env: &SignedEnvelope) -> crate::Result<Vec<u8>> {
    log::warn!(
        "bundle signature NOT verified (TOFU mode — no --server-pubkey provided). \
         Use --server-pubkey to pin the server's key after first enrollment."
    );
    Ok(STANDARD.decode(&env.payload)?)
}

/// Generate a 16-byte random nonce and return it base64-encoded (standard).
pub fn new_nonce() -> String {
    let mut b = [0u8; 16];
    use rand::RngCore;
    OsRng.fill_bytes(&mut b);
    STANDARD.encode(b)
}

/// Encode a public key as standard base64 (wire format).
pub fn encode_public_key(key: &PublicKey) -> String {
    STANDARD.encode(key.to_bytes())
}

/// Decode a wire-format base64 public key; the suite is inferred from its
/// length (32 bytes → Ed25519, 65 bytes → uncompressed P-256).
pub fn decode_public_key(s: &str) -> crate::Result<PublicKey> {
    PublicKey::from_bytes(&STANDARD.decode(s.trim())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_key() -> PrivateKey {
        let seed: [u8; 32] = (1u8..=32).collect::<Vec<_>>().try_into().unwrap();
        ed25519_dalek::SigningKey::from_bytes(&seed).into()
    }

    #[test]
    fn sign_verify_roundtrip() {
        for key in [test_key(), PrivateKey::generate(Suite::P256)] {
            let pub_key = key.public_key();
            let payload = json!({"b": "val", "a": 42});
            let env = sign(&payload, &key, "device").unwrap();
            assert_eq!(env.alg, key.suite().sign_alg());
            let raw = verify(&env, &pub_key).unwrap();
            let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(v["a"], json!(42));
        }
    }

    #[test]
    fn tampered_payload_rejected() {
        for key in [test_key(), PrivateKey::generate(Suite::P256)] {
            let pub_key = key.public_key();
            let mut env = sign(&json!({"x": 1}), &key, "k").unwrap();
            // Replace payload with a different value's canonical bytes
            let tampered = canonical::canonicalize(&json!({"x": 2})).unwrap();
            env.payload = STANDARD.encode(&tampered);
            assert!(verify(&env, &pub_key).is_err());
        }
    }

    #[test]
    fn suite_mismatch_rejected() {
        let p256_key = PrivateKey::generate(Suite::P256);
        let env = sign(&json!({"x": 1}), &p256_key, "k").unwrap();
        let err = verify(&env, &test_key().public_key()).unwrap_err();
        assert!(err.to_string().contains("ecdsa-p256-sha256"), "{err}");
    }

    #[test]
    fn public_key_wire_roundtrip() {
        for key in [test_key(), PrivateKey::generate(Suite::P256)] {
            let pub_key = key.public_key();
            let b64 = encode_public_key(&pub_key);
            assert_eq!(decode_public_key(&b64).unwrap(), pub_key);
        }
        assert_eq!(PrivateKey::generate(Suite::P256).public_key().to_bytes().len(), 65);
    }
}
