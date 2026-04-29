//! Ed25519 sign / verify — matches pkg/protocol/sign.go.
//!
//! Signing input = RFC 8785 canonical JSON bytes of the payload struct.
//! The signature covers exactly those bytes (no additional framing).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::canonical;

/// Wire-format signed envelope (matches protocol.SignedEnvelope in wire.go).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedEnvelope {
    pub protocol_version: String,
    pub key_id: String,
    pub alg: String,   // "ed25519"
    pub payload: String,   // base64(canonical JSON)
    pub signature: String, // base64(ed25519 signature)
}

/// Sign `value` with `key`, returning a [`SignedEnvelope`].
///
/// `key_id` is an opaque label for the signer, e.g. `"device"` or `"server"`.
pub fn sign<T: Serialize>(value: &T, key: &SigningKey, key_id: &str) -> crate::Result<SignedEnvelope> {
    let canon = canonical::canonicalize(value)?;
    let sig = key.sign(&canon);
    Ok(SignedEnvelope {
        protocol_version: crate::wire::VERSION.to_string(),
        key_id: key_id.to_string(),
        alg: "ed25519".to_string(),
        payload: STANDARD.encode(&canon),
        signature: STANDARD.encode(sig.to_bytes()),
    })
}

/// Verify the signature on `env` using `pub_key`.
///
/// Returns the canonical payload bytes on success so the caller can
/// `serde_json::from_slice` them into the expected type.
pub fn verify(env: &SignedEnvelope, pub_key: &VerifyingKey) -> crate::Result<Vec<u8>> {
    if env.alg != "ed25519" {
        return Err(format!("unsupported alg {:?}", env.alg).into());
    }
    let payload = STANDARD.decode(&env.payload)?;
    let sig_bytes = STANDARD.decode(&env.signature)?;
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "signature must be 64 bytes")?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
    pub_key
        .verify(&payload, &sig)
        .map_err(|e| -> crate::Error { format!("invalid signature: {e}").into() })?;
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

/// Encode an Ed25519 public key as standard base64 (wire format).
pub fn encode_public_key(key: &VerifyingKey) -> String {
    STANDARD.encode(key.as_bytes())
}

/// Decode a wire-format base64 Ed25519 public key.
pub fn decode_public_key(s: &str) -> crate::Result<VerifyingKey> {
    let bytes = STANDARD.decode(s)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes")?;
    VerifyingKey::from_bytes(&arr).map_err(|e| e.to_string().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_key() -> SigningKey {
        let seed: [u8; 32] = (1u8..=32).collect::<Vec<_>>().try_into().unwrap();
        SigningKey::from_bytes(&seed)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let key = test_key();
        let pub_key = key.verifying_key();
        let payload = json!({"b": "val", "a": 42});
        let env = sign(&payload, &key, "device").unwrap();
        let raw = verify(&env, &pub_key).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["a"], json!(42));
    }

    #[test]
    fn tampered_payload_rejected() {
        let key = test_key();
        let pub_key = key.verifying_key();
        let mut env = sign(&json!({"x": 1}), &key, "k").unwrap();
        // Replace payload with a different value's canonical bytes
        let tampered = canonical::canonicalize(&json!({"x": 2})).unwrap();
        env.payload = STANDARD.encode(&tampered);
        assert!(verify(&env, &pub_key).is_err());
    }
}
