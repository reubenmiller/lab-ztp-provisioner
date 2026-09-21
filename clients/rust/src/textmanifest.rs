//! Text-format enroll responses — mirrors pkg/protocol/enrolltext.go and
//! pkg/protocol/textmanifest.go.
//!
//! A device selects this rendering with `EnrollRequest.response_format =
//! "text"`. It exists for devices without a JSON parser (the POSIX shell
//! agent, constrained BLE devices); the Rust agent only speaks it behind a
//! hidden flag, so the text path can be exercised end to end — including over
//! a BLE relay — from a Linux box.
//!
//! Response: one `key=value` record per line (`status`, `reason`,
//! `retry_after`, `server_time`, `manifest.*`, `encrypted.*`, …). Unknown keys
//! are ignored. When the bundle is encrypted, the decrypted plaintext is the
//! `manifest.*` records.
//!
//! Manifest (the signed payload): sorted lines of
//! `device_id=`, `issued_at=`, `expires_at=`, `protocol_version=`,
//! `module=<type> <base64 payload>` and
//! `module-sealed=<type> <format> <ephemeral_pub> <nonce> <ciphertext>`.

use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};

use crate::encrypt::{EncryptedPayload, SealedPayload};
use crate::sign::SignedEnvelope;
use crate::suite::Suite;
use crate::wire::{EnrollResponse, EnrollStatus, Module, ProvisioningBundle, VERSION};

/// Decode an enroll response body in either rendering. JSON is recognised by
/// its leading `{`; anything else is read as text.
pub fn decode_enroll_response(body: &[u8]) -> crate::Result<EnrollResponse> {
    let trimmed = body.trim_ascii();
    if trimmed.first() == Some(&b'{') {
        return serde_json::from_slice(trimmed).map_err(|e| format!("decode enroll response: {e}").into());
    }
    let text = std::str::from_utf8(trimmed).map_err(|e| format!("decode enroll response: {e}"))?;
    enroll_response_from_text(text)
}

/// Parse the text rendering of an EnrollResponse.
pub fn enroll_response_from_text(text: &str) -> crate::Result<EnrollResponse> {
    let kv = parse_kv(text);
    let status = match kv.get("status").map(String::as_str) {
        Some("accepted") => EnrollStatus::Accepted,
        Some("pending") => EnrollStatus::Pending,
        Some("rejected") => EnrollStatus::Rejected,
        Some(other) => return Err(format!("decode enroll response: unknown status {other:?}").into()),
        None => {
            let snippet: String = text.chars().take(120).collect();
            return Err(format!("decode enroll response: no status record in {snippet:?}").into());
        }
    };
    let encrypted_bundle = match (
        kv.get("encrypted.alg"),
        kv.get("encrypted.server_key"),
        kv.get("encrypted.nonce"),
        kv.get("encrypted.ciphertext"),
    ) {
        (Some(alg), Some(server_key), Some(nonce), Some(ciphertext)) => Some(EncryptedPayload {
            alg: alg.clone(),
            server_key: server_key.clone(),
            nonce: nonce.clone(),
            ciphertext: ciphertext.clone(),
        }),
        _ => None,
    };
    Ok(EnrollResponse {
        protocol_version: kv.get("protocol_version").cloned().unwrap_or_else(|| VERSION.to_string()),
        status,
        reason: kv.get("reason").cloned(),
        retry_after: kv.get("retry_after").and_then(|v| v.parse().ok()),
        bundle: envelope_from_kv(&kv, "bundle"),
        encrypted_bundle,
        server_time: kv.get("server_time").and_then(|v| v.parse::<DateTime<Utc>>().ok()),
        text_manifest: envelope_from_kv(&kv, "manifest"),
    })
}

/// Parse `manifest.*` records — the plaintext of an encrypted text bundle.
pub fn manifest_envelope_from_text(text: &str) -> crate::Result<SignedEnvelope> {
    envelope_from_kv(&parse_kv(text), "manifest").ok_or_else(|| "decrypted bundle has no manifest.* records".into())
}

/// Parse a verified manifest payload into a bundle.
///
/// `module=` lines become `raw_payload` modules: their bytes are exactly what
/// the applier receives on stdin (canonical JSON or the module's own bytes),
/// so re-parsing them would gain nothing. `module-sealed=` lines carry no
/// algorithm; they are sealed under the suite of the device's ephemeral key,
/// which the caller passes as `suite`.
pub fn parse_manifest(body: &[u8], suite: Suite) -> crate::Result<ProvisioningBundle> {
    let text = std::str::from_utf8(body).map_err(|e| format!("manifest: {e}"))?;
    let mut device_id = None;
    let mut issued_at = None;
    let mut expires_at = None;
    let mut protocol_version = None;
    let mut modules = Vec::new();

    for line in text.split('\n') {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k {
            "device_id" => device_id = Some(unescape(v)),
            "protocol_version" => protocol_version = Some(unescape(v)),
            "issued_at" => issued_at = Some(parse_time(v, "issued_at")?),
            "expires_at" => expires_at = Some(parse_time(v, "expires_at")?),
            "module" => {
                let (module_type, b64) = v
                    .split_once(' ')
                    .ok_or_else(|| format!("manifest: malformed module line {v:?}"))?;
                let raw = STANDARD
                    .decode(b64)
                    .map_err(|e| format!("manifest: module {module_type}: {e}"))?;
                modules.push(Module {
                    module_type: module_type.to_string(),
                    payload: None,
                    sealed: None,
                    raw_payload: Some(raw),
                });
            }
            "module-sealed" => {
                let f: Vec<&str> = v.split(' ').collect();
                let [module_type, format, ephemeral_pub, nonce, ciphertext] = f[..] else {
                    return Err(format!("manifest: malformed module-sealed line {v:?}").into());
                };
                modules.push(Module {
                    module_type: module_type.to_string(),
                    payload: None,
                    sealed: Some(SealedPayload {
                        alg: suite.seal_alg().to_string(),
                        ephemeral_pub: ephemeral_pub.to_string(),
                        nonce: nonce.to_string(),
                        ciphertext: ciphertext.to_string(),
                        format: format.to_string(),
                    }),
                    raw_payload: None,
                });
            }
            _ => {} // forward compatible: ignore unknown records
        }
    }

    Ok(ProvisioningBundle {
        protocol_version: protocol_version.ok_or("manifest: missing protocol_version")?,
        device_id: device_id.ok_or("manifest: missing device_id")?,
        issued_at: issued_at.ok_or("manifest: missing issued_at")?,
        expires_at,
        modules,
    })
}

fn parse_kv(text: &str) -> HashMap<String, String> {
    text.split('\n')
        .filter_map(|line| line.trim_end_matches('\r').split_once('='))
        .map(|(k, v)| (k.to_string(), unescape(v)))
        .collect()
}

fn envelope_from_kv(kv: &HashMap<String, String>, prefix: &str) -> Option<SignedEnvelope> {
    let get = |field: &str| kv.get(&format!("{prefix}.{field}")).cloned();
    Some(SignedEnvelope {
        protocol_version: VERSION.to_string(),
        key_id: get("key_id").unwrap_or_default(),
        alg: get("alg")?,
        payload: get("payload")?,
        signature: get("signature")?,
    })
}

fn parse_time(v: &str, field: &str) -> crate::Result<DateTime<Utc>> {
    v.parse::<DateTime<Utc>>()
        .map_err(|e| format!("manifest: {field} {v:?}: {e}").into())
}

/// Reverse the CR/LF escaping the server applies to record values.
fn unescape(v: &str) -> String {
    v.replace("\\n", "\n").replace("\\r", "\r")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_text_response() {
        let r = decode_enroll_response(
            b"protocol_version=1\nstatus=pending\nreason=awaiting\\napproval\nretry_after=30\nserver_time=2026-01-02T03:04:05Z\n",
        )
        .unwrap();
        assert!(matches!(r.status, EnrollStatus::Pending));
        assert_eq!(r.reason.as_deref(), Some("awaiting\napproval"));
        assert_eq!(r.retry_after, Some(30));
        assert_eq!(r.server_time.unwrap().to_rfc3339(), "2026-01-02T03:04:05+00:00");
        assert!(r.text_manifest.is_none() && r.encrypted_bundle.is_none());
    }

    #[test]
    fn json_still_decodes() {
        let r = decode_enroll_response(br#" {"protocol_version":"1","status":"rejected","reason":"no"}"#).unwrap();
        assert!(matches!(r.status, EnrollStatus::Rejected));
        assert_eq!(r.reason.as_deref(), Some("no"));
    }

    #[test]
    fn non_protocol_body_is_an_error() {
        assert!(decode_enroll_response(b"<html>502 Bad Gateway</html>").is_err());
    }

    #[test]
    fn manifest_and_encrypted_records() {
        let r = decode_enroll_response(
            b"status=accepted\r\nmanifest.alg=ecdsa-p256-sha256\r\nmanifest.key_id=k\r\n\
              manifest.payload=cA==\r\nmanifest.signature=cw==\r\n",
        )
        .unwrap();
        let m = r.text_manifest.unwrap();
        assert_eq!((m.alg.as_str(), m.payload.as_str(), m.signature.as_str()), ("ecdsa-p256-sha256", "cA==", "cw=="));

        let env = manifest_envelope_from_text("manifest.alg=ed25519\nmanifest.key_id=k\nmanifest.payload=cA==\nmanifest.signature=cw==").unwrap();
        assert_eq!(env.alg, "ed25519");
        assert!(manifest_envelope_from_text("status=accepted").is_err());
    }

    #[test]
    fn manifest_body() {
        let body = format!(
            "device_id=dev\nexpires_at=2026-01-02T04:04:05Z\nissued_at=2026-01-02T03:04:05Z\n\
             module-sealed=wifi.v2 raw EPH NONCE CT\nmodule=ssh.authorized_keys.v2 {}\nprotocol_version=1\nfuture=ignored",
            STANDARD.encode(b"[ssh]\nkey=abc\n")
        );
        let b = parse_manifest(body.as_bytes(), Suite::P256).unwrap();
        assert_eq!(b.device_id, "dev");
        assert!(b.expires_at.is_some());
        assert_eq!(b.modules.len(), 2);
        let sealed = b.modules[0].sealed.as_ref().unwrap();
        assert_eq!(
            (b.modules[0].module_type.as_str(), sealed.alg.as_str(), sealed.format.as_str(), sealed.ciphertext.as_str()),
            ("wifi.v2", crate::encrypt::ALG_P256, "raw", "CT")
        );
        assert_eq!(b.modules[1].raw_payload.as_deref(), Some(&b"[ssh]\nkey=abc\n"[..]));

        assert!(parse_manifest(b"device_id=dev\nprotocol_version=1", Suite::P256).is_err(), "missing issued_at");
    }
}
