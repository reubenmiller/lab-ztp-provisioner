//! Wire-protocol types — mirrors pkg/protocol/wire.go exactly.
//!
//! All field names and JSON tags match Go 1:1. `omitempty` in Go →
//! `#[serde(skip_serializing_if = "...")]` here. Timestamps are RFC3339 UTC
//! via the `time` crate's well-known Rfc3339 format.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::encrypt::{EncryptedPayload, SealedPayload};
use crate::sign::SignedEnvelope;

pub const VERSION: &str = "1";

/// Module types the Rust agent declares support for. v1 (JSON) module
/// types were removed from the server; only v2 (INI) remains. Older
/// agents whose appliers still parse JSON must be upgraded — the
/// dispatcher silently skips unknown module types so the agent won't
/// crash, but it also won't apply anything.
pub const CAPABILITIES: &[&str] = &[
    "wifi.v2",
    "ssh.authorized_keys.v2",
    "c8y.v2",
    "files.v2",
    "hook.v2",
    "passwd.v2",
];

// ---- EnrollRequest ----------------------------------------------------------

/// Sent by the device to request a provisioning bundle.
/// Signed with the device's long-lived Ed25519 identity key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollRequest {
    pub protocol_version: String,
    pub nonce: String, // base64(random 16 bytes)

    #[serde(with = "rfc3339_z")]
    pub timestamp: DateTime<Utc>,

    pub device_id: String,
    pub public_key: String, // base64(Ed25519 pub, 32 bytes)

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_x25519: Option<String>, // base64(X25519 pub, 32 bytes)

    #[serde(skip_serializing_if = "is_false")]
    pub encrypt_bundle: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_token: Option<String>,

    pub facts: DeviceFacts,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<std::collections::HashMap<String, String>>,
}

/// Device identity facts included in every enroll request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DeviceFacts {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub machine_id: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub mac_addresses: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub serial: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
}

// ---- EnrollResponse ---------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EnrollStatus {
    Accepted,
    Pending,
    Rejected,
}

/// Server's reply to an enroll request.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub protocol_version: String,
    pub status: EnrollStatus,

    #[serde(default)]
    pub reason: Option<String>,

    #[serde(default)]
    pub retry_after: Option<u32>, // seconds

    #[serde(default)]
    pub bundle: Option<SignedEnvelope>,

    #[serde(default)]
    pub encrypted_bundle: Option<EncryptedPayload>,

    /// Server's UTC clock at response time. Devices whose clocks are not yet
    /// synced can compute a correction offset from this field and retry.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_rfc3339_z")]
    pub server_time: Option<DateTime<Utc>>,
}

// ---- ProvisioningBundle -----------------------------------------------------

/// The configuration delivered to a device after enrolment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisioningBundle {
    pub protocol_version: String,
    pub device_id: String,

    #[serde(with = "rfc3339_z")]
    pub issued_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_rfc3339_z")]
    pub expires_at: Option<DateTime<Utc>>,

    pub modules: Vec<Module>,
}

/// A single configuration module inside a bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Module {
    #[serde(rename = "type")]
    pub module_type: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Map<String, serde_json::Value>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub sealed: Option<SealedPayload>,

    /// `[]byte` in Go → base64 string on the wire.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_optional_base64",
        deserialize_with = "deserialize_optional_base64"
    )]
    pub raw_payload: Option<Vec<u8>>,
}

// ---- Acknowledgement ---------------------------------------------------------

/// Sent by the device after applying a bundle (optional in current protocol).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Acknowledgement {
    pub protocol_version: String,
    pub device_id: String,

    #[serde(with = "rfc3339_z")]
    pub bundle_issued_at: DateTime<Utc>,

    pub results: Vec<ModuleResult>,
}

/// Per-module outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleResult {
    #[serde(rename = "type")]
    pub module_type: String,
    pub ok: bool,

    #[serde(skip_serializing_if = "is_false")]
    pub skipped: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
}

// ---- serde helpers ----------------------------------------------------------

fn is_false(b: &bool) -> bool {
    !b
}

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Serialize/deserialize DateTime<Utc> as RFC3339 with 'Z' suffix, seconds precision.
/// Matches Go's time.MarshalJSON format for timestamps without nanoseconds.
mod rfc3339_z {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(dt: &DateTime<Utc>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Secs, true))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DateTime<Utc>, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<DateTime<Utc>>().map_err(serde::de::Error::custom)
    }

    use serde::Deserialize;
}

mod opt_rfc3339_z {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(dt: &Option<DateTime<Utc>>, s: S) -> Result<S::Ok, S::Error> {
        match dt {
            Some(dt) => s.serialize_str(&dt.to_rfc3339_opts(SecondsFormat::Secs, true)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Option<DateTime<Utc>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => s
                .parse::<DateTime<Utc>>()
                .map(Some)
                .map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}
use serde::{Deserializer, Serializer};

fn serialize_optional_base64<S: Serializer>(
    v: &Option<Vec<u8>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match v {
        Some(bytes) => s.serialize_str(&STANDARD.encode(bytes)),
        None => s.serialize_none(),
    }
}

fn deserialize_optional_base64<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<u8>>, D::Error> {
    let opt: Option<String> = Option::deserialize(d)?;
    match opt {
        Some(s) => STANDARD.decode(&s).map(Some).map_err(serde::de::Error::custom),
        None => Ok(None),
    }
}
