//! Crypto suites — mirrors pkg/protocol/suite.go.
//!
//! A suite names a coherent set of algorithms. The server selects one per
//! profile; the agent picks the one its identity key was created for, signs its
//! EnrollRequest with it and publishes the matching ephemeral key-agreement key.
//! Inbound envelopes and sealed payloads always carry their own `alg`, so the
//! agent decides how to verify/decrypt from the message, never from config.

use std::fmt;
use std::str::FromStr;

/// `SignedEnvelope.alg` for Ed25519.
pub const ALG_ED25519: &str = "ed25519";
/// `SignedEnvelope.alg` for ECDSA P-256 / SHA-256 (raw `r‖s` signatures).
pub const ALG_ECDSA_P256: &str = "ecdsa-p256-sha256";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Suite {
    /// The original suite and the default: Ed25519 signatures, X25519 sealing.
    #[default]
    Ed25519X25519,
    /// NIST P-256 for both signatures and key agreement (HKDF-SHA256 derived
    /// ChaCha20-Poly1305 key). Selected per profile on the server.
    P256,
}

impl Suite {
    pub fn as_str(&self) -> &'static str {
        match self {
            Suite::Ed25519X25519 => "ed25519-x25519",
            Suite::P256 => "p256",
        }
    }

    /// Identifier this suite puts in `SignedEnvelope.alg`.
    pub fn sign_alg(&self) -> &'static str {
        match self {
            Suite::Ed25519X25519 => ALG_ED25519,
            Suite::P256 => ALG_ECDSA_P256,
        }
    }

    /// Identifier this suite puts in `SealedPayload.alg` / `EncryptedPayload.alg`.
    pub fn seal_alg(&self) -> &'static str {
        match self {
            Suite::Ed25519X25519 => crate::encrypt::ALG,
            Suite::P256 => crate::encrypt::ALG_P256,
        }
    }

    /// Maps an envelope's `alg` back to its suite.
    pub fn for_sign_alg(alg: &str) -> crate::Result<Suite> {
        match alg {
            ALG_ED25519 => Ok(Suite::Ed25519X25519),
            ALG_ECDSA_P256 => Ok(Suite::P256),
            other => Err(format!("unsupported alg {other:?}").into()),
        }
    }
}

impl fmt::Display for Suite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Suite {
    type Err = String;

    /// The empty string selects the default, so an unset option means "unchanged".
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "" | "ed25519-x25519" => Ok(Suite::Ed25519X25519),
            "p256" => Ok(Suite::P256),
            other => Err(format!(
                "unknown crypto suite {other:?} (want \"ed25519-x25519\" or \"p256\")"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        assert_eq!("".parse::<Suite>().unwrap(), Suite::Ed25519X25519);
        assert_eq!("ed25519-x25519".parse::<Suite>().unwrap(), Suite::Ed25519X25519);
        assert_eq!("p256".parse::<Suite>().unwrap(), Suite::P256);
        assert!("rsa".parse::<Suite>().is_err());
    }

    #[test]
    fn alg_roundtrip() {
        for s in [Suite::Ed25519X25519, Suite::P256] {
            assert_eq!(Suite::for_sign_alg(s.sign_alg()).unwrap(), s);
        }
    }
}
