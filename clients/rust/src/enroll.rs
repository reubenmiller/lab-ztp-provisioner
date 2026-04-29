//! Core enrollment loop — mirrors internal/agent/run.go.
//!
//! Behaviour:
//!  1. Build a fresh ephemeral X25519 keypair per attempt.
//!  2. Sign an EnrollRequest with the device's identity key.
//!  3. POST to /v1/enroll.
//!  4. Handle status:
//!     - rejected → fatal error
//!     - pending  → sleep (retry_after hint or cfg.pending_poll), retry
//!     - accepted → verify bundle signature, unseal modules, dispatch appliers

use base64::{engine::general_purpose::STANDARD, Engine as _};
use std::path::PathBuf;
use std::time::Duration;

use crate::appliers::Dispatcher;
use crate::encrypt;
use crate::identity::Identity;
use crate::sign;
use crate::transport;
use crate::wire::{
    EnrollRequest, EnrollResponse, EnrollStatus, ProvisioningBundle, VERSION,
    CAPABILITIES,
};

// ── Typed errors ──────────────────────────────────────────────────────────────

/// Returned when the server is unreachable after `MaxNetworkFailures` consecutive
/// network-level errors. The outer multi-transport dispatcher treats this as a
/// signal to try the next transport (e.g. BLE) rather than aborting entirely.
#[derive(Debug)]
pub struct ServerUnreachableError {
    pub attempts: u32,
    pub message: String,
}

impl std::fmt::Display for ServerUnreachableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ServerUnreachableError {}

/// Returned when the server definitively rejects enrollment. Terminal — the
/// caller must NOT fall back to another transport; operator intervention required.
#[derive(Debug)]
pub struct EnrollRejectedError {
    pub reason: String,
}

impl std::fmt::Display for EnrollRejectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.reason.is_empty() {
            write!(f, "server rejected enrollment")
        } else {
            write!(f, "server rejected enrollment: {}", self.reason)
        }
    }
}
impl std::error::Error for EnrollRejectedError {}

// ── Config ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Config {
    pub server_url: String,
    pub device_id: String, // if empty, derived from /etc/machine-id or hostname
    pub bootstrap_token: Option<String>,
    /// Optional advisory profile-name hint sent in `EnrollRequest.metadata`.
    /// The server treats it as a hint only — any operator-side binding
    /// (allowlist/token, sticky persisted name, override, fact-based
    /// selector) wins over it. `None` or empty = no hint sent.
    pub profile: Option<String>,
    /// Server signing public key (32 raw Ed25519 bytes).
    /// `None` means TOFU mode — bundle signature verification is skipped.
    pub server_pub_key: Option<[u8; 32]>,
    pub ca_file: Option<PathBuf>,
    pub insecure: bool,
    pub identity: Identity,
    pub dispatcher: Dispatcher,
    pub agent_version: String,
    pub encrypt: bool,
    /// How long to wait between retries when the server says "pending".
    /// Default: 10 s.
    pub pending_poll: Duration,
    /// Cap on total enrollment attempts; 0 = unlimited.
    pub max_attempts: u32,
    /// Cap on consecutive network-level errors before returning
    /// ServerUnreachableError. 0 = unlimited (preserves existing behaviour).
    pub max_network_failures: u32,
    /// Debug bundle-dump mode (mirrors ZTP_DEBUG env var behaviour).
    /// ""              → disabled
    /// "1"/"true"/etc. → dump then apply
    /// "only"/"dump"   → dump then exit without applying
    pub debug: String,
    /// TCP dial override: raw `ip:port` for the ZTP server, obtained from
    /// mDNS discovery.  When set, the ureq agent connects directly to this
    /// address instead of resolving the hostname, which is needed on Linux
    /// without nss-mdns where `.local` names don't resolve via system DNS.
    pub dial_addr: Option<String>,
    /// Offset added to the local clock when building EnrollRequest timestamps.
    /// Set automatically when the server returns a `server_time` in a rejection
    /// response, allowing devices with unsynced clocks to self-correct and retry.
    /// Can also be set externally (e.g. by the BLE time-sync path).
    pub clock_offset: chrono::Duration,
    /// Prefix prepended to the device id in the BLE advertising name.
    /// When empty, defaults to "ztp-", giving names like "ztp-<device-id>".
    /// Set to a custom value (e.g. "acme-") to brand the peripheral name.
    pub ble_name_prefix: String,
    /// Controls whether the agent writes the system real-time clock from the
    /// verified bundle's `issued_at` before dispatching appliers. Default
    /// (`Auto`) advances the clock when it is more than 60 s behind so that
    /// downstream TLS NotBefore checks (e.g. `tedge cert download c8y`)
    /// succeed on devices that boot before any time-sync mechanism is
    /// available.
    pub system_clock_policy: crate::clock::Policy,
    /// Minimum |target - now| at which `system_clock_policy` will act. Zero
    /// means use `clock::DEFAULT_THRESHOLD` (60 s).
    pub system_clock_threshold: chrono::Duration,
}

/// Run the enroll → apply loop until success or fatal error.
pub fn run(mut cfg: Config) -> crate::Result<()> {
    let agent = transport::build_agent(cfg.ca_file.as_deref(), cfg.insecure, cfg.dial_addr.as_deref())?;

    let server_pub: Option<ed25519_dalek::VerifyingKey> = cfg.server_pub_key
        .as_ref()
        .map(|k| sign::decode_public_key(&STANDARD.encode(k)))
        .transpose()?;

    let device_id = resolve_device_id(&cfg.device_id)?;
    log::info!("enrolling device device_id={device_id}");

    let pending_poll = if cfg.pending_poll.is_zero() {
        Duration::from_secs(10)
    } else {
        cfg.pending_poll
    };

    let mut attempts = 0u32;
    let mut net_failures = 0u32;
    let mut clock_adjusted = false;
    loop {
        attempts += 1;
        if cfg.max_attempts > 0 && attempts > cfg.max_attempts {
            return Err(format!("exceeded max attempts ({})", cfg.max_attempts).into());
        }

        // Fresh ephemeral X25519 keypair per attempt to maintain forward
        // secrecy: a captured ciphertext is tied to this one-shot key.
        let (eph_priv, eph_pub) = encrypt::generate_x25519()?;
        let eph_pub_b64 = STANDARD.encode(eph_pub);

        let req = build_request(&device_id, &cfg, &eph_pub_b64);
        let env = sign::sign(&req, cfg.identity.signing_key(), "device")?;

        let resp = match transport::post_enroll(&agent, &cfg.server_url, &env) {
            Ok(r) => r,
            Err(e) => {
                net_failures += 1;
                log::warn!("enroll request failed: {e} consecutive_failures={net_failures}");
                if cfg.max_network_failures > 0 && net_failures >= cfg.max_network_failures {
                    return Err(Box::new(ServerUnreachableError {
                        attempts: net_failures,
                        message: format!(
                            "server unreachable after {net_failures} consecutive network failures"
                        ),
                    }));
                }
                sleep_interruptible(pending_poll)?;
                continue;
            }
        };
        net_failures = 0; // reset on any successful HTTP response

        // Keep our clock offset in sync with the server on every response.
        if let Some(server_time) = resp.server_time {
            cfg.clock_offset = server_time.signed_duration_since(chrono::Utc::now());
        }

        match resp.status {
            EnrollStatus::Rejected => {
                // If the rejection is a clock-skew error and we haven't yet
                // self-corrected, adjust the offset (set above from server_time)
                // and retry once immediately with a fresh timestamp.
                let reason = resp.reason.clone().unwrap_or_default();
                if !clock_adjusted
                    && resp.server_time.is_some()
                    && reason.contains("timestamp out of allowed skew")
                {
                    log::warn!(
                        "clock skew detected, auto-correcting and retrying: \
                         offset={:?} reason={reason}",
                        cfg.clock_offset,
                    );
                    clock_adjusted = true;
                    continue;
                }
                return Err(Box::new(EnrollRejectedError { reason }));
            }
            EnrollStatus::Pending => {
                let reason = resp.reason.unwrap_or_default();
                log::info!("waiting for manual approval: {reason}");
                let delay = if let Some(secs) = resp.retry_after {
                    let hint = Duration::from_secs(secs as u64);
                    hint.min(pending_poll)
                } else {
                    pending_poll
                };
                sleep_interruptible(delay)?;
                continue;
            }
            EnrollStatus::Accepted => {
                handle_accepted(resp, &eph_priv, server_pub.as_ref(), &cfg, &device_id)?;
                return Ok(());
            }
        }
    }
}

pub(crate) fn handle_accepted(
    resp: EnrollResponse,
    eph_priv: &[u8; 32],
    server_pub: Option<&ed25519_dalek::VerifyingKey>,
    cfg: &Config,
    _device_id: &str,
) -> crate::Result<()> {
    // If the server encrypted the entire bundle, decrypt it first.
    let signed_env = if let Some(enc) = resp.encrypted_bundle {
        if !cfg.encrypt {
            return Err(
                "server returned encrypted bundle but agent did not request encryption".into(),
            );
        }
        let plain = encrypt::open_for_device(eph_priv, &enc)?;
        serde_json::from_slice(&plain)
            .map_err(|e| format!("decode encrypted envelope: {e}"))?
    } else {
        resp.bundle
            .ok_or("server returned accepted with no bundle")?
    };

    // Verify the server's signature over the bundle, or skip in TOFU mode.
    let payload_bytes = match server_pub {
        Some(key) => sign::verify(&signed_env, key)?,
        None => sign::decode_payload_unverified(&signed_env)?,
    };
    let mut bundle: ProvisioningBundle =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("decode bundle: {e}"))?;

    // The bundle's issued_at field is inside the signed payload, so it
    // carries the same trust as the rest of the bundle. Apply it to the
    // system clock now, before any applier runs, so that downstream TLS
    // validation (e.g. `tedge cert download c8y`) sees a sane wall time on
    // devices that booted with a stale clock. Errors are logged inside
    // `clock::adjust` and intentionally not propagated — a small drift that
    // could not be fixed shouldn't block provisioning entirely.
    let _ = crate::clock::adjust(
        bundle.issued_at,
        cfg.system_clock_policy,
        cfg.system_clock_threshold,
    );

    // Unseal any per-module ciphertexts addressed to our ephemeral key.
    unseal_modules(&mut bundle, eph_priv)?;

    // Debug dump.
    if !cfg.debug.is_empty() {
        debug_dump_bundle(&bundle);
        match cfg.debug.as_str() {
            "only" | "dump" | "inspect" => {
                log::info!("debug mode: skipping applier dispatch (debug={})", cfg.debug);
                return Ok(());
            }
            _ => {}
        }
    }

    let results = cfg.dispatcher.apply(&bundle);
    let mut any_fail = false;
    for r in &results {
        log::info!(
            "module applied: type={} ok={} skipped={} error={:?}",
            r.module_type,
            r.ok,
            r.skipped,
            r.error
        );
        if !r.ok && !r.skipped {
            any_fail = true;
        }
    }
    if any_fail {
        return Err("one or more modules failed to apply".into());
    }
    log::info!("provisioning complete: {} modules applied", results.len());
    Ok(())
}

/// Unseal any Module that arrived with a SealedPayload.
fn unseal_modules(bundle: &mut ProvisioningBundle, device_priv: &[u8; 32]) -> crate::Result<()> {
    for m in &mut bundle.modules {
        let sealed = match m.sealed.take() {
            Some(s) => s,
            None => continue,
        };
        let (plaintext, format) = encrypt::open_sealed_module(device_priv, &sealed)
            .map_err(|e| format!("module {}: {e}", m.module_type))?;

        match format.as_str() {
            "json" => {
                if !plaintext.is_empty() {
                    m.payload = Some(
                        serde_json::from_slice(&plaintext)
                            .map_err(|e| format!("module {}: decode sealed json: {e}", m.module_type))?,
                    );
                }
            }
            "raw" => {
                m.raw_payload = Some(plaintext);
            }
            f => {
                return Err(
                    format!("module {}: unsupported sealed format {:?}", m.module_type, f).into(),
                )
            }
        }
    }
    Ok(())
}

pub(crate) fn build_request(device_id: &str, cfg: &Config, eph_pub_b64: &str) -> EnrollRequest {
    let metadata = cfg.profile.as_ref().filter(|s| !s.is_empty()).map(|p| {
        let mut m = std::collections::HashMap::new();
        m.insert("profile".to_string(), p.clone());
        m
    });
    EnrollRequest {
        protocol_version: VERSION.to_string(),
        nonce: sign::new_nonce(),
        timestamp: chrono::Utc::now() + cfg.clock_offset,
        device_id: device_id.to_string(),
        public_key: sign::encode_public_key(&cfg.identity.verifying_key()),
        ephemeral_x25519: Some(eph_pub_b64.to_string()),
        encrypt_bundle: cfg.encrypt,
        bootstrap_token: cfg.bootstrap_token.clone(),
        facts: crate::facts::collect(&cfg.agent_version),
        capabilities: CAPABILITIES.iter().map(|s| s.to_string()).collect(),
        metadata,
    }
}

pub(crate) fn resolve_device_id(configured: &str) -> crate::Result<String> {
    if !configured.is_empty() {
        return Ok(configured.to_string());
    }
    for path in &["/etc/device-id", "/var/lib/ztp/device-id"] {
        if let Ok(s) = std::fs::read_to_string(path) {
            let s = s.trim().to_string();
            if !s.is_empty() {
                return Ok(s);
            }
        }
    }
    if let Ok(out) = std::process::Command::new("tedge-identity").output() {
        if out.status.success() {
            let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !s.is_empty() {
                return Ok(s);
            }
        }
    }
    Err("could not determine device ID: set --device-id, create /etc/device-id, or install tedge-identity".into())
}

fn sleep_interruptible(d: Duration) -> crate::Result<()> {
    // On Unix we could handle SIGINT here; for now just sleep.
    std::thread::sleep(d);
    Ok(())
}

fn debug_dump_bundle(bundle: &ProvisioningBundle) {
    eprintln!(
        "=== provisioning bundle ({} modules, device={}) ===",
        bundle.modules.len(),
        bundle.device_id
    );
    for (i, m) in bundle.modules.iter().enumerate() {
        eprintln!("--- module[{i}]: {} ---", m.module_type);
        if let Some(raw) = &m.raw_payload {
            eprintln!("{}", String::from_utf8_lossy(raw));
        } else if let Some(payload) = &m.payload {
            match serde_json::to_string_pretty(payload) {
                Ok(s) => eprintln!("  {s}"),
                Err(e) => eprintln!("  (marshal error: {e})"),
            }
        } else {
            eprintln!("  (empty payload)");
        }
    }
}

#[cfg(test)]
mod system_clock_tests {
    //! End-to-end tests for the post-verify system-clock adjustment.
    //!
    //! These live inside the crate so they can call the `pub(crate)`
    //! `handle_accepted` directly. They install a recording setter via
    //! `clock::set_clock_fn_for_test` so the host clock is never touched.

    use super::*;
    use chrono::{DateTime, Utc};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
    use std::sync::{Mutex, OnceLock};

    use crate::{appliers, clock, encrypt, identity, sign, wire};

    static CALLS: OnceLock<Mutex<Vec<DateTime<Utc>>>> = OnceLock::new();

    fn calls() -> &'static Mutex<Vec<DateTime<Utc>>> {
        CALLS.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn record(t: DateTime<Utc>) -> Result<(), String> {
        calls().lock().unwrap().push(t);
        Ok(())
    }

    /// Runs `f` with the recording setter installed; serialises tests because
    /// the setter slot is global. Resets the recording before each test.
    /// Poison-resistant: a panic in one test mustn't break the others.
    fn with_recorder<F: FnOnce()>(f: F) {
        static GUARD: OnceLock<Mutex<()>> = OnceLock::new();
        let mu = GUARD.get_or_init(|| Mutex::new(()));
        let _g = mu.lock().unwrap_or_else(|p| p.into_inner());
        {
            let mut c = calls().lock().unwrap_or_else(|p| p.into_inner());
            c.clear();
        }
        let prev = clock::set_clock_fn_for_test(Some(record));
        f();
        clock::set_clock_fn_for_test(prev);
    }

    /// Helper to read the recorded calls, tolerating any prior poisoning.
    fn recorded() -> Vec<DateTime<Utc>> {
        calls()
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    /// Truncate `t` to whole seconds. The wire format serialises timestamps
    /// to RFC3339 with second precision, so the bundle round-trip drops
    /// sub-second fractions and the assertion needs to use the truncated
    /// form to match what `handle_accepted` will see.
    fn trunc_secs(t: DateTime<Utc>) -> DateTime<Utc> {
        DateTime::from_timestamp(t.timestamp(), 0).unwrap()
    }

    fn make_cfg(tmp: &tempfile::TempDir, policy: clock::Policy) -> (Config, SigningKey) {
        let id_path = tmp.path().join("id.key");
        let id = identity::Identity::load_or_create(&id_path).expect("identity");
        let server_signing = SigningKey::generate(&mut OsRng);
        let server_pub: [u8; 32] = server_signing.verifying_key().to_bytes();
        let cfg = Config {
            server_url: String::new(),
            device_id: "dev-clock-test".to_string(),
            bootstrap_token: None,
            profile: None,
            server_pub_key: Some(server_pub),
            ca_file: None,
            insecure: true,
            identity: id,
            dispatcher: appliers::Dispatcher::new(tmp.path().join("appliers")),
            agent_version: "test".to_string(),
            encrypt: false,
            pending_poll: Duration::from_millis(10),
            max_attempts: 1,
            max_network_failures: 1,
            debug: String::new(),
            dial_addr: None,
            clock_offset: chrono::Duration::zero(),
            ble_name_prefix: String::new(),
            system_clock_policy: policy,
            system_clock_threshold: chrono::Duration::zero(),
        };
        (cfg, server_signing)
    }

    fn signed_bundle(
        server_signing: &SigningKey,
        device_id: &str,
        issued_at: DateTime<Utc>,
    ) -> sign::SignedEnvelope {
        let bundle = wire::ProvisioningBundle {
            protocol_version: wire::VERSION.to_string(),
            device_id: device_id.to_string(),
            issued_at,
            expires_at: None,
            modules: vec![],
        };
        sign::sign(&bundle, server_signing, "server").expect("sign bundle")
    }

    fn fresh_eph_priv() -> [u8; 32] {
        let (priv_, _) = encrypt::generate_x25519().expect("eph keypair");
        priv_
    }

    fn run_handle_accepted(cfg: &Config, signed: sign::SignedEnvelope) {
        let resp = wire::EnrollResponse {
            protocol_version: wire::VERSION.to_string(),
            status: wire::EnrollStatus::Accepted,
            reason: None,
            retry_after: None,
            bundle: Some(signed),
            encrypted_bundle: None,
            server_time: None,
        };
        let server_pub_decoded =
            ed25519_dalek::VerifyingKey::from_bytes(&cfg.server_pub_key.unwrap())
                .expect("decode server pub");
        let eph = fresh_eph_priv();
        handle_accepted(resp, &eph, Some(&server_pub_decoded), cfg, "dev-clock-test")
            .expect("handle_accepted");
    }

    #[test]
    fn auto_advances_when_far_behind() {
        with_recorder(|| {
            let tmp = tempfile::tempdir().unwrap();
            let (cfg, server_key) = make_cfg(&tmp, clock::Policy::Auto);
            let issued_at = trunc_secs(Utc::now() + chrono::Duration::hours(2));
            let signed = signed_bundle(&server_key, "dev-clock-test", issued_at);

            run_handle_accepted(&cfg, signed);

            let r = recorded();
            assert_eq!(r.len(), 1, "expected one clock-set call");
            assert_eq!(r[0], issued_at, "setter received wrong target");
        });
    }

    #[test]
    fn off_skips_clock_set() {
        with_recorder(|| {
            let tmp = tempfile::tempdir().unwrap();
            let (cfg, server_key) = make_cfg(&tmp, clock::Policy::Off);
            let issued_at = trunc_secs(Utc::now() + chrono::Duration::hours(2));
            let signed = signed_bundle(&server_key, "dev-clock-test", issued_at);

            run_handle_accepted(&cfg, signed);

            assert!(recorded().is_empty(), "PolicyOff must not call setter");
        });
    }

    #[test]
    fn auto_skips_when_within_threshold() {
        with_recorder(|| {
            let tmp = tempfile::tempdir().unwrap();
            let (cfg, server_key) = make_cfg(&tmp, clock::Policy::Auto);
            // 5 s ahead — well within the 60 s threshold.
            let issued_at = trunc_secs(Utc::now() + chrono::Duration::seconds(5));
            let signed = signed_bundle(&server_key, "dev-clock-test", issued_at);

            run_handle_accepted(&cfg, signed);

            assert!(recorded().is_empty(), "small drift must not trigger a set");
        });
    }
}
