//! System real-time clock adjustment from a verified provisioning bundle.
//!
//! Mirror of `internal/agent/clock` in the Go agent. The trusted target is
//! `ProvisioningBundle.issued_at`, which lives inside the Ed25519-signed
//! payload — so authenticity matches the trust the agent already places in
//! the server's signing key, regardless of whether the bundle reached the
//! device over HTTPS or via a BLE relay.
//!
//! This module deliberately is not a time-sync daemon: no slewing, no drift
//! tracking, no external time source. Its only job is to fix gross offsets
//! that would otherwise cause TLS NotBefore checks in downstream appliers
//! (e.g. `tedge cert download c8y`) to fail on devices that boot before any
//! time-sync mechanism is available.

use chrono::{DateTime, Utc};

/// Controls when the agent is allowed to write the system clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Policy {
    /// Default. Advance the clock (never reverse) when the trusted target is
    /// at least `threshold` ahead of local time. Fixes the common
    /// "device boots in 1970" problem while leaving small NTP-class drifts
    /// alone, and never moves the clock backwards.
    #[default]
    Auto,
    /// Disable system-clock adjustment entirely. Use when chronyd /
    /// systemd-timesyncd / ptp4l already manage the clock.
    Off,
    /// Adjust unconditionally — backwards as well as forwards — whenever
    /// `|target - now| > threshold`. Useful for bench testing.
    Always,
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Policy::Auto => "auto",
            Policy::Off => "off",
            Policy::Always => "always",
        })
    }
}

/// Parse a token from CLI / env / config. Empty string maps to `Auto` so
/// unset configuration gets the safe default. Unknown tokens return an error
/// rather than silently falling back.
pub fn parse_policy(s: &str) -> Result<Policy, String> {
    match s.trim().to_ascii_lowercase().as_str() {
        "" | "auto" => Ok(Policy::Auto),
        "off" | "false" | "0" | "disable" | "disabled" => Ok(Policy::Off),
        "always" | "force" => Ok(Policy::Always),
        other => Err(format!(
            "invalid system-clock policy {other:?} (expected: auto, off, always)"
        )),
    }
}

/// Minimum |target - now| difference at which a policy will act. Below this,
/// `adjust` is a no-op so small NTP-class drifts do not cause needless jumps.
pub const DEFAULT_THRESHOLD: chrono::Duration = chrono::Duration::seconds(60);

/// Outcome of evaluating a policy against (now, target). Returned by `decide`
/// so the state machine can be exercised in unit tests without touching the
/// host clock.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Target is the zero (epoch / unset) timestamp.
    SkipZero,
    /// Policy is `Off`.
    SkipPolicy,
    /// |delta| < threshold (small drift).
    SkipThreshold,
    /// Auto policy refuses to roll the clock backwards.
    SkipBackward,
    /// Auto policy advancing the clock forwards.
    Advance,
    /// Always policy setting the clock (forwards or backwards).
    Set,
}

/// Decide what `adjust` would do for (now, target, policy, threshold). Pure;
/// touches no host state.
pub fn decide(
    now: DateTime<Utc>,
    target: DateTime<Utc>,
    policy: Policy,
    threshold: chrono::Duration,
) -> Action {
    let threshold = if threshold <= chrono::Duration::zero() {
        DEFAULT_THRESHOLD
    } else {
        threshold
    };
    if target.timestamp() == 0 && target.timestamp_subsec_nanos() == 0 {
        return Action::SkipZero;
    }
    if policy == Policy::Off {
        return Action::SkipPolicy;
    }
    let delta = target.signed_duration_since(now);
    let abs = if delta < chrono::Duration::zero() { -delta } else { delta };
    if abs < threshold {
        return Action::SkipThreshold;
    }
    if policy == Policy::Auto && delta < chrono::Duration::zero() {
        return Action::SkipBackward;
    }
    if policy == Policy::Auto {
        Action::Advance
    } else {
        Action::Set
    }
}

/// Type of the platform-specific clock setter. Replaceable in tests via
/// `set_clock_fn_for_test`.
pub type SetClockFn = fn(DateTime<Utc>) -> Result<(), String>;

#[cfg(unix)]
fn default_set_clock(t: DateTime<Utc>) -> Result<(), String> {
    // settimeofday(2) — requires CAP_SYS_TIME (effectively root). Failure
    // returns errno; we surface it as a string so the caller can log a clear
    // warning and continue.
    let tv = libc::timeval {
        tv_sec: t.timestamp() as libc::time_t,
        tv_usec: (t.timestamp_subsec_nanos() / 1000) as libc::suseconds_t,
    };
    // SAFETY: tv is a fully-initialised local; we pass a null tz which is the
    // documented "ignore timezone" form on Linux/macOS/BSD.
    let rc = unsafe { libc::settimeofday(&tv as *const libc::timeval, std::ptr::null()) };
    if rc == 0 {
        Ok(())
    } else {
        let err = std::io::Error::last_os_error();
        Err(format!("settimeofday: {err}"))
    }
}

#[cfg(not(unix))]
fn default_set_clock(_t: DateTime<Utc>) -> Result<(), String> {
    Err("system clock adjustment not supported on this platform".to_string())
}

// Test seam: the integration test in `enroll.rs` substitutes a recording
// closure here so it can verify wiring without actually calling settimeofday.
// Using a `RwLock` (rather than `Mutex`) so concurrent reads are cheap; only
// the test thread takes the write lock.
use std::sync::RwLock;
static SET_CLOCK_FN: RwLock<Option<SetClockFn>> = RwLock::new(None);

/// Install a custom clock setter. Used by tests; production code never calls
/// this. Returns the previous setter so a test can restore it on teardown.
pub fn set_clock_fn_for_test(f: Option<SetClockFn>) -> Option<SetClockFn> {
    let mut guard = SET_CLOCK_FN.write().expect("clock setter lock poisoned");
    let prev = *guard;
    *guard = f;
    prev
}

fn invoke_setter(t: DateTime<Utc>) -> Result<(), String> {
    let guard = SET_CLOCK_FN.read().expect("clock setter lock poisoned");
    match *guard {
        Some(f) => f(t),
        None => default_set_clock(t),
    }
}

/// Evaluate the policy and, when appropriate, set the system clock to
/// `target`. Logs every decision via the `log` crate; returns `Err(...)`
/// only when an attempted set actually failed (e.g. CAP_SYS_TIME missing).
///
/// The error is intentionally non-fatal at the call site: a failed
/// adjustment should warn loudly but must not block applier dispatch — a
/// device with only a small drift can still complete provisioning, and a
/// noisy log is more useful than a hard failure.
pub fn adjust(
    target: DateTime<Utc>,
    policy: Policy,
    threshold: chrono::Duration,
) -> Result<(), String> {
    let now = Utc::now();
    let action = decide(now, target, policy, threshold);
    let delta = target.signed_duration_since(now);
    match action {
        Action::SkipZero | Action::SkipPolicy | Action::SkipThreshold | Action::SkipBackward => {
            log::debug!(
                "system clock: no adjustment action={action:?} now={now} target={target} delta={delta}"
            );
            Ok(())
        }
        Action::Advance | Action::Set => {
            match invoke_setter(target) {
                Ok(()) => {
                    log::info!(
                        "system clock: adjusted from verified bundle action={action:?} \
                         old={now} new={target} delta={delta}"
                    );
                    Ok(())
                }
                Err(e) => {
                    log::warn!(
                        "system clock: adjustment failed action={action:?} delta={delta} err={e}"
                    );
                    Err(format!("set system clock: {e}"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn t(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(secs, 0).unwrap()
    }

    #[test]
    fn parse_policy_table() {
        assert_eq!(parse_policy("").unwrap(), Policy::Auto);
        assert_eq!(parse_policy("auto").unwrap(), Policy::Auto);
        assert_eq!(parse_policy(" AUTO ").unwrap(), Policy::Auto);
        assert_eq!(parse_policy("off").unwrap(), Policy::Off);
        assert_eq!(parse_policy("disabled").unwrap(), Policy::Off);
        assert_eq!(parse_policy("false").unwrap(), Policy::Off);
        assert_eq!(parse_policy("always").unwrap(), Policy::Always);
        assert_eq!(parse_policy("force").unwrap(), Policy::Always);
        assert!(parse_policy("sometimes").is_err());
    }

    #[test]
    fn policy_display() {
        assert_eq!(Policy::Auto.to_string(), "auto");
        assert_eq!(Policy::Off.to_string(), "off");
        assert_eq!(Policy::Always.to_string(), "always");
    }

    #[test]
    fn decide_state_machine() {
        let now = t(1_700_000_000);
        let thr = chrono::Duration::seconds(60);
        let zero = DateTime::<Utc>::from_timestamp(0, 0).unwrap();

        assert_eq!(decide(now, zero, Policy::Auto, thr), Action::SkipZero);
        assert_eq!(
            decide(now, now + chrono::Duration::hours(1), Policy::Off, thr),
            Action::SkipPolicy
        );
        assert_eq!(
            decide(now, now + chrono::Duration::seconds(30), Policy::Auto, thr),
            Action::SkipThreshold
        );
        assert_eq!(
            decide(now, now - chrono::Duration::seconds(30), Policy::Auto, thr),
            Action::SkipThreshold
        );
        assert_eq!(
            decide(now, now - chrono::Duration::hours(2), Policy::Auto, thr),
            Action::SkipBackward
        );
        assert_eq!(
            decide(now, now + chrono::Duration::minutes(5), Policy::Auto, thr),
            Action::Advance
        );
        assert_eq!(
            decide(now, now + chrono::Duration::seconds(10), Policy::Always, thr),
            Action::SkipThreshold
        );
        assert_eq!(
            decide(now, now + chrono::Duration::minutes(5), Policy::Always, thr),
            Action::Set
        );
        assert_eq!(
            decide(now, now - chrono::Duration::minutes(5), Policy::Always, thr),
            Action::Set
        );
    }

    #[test]
    fn decide_default_threshold_when_zero() {
        let now = t(1_700_000_000);
        // 30 s forward with threshold=0 should fall back to DEFAULT_THRESHOLD
        // (60 s) and therefore skip.
        assert_eq!(
            decide(
                now,
                now + chrono::Duration::seconds(30),
                Policy::Auto,
                chrono::Duration::zero(),
            ),
            Action::SkipThreshold
        );
    }
}
