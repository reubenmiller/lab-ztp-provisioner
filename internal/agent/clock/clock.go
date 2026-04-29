// Package clock brings the system real-time clock into agreement with a
// trusted timestamp from a cryptographically verified provisioning bundle.
//
// It is deliberately not a time-sync daemon: there is no slewing, no drift
// tracking, no external time source. Its only job is to fix gross offsets
// that would otherwise cause TLS NotBefore checks in downstream appliers
// (e.g. `tedge cert download c8y`) to fail on devices that boot before any
// time-sync mechanism is available.
//
// The trusted timestamp is `ProvisioningBundle.IssuedAt`, which is inside
// the Ed25519-signed bundle payload — so authenticity matches the trust the
// agent already places in the server's signing key, regardless of whether
// the bundle reached the device over HTTP or BLE relay.
package clock

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Policy controls when the agent is allowed to write the system clock.
type Policy int

const (
	// PolicyAuto is the zero value and the recommended default. The clock is
	// advanced (never reversed) and only when the trusted target is at least
	// Threshold ahead of the current local time. Fixes the common
	// "device boots in 1970" problem while leaving small NTP-class drifts
	// alone, and never moves the clock backwards.
	PolicyAuto Policy = iota
	// PolicyOff disables system-clock adjustment entirely. Use when chronyd
	// / systemd-timesyncd / ptp4l already manage the clock and the agent
	// must not interfere.
	PolicyOff
	// PolicyAlways adjusts unconditionally — backwards as well as forwards —
	// whenever |target - now| > Threshold. Useful for bench testing.
	PolicyAlways
)

// String returns the canonical token used by ParsePolicy.
func (p Policy) String() string {
	switch p {
	case PolicyAuto:
		return "auto"
	case PolicyOff:
		return "off"
	case PolicyAlways:
		return "always"
	}
	return fmt.Sprintf("Policy(%d)", int(p))
}

// ParsePolicy parses a token from a CLI flag, config file, or env var. The
// empty string maps to PolicyAuto so unset configuration gets the safe
// default. Unknown tokens return an error rather than silently falling back.
func ParsePolicy(s string) (Policy, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return PolicyAuto, nil
	case "off", "false", "0", "disable", "disabled":
		return PolicyOff, nil
	case "always", "force":
		return PolicyAlways, nil
	}
	return PolicyAuto, fmt.Errorf("invalid system-clock policy %q (expected: auto, off, always)", s)
}

// DefaultThreshold is the minimum |target-now| difference at which the
// policy will act. Below this, Adjust is a no-op so small NTP-class drifts
// do not cause needless clock jumps.
const DefaultThreshold = 60 * time.Second

// Decision describes what Adjust would do (or did) for a given input. It
// exists so the policy can be unit-tested without touching the host clock.
type Decision struct {
	// Action is one of: "skip-zero", "skip-policy", "skip-threshold",
	// "skip-backward", "advance", "set".
	Action    string
	Reason    string
	Now       time.Time
	Target    time.Time
	Delta     time.Duration // target - now
	Threshold time.Duration
}

// Decide returns the Decision the policy would produce for (now, target,
// threshold). It does not touch the system clock.
func Decide(now, target time.Time, policy Policy, threshold time.Duration) Decision {
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	d := Decision{Now: now, Target: target, Delta: target.Sub(now), Threshold: threshold}
	if target.IsZero() {
		d.Action = "skip-zero"
		d.Reason = "target timestamp is zero"
		return d
	}
	if policy == PolicyOff {
		d.Action = "skip-policy"
		d.Reason = "system-clock policy is off"
		return d
	}
	abs := d.Delta
	if abs < 0 {
		abs = -abs
	}
	if abs < threshold {
		d.Action = "skip-threshold"
		d.Reason = fmt.Sprintf("offset %s is within threshold %s", d.Delta.Round(time.Second), threshold)
		return d
	}
	if policy == PolicyAuto && d.Delta < 0 {
		d.Action = "skip-backward"
		d.Reason = fmt.Sprintf("auto policy refuses to move clock backward by %s", (-d.Delta).Round(time.Second))
		return d
	}
	if policy == PolicyAuto {
		d.Action = "advance"
		d.Reason = fmt.Sprintf("advancing clock by %s to verified bundle.issued_at", d.Delta.Round(time.Second))
		return d
	}
	// PolicyAlways
	d.Action = "set"
	d.Reason = fmt.Sprintf("setting clock by %s (always policy)", d.Delta.Round(time.Second))
	return d
}

// SetClockFunc is the platform-specific clock setter. It is replaced in
// tests and on unsupported platforms always returns ErrUnsupported.
var SetClockFunc = setSystemClock

// ErrUnsupported is returned by SetClockFunc on platforms where this package
// cannot adjust the system clock (e.g. Windows builds).
var ErrUnsupported = errors.New("system clock adjustment not supported on this platform")

// Adjust evaluates the policy and, when appropriate, sets the system clock
// to target. It logs every decision via logger so operators can see why the
// clock was (or wasn't) touched. Returns nil for no-op decisions; returns
// an error only when an attempted set actually failed (e.g. CAP_SYS_TIME
// missing). The error is intentionally non-fatal at the call site: a clock
// adjustment that fails should warn loudly but must not block applier
// dispatch — the device may still complete provisioning if its clock is
// only slightly off, and a noisy log is more useful than a hard failure.
func Adjust(target time.Time, policy Policy, threshold time.Duration, logger *slog.Logger) error {
	if logger == nil {
		logger = slog.Default()
	}
	d := Decide(time.Now(), target, policy, threshold)
	switch d.Action {
	case "skip-zero", "skip-policy", "skip-threshold", "skip-backward":
		logger.Debug("system clock: no adjustment",
			"action", d.Action,
			"reason", d.Reason,
			"now", d.Now.UTC().Format(time.RFC3339),
			"target", target.UTC().Format(time.RFC3339),
			"delta", d.Delta.Round(time.Second))
		return nil
	case "advance", "set":
		if err := SetClockFunc(target); err != nil {
			logger.Warn("system clock: adjustment failed",
				"action", d.Action,
				"delta", d.Delta.Round(time.Second),
				"err", err)
			return fmt.Errorf("set system clock: %w", err)
		}
		logger.Info("system clock: adjusted from verified bundle",
			"action", d.Action,
			"old", d.Now.UTC().Format(time.RFC3339),
			"new", target.UTC().Format(time.RFC3339),
			"delta", d.Delta.Round(time.Second))
		return nil
	}
	return nil
}
