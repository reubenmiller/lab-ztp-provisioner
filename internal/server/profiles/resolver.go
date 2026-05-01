package profiles

import (
	"context"
	"errors"
	"log/slog"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// ErrNoProfile is returned by Resolver.Resolve when no profile matches and
// no default is configured. The engine surfaces it as an enrollment-time
// rejection.
var ErrNoProfile = errors.New("no profile matched and no default configured")

// ResolveHints carries verifier-supplied profile selection hints. Verifiers
// (allowlist, bootstrap_token, …) populate it during Verify; the engine
// passes it to Resolve. Empty hints fall through to selector matching.
type ResolveHints struct {
	// Profile is the explicit name from a verifier (allowlist entry,
	// bootstrap token).
	Profile string

	// PersistedProfile is the device's previously-resolved profile name,
	// loaded from store.Device.ProfileName. Sticky across re-enrollment so
	// a device that got "lab" once stays "lab" even after facts change.
	PersistedProfile string

	// Override is store.Device.Overrides["profile"] if set — the operator's
	// manual override.
	Override string

	// Requested is the device-supplied advisory profile hint, taken from
	// EnrollRequest.Metadata["profile"]. It is unauthenticated at first
	// contact, so it sits AFTER override / persisted / verifier in the
	// precedence chain — it can never escape an explicit operator-side
	// binding, only nudge selection when nothing else matches.
	Requested string
}

// Resolver merges file profiles and resolves a per-device
// profile via the precedence chain, and instantiates a payload.Registry on
// demand.
//
// Safe for concurrent use. The file loader's snapshot is read under RLock.
type Resolver struct {
	File           *FileLoader
	DefaultProfile string
	Logger         *slog.Logger
}

// NewResolver returns a Resolver with the supplied file loader.
func NewResolver(fileLoader *FileLoader, defaultProfile string, logger *slog.Logger) *Resolver {
	if logger == nil {
		logger = slog.Default()
	}
	return &Resolver{
		File:           fileLoader,
		DefaultProfile: defaultProfile,
		Logger:         logger,
	}
}

// List returns all file-backed profiles, sorted by (priority desc, name asc).
func (r *Resolver) List(ctx context.Context) ([]Profile, error) {
	var out []Profile
	if r.File != nil {
		out = r.File.Snapshot()
	}
	sortByPriority(out)
	return out, nil
}

// Get returns the named profile from the file loader.
func (r *Resolver) Get(ctx context.Context, name string) (*Profile, error) {
	if r.File != nil {
		if p := r.File.Get(name); p != nil {
			return p, nil
		}
	}
	return nil, nil
}

// Resolve walks the precedence chain to pick a profile for this device:
//
//  1. hints.Override          (Device.Overrides["profile"], operator-set)
//  2. hints.PersistedProfile  (Device.ProfileName from prior enrollment)
//  3. hints.Profile           (verifier-supplied: allowlist / token)
//  4. selector match on facts (priority-ordered)
//  5. hints.Requested         (device-supplied advisory hint, only honoured
//     when nothing operator-side matched first)
//  6. r.DefaultProfile        (config setting)
//  7. profile literally named "default"
//
// Returns ErrNoProfile if no step matches. The chosen profile's name is
// returned alongside so the engine can persist it back to Device.ProfileName.
func (r *Resolver) Resolve(ctx context.Context, hints ResolveHints, facts protocol.DeviceFacts) (*Profile, error) {
	tries := []string{hints.Override, hints.PersistedProfile, hints.Profile}
	for _, name := range tries {
		if name == "" {
			continue
		}
		p, err := r.Get(ctx, name)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
		// Explicitly assigned but missing → log and continue. We don't fail
		// hard here so a deleted profile doesn't permanently brick a fleet:
		// resolution falls through to selectors / default.
		r.Logger.Warn("profile assignment refers to unknown profile; falling through", "name", name)
	}
	all, err := r.List(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].Selector == nil || all[i].Selector.IsEmpty() {
			continue
		}
		if all[i].Selector.Match(facts) {
			return &all[i], nil
		}
	}
	// Step 5: device-supplied advisory hint. Same fall-through-on-miss
	// semantics as steps 1-3 — a typo or stale name in the device config
	// must not brick the fleet, it just falls through to the configured
	// default.
	if hints.Requested != "" {
		if p, err := r.Get(ctx, hints.Requested); err != nil {
			return nil, err
		} else if p != nil {
			return p, nil
		}
		r.Logger.Warn("device-requested profile not found; falling through", "name", hints.Requested)
	}
	if r.DefaultProfile != "" {
		if p, err := r.Get(ctx, r.DefaultProfile); err != nil {
			return nil, err
		} else if p != nil {
			return p, nil
		}
		r.Logger.Warn("configured default_profile not found; falling back to literal 'default'", "configured", r.DefaultProfile)
	}
	if p, err := r.Get(ctx, DefaultName); err != nil {
		return nil, err
	} else if p != nil {
		return p, nil
	}
	return nil, ErrNoProfile
}

// BuildRegistry returns the providers configured by p, in canonical order.
// Returns an empty Registry (not nil) when p has no payload configured —
// this lets the engine emit an empty (but signed) bundle, which is a
// useful no-op for "trust this device but don't push any modules" cases.
func (r *Resolver) BuildRegistry(p *Profile) payload.Registry {
	if p == nil || p.Payload == nil {
		return payload.Registry{}
	}
	return p.Payload.BuildRegistry()
}
