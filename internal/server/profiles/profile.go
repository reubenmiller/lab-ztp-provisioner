// Package profiles defines named provisioning profiles — the unit of
// configuration that determines which payload modules a device receives at
// enrollment.
//
// Profiles can come from two sources:
//
//   - file: YAML files in a directory (default /etc/ztp/profiles.d). These
//     are the canonical, git-managed source of truth. They may be encrypted
//     with SOPS (detected by a top-level `sops:` key) and may use ${VAR}
//     environment-variable interpolation in string leaves.
//
//   - db:   profiles created/edited through the admin UI. Stored in the
//     same Store as devices and tokens.
//
// The Resolver merges both sources at request time. File profiles win on
// name collision (the UI surfaces a warning); operators cannot accidentally
// override a git-managed profile from the UI.
//
// Per-device profile selection follows a deterministic precedence chain
// (see Resolver.Resolve).
package profiles

import (
	"fmt"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Source identifies where a profile came from. Used by the API + UI to
// determine whether a profile is editable.
type Source string

const (
	SourceFile Source = "file"
	SourceDB   Source = "db"
)

// Profile is a named bundle of payload-provider settings plus the metadata
// the resolver needs to decide which device gets which profile.
type Profile struct {
	// Name is the unique identifier. Lowercase letters, digits, dash and
	// underscore only — see ValidateName.
	Name string `json:"name" yaml:"name"`

	// Description is shown in the UI's profile picker so operators have
	// context when assigning profiles.
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Labels are arbitrary string tags used for grouping in the UI and as
	// match keys for Selector.MatchLabels (matched against device facts).
	Labels map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`

	// Selector enables auto-matching by device facts. Optional; if unset the
	// profile only applies via explicit assignment (allowlist, token, manual
	// approval, or persisted Device.ProfileName).
	Selector *Selector `json:"selector,omitempty" yaml:"selector,omitempty"`

	// Priority orders selector evaluation: profiles with higher priority are
	// evaluated first. Equal priorities fall back to lexicographic name
	// order so resolution is deterministic.
	Priority int `json:"priority,omitempty" yaml:"priority,omitempty"`

	// Payload is the actual provider configuration. Same shape as the
	// pre-profile top-level `payload:` block.
	Payload *payload.Set `json:"payload,omitempty" yaml:"payload,omitempty"`

	// Crypto selects the algorithm suite used to sign and seal bundles for
	// devices on this profile. Omitted means the server's configured default,
	// which is itself the original Ed25519/X25519 suite unless an operator
	// changes it. It lives per-profile because the reason to change it is a
	// device population, not a deployment: a fleet of microcontrollers needs
	// a different suite from a fleet of Linux boxes served by the same server.
	Crypto *CryptoOptions `json:"crypto,omitempty" yaml:"crypto,omitempty"`

	// Source is set by the loader; it is not read from YAML.
	Source Source `json:"source" yaml:"-"`

	// UpdatedAt / UpdatedBy track last-modification metadata. For file
	// profiles, UpdatedAt is the file's mtime and UpdatedBy is "file".
	UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"-"`
	UpdatedBy string    `json:"updated_by,omitempty" yaml:"-"`
}

// CryptoOptions selects the algorithm suite for a profile's devices.
type CryptoOptions struct {
	// Suite is "ed25519-x25519" (the default) or "p256". See
	// protocol.Suite for what each one means and why the second exists.
	Suite string `json:"suite,omitempty" yaml:"suite,omitempty"`
}

// Suite resolves the profile's suite, falling back to def when the profile
// does not select one. An unparseable value is an operator error and is
// returned as such rather than silently defaulted — a profile that asks for a
// suite the server does not know would otherwise serve the wrong algorithms
// to a fleet that cannot verify them.
func (p *Profile) Suite(def protocol.Suite) (protocol.Suite, error) {
	if p == nil || p.Crypto == nil || p.Crypto.Suite == "" {
		if def == "" {
			return protocol.DefaultSuite, nil
		}
		return def, nil
	}
	s, err := protocol.ParseSuite(p.Crypto.Suite)
	if err != nil {
		return "", fmt.Errorf("profile %q: %w", p.Name, err)
	}
	return s, nil
}

// Selector matches a profile against a device's facts. All non-empty
// constraints must match (logical AND). Empty constraints are ignored.
//
// The selector is intentionally NOT a generic DSL: keep the surface small,
// keep the matching predictable, and force operators to extend the schema
// (and add tests) when they need a new dimension.
type Selector struct {
	// MatchLabels are facts.labels[k] == v equalities. Facts must expose
	// labels for these to match (extension point on protocol.DeviceFacts).
	MatchLabels map[string]string `json:"match_labels,omitempty" yaml:"match_labels,omitempty"`

	// MatchModel is a regular expression matched against facts.model.
	MatchModel string `json:"match_model,omitempty" yaml:"match_model,omitempty"`

	// MatchMACOUI is a list of MAC OUI prefixes (first three octets,
	// case-insensitive, "aa:bb:cc" or "aabbcc"). The selector matches if
	// ANY reported MAC starts with ANY listed OUI.
	MatchMACOUI []string `json:"match_mac_oui,omitempty" yaml:"match_mac_oui,omitempty"`

	// MatchHostname is a regex against facts.hostname.
	MatchHostname string `json:"match_hostname,omitempty" yaml:"match_hostname,omitempty"`
}
