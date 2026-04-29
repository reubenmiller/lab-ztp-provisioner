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
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
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

	// Source is set by the loader; it is not read from YAML.
	Source Source `json:"source" yaml:"-"`

	// UpdatedAt / UpdatedBy track last-modification metadata. For file
	// profiles, UpdatedAt is the file's mtime and UpdatedBy is "file".
	UpdatedAt time.Time `json:"updated_at,omitempty" yaml:"-"`
	UpdatedBy string    `json:"updated_by,omitempty" yaml:"-"`
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
