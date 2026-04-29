package sopsage

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Metadata mirrors the top-level "sops:" YAML map produced by the upstream
// sops CLI. Only the subset of fields we read or write is modelled; unknown
// fields parse without error and are preserved on round-trip via
// MetadataExtras so we don't strip data we don't understand.
type Metadata struct {
	// AgeRecipients holds one entry per age recipient the data key was
	// sealed to. We never write empty stanzas (kms/gcp_kms/...) because
	// we only support age, but we read them tolerantly to cope with files
	// that operators sealed with the upstream CLI and an age recipient
	// alongside other backends.
	AgeRecipients []AgeStanza `yaml:"age,omitempty"`

	// LastModified is the RFC3339 timestamp embedded in the file. It
	// doubles as the additional-authenticated-data input when sealing
	// the MAC, so changing it without re-computing the MAC breaks
	// verification — by design.
	LastModified string `yaml:"lastmodified,omitempty"`

	// MAC is itself an ENC[…] token. Plaintext is hex(HMAC-SHA512). See
	// package doc for the exact computation.
	MAC string `yaml:"mac,omitempty"`

	// EncryptedRegex / UnencryptedRegex / EncryptedSuffix / UnencryptedSuffix
	// are the rules used at sealing time. We persist them verbatim so an
	// in-place edit re-applies the same rules without the operator having
	// to remember them.
	EncryptedRegex    string `yaml:"encrypted_regex,omitempty"`
	UnencryptedRegex  string `yaml:"unencrypted_regex,omitempty"`
	EncryptedSuffix   string `yaml:"encrypted_suffix,omitempty"`
	UnencryptedSuffix string `yaml:"unencrypted_suffix,omitempty"`

	// MACOnlyEncrypted toggles MAC scope. When true the MAC covers only
	// encrypted leaves; otherwise it covers every leaf in the document
	// (which is the upstream default and also ours).
	MACOnlyEncrypted bool `yaml:"mac_only_encrypted,omitempty"`

	// Version records the format version. We emit "3.7.3" (matching the
	// fixture in our testdata) for maximum CLI compatibility.
	Version string `yaml:"version,omitempty"`
}

// AgeStanza is one age recipient's record. "Enc" is the PEM-armored age
// ciphertext of the data key — the same format the `age` CLI produces with
// `-a`.
type AgeStanza struct {
	Recipient string `yaml:"recipient"`
	Enc       string `yaml:"enc"`
}

// EncryptionRules selects which YAML leaves to encrypt. Semantics match
// upstream sops: a leaf is sealed if its key matches EncryptedRegex OR
// ends in EncryptedSuffix; a leaf is left alone if it matches
// UnencryptedRegex OR ends in UnencryptedSuffix. When no rule is set we
// default to encrypting everything, matching `sops --encrypt` with no
// flags.
//
// Only the leaf's own key is considered, never the dotted path —
// matching upstream — so a key named "password" anywhere in the tree is
// always encrypted under EncryptedRegex="^password$".
type EncryptionRules struct {
	EncryptedRegex    string
	UnencryptedRegex  string
	EncryptedSuffix   string
	UnencryptedSuffix string
}

// shouldEncrypt returns whether the leaf at parentEncrypted scope with the
// given key should be sealed. parentEncrypted carries inherited
// "everything below this is encrypted" state from a matching ancestor
// key, so e.g. encrypting a list under key "secrets" still seals every
// element even though the list indices aren't in `key`.
func (r EncryptionRules) shouldEncrypt(key string, parentEncrypted bool) (bool, error) {
	// An explicit unencrypted rule beats inherited "encrypt me" — this
	// gives operators a way to punch holes in an otherwise-sealed subtree.
	if r.UnencryptedSuffix != "" && strings.HasSuffix(key, r.UnencryptedSuffix) {
		return false, nil
	}
	if r.UnencryptedRegex != "" {
		re, err := regexp.Compile(r.UnencryptedRegex)
		if err != nil {
			return false, fmt.Errorf("unencrypted_regex: %w", err)
		}
		if re.MatchString(key) {
			return false, nil
		}
	}
	if r.EncryptedSuffix != "" && strings.HasSuffix(key, r.EncryptedSuffix) {
		return true, nil
	}
	if r.EncryptedRegex != "" {
		re, err := regexp.Compile(r.EncryptedRegex)
		if err != nil {
			return false, fmt.Errorf("encrypted_regex: %w", err)
		}
		if re.MatchString(key) {
			return true, nil
		}
	}
	// No rule matched: fall back to inherited state. With no rules at
	// all and no inherited state this means "leaf stays plaintext",
	// which is the correct default for `seal` invoked with neither a
	// regex nor a tag.
	return parentEncrypted, nil
}

// rulesAreSet reports whether at least one selection rule is configured.
// When false, callers fall back to the YAML-tag-driven seal flow.
func (r EncryptionRules) rulesAreSet() bool {
	return r.EncryptedRegex != "" || r.UnencryptedRegex != "" ||
		r.EncryptedSuffix != "" || r.UnencryptedSuffix != ""
}

// validate returns an error if the configured regexes don't compile.
// Called early so seal-time errors surface before the data key is
// generated.
func (r EncryptionRules) validate() error {
	if r.EncryptedRegex != "" {
		if _, err := regexp.Compile(r.EncryptedRegex); err != nil {
			return fmt.Errorf("encrypted_regex: %w", err)
		}
	}
	if r.UnencryptedRegex != "" {
		if _, err := regexp.Compile(r.UnencryptedRegex); err != nil {
			return fmt.Errorf("unencrypted_regex: %w", err)
		}
	}
	return nil
}

// ErrNoMatchingIdentity is returned by Decrypt when none of the supplied
// age identities can unwrap any of the file's recipient stanzas.
var ErrNoMatchingIdentity = errors.New("sopsage: no age identity could decrypt the data key")

// ErrMACMismatch is returned by Decrypt when the recomputed MAC does not
// match the value stored in the file. In strict mode this aborts
// decryption; permissive callers can wrap Decrypt and ignore it (we do
// not do this in the server because a MAC mismatch is the canonical
// indicator of file tampering).
var ErrMACMismatch = errors.New("sopsage: MAC verification failed")

// ErrNotEncrypted is returned by Decrypt when the input lacks a top-level
// "sops:" map. Callers usually screen with IsEncrypted first.
var ErrNotEncrypted = errors.New("sopsage: input is not a SOPS-encrypted document")
