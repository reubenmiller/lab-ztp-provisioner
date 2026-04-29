package sopsage

import (
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

// TestEncrypt_RoundTrip seals a plaintext document with our encrypt path,
// then decrypts it with our decrypt path and compares the result against
// the original. This is the minimum bar for self-consistency; a separate
// fixture-based test covers compatibility with the upstream sops CLI.
func TestEncrypt_RoundTrip(t *testing.T) {
	keyBytes, err := os.ReadFile("testdata/upstream.key.txt")
	if err != nil {
		t.Skipf("key missing: %v", err)
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(keyBytes)))
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	// Derive the recipient from the identity so we don't have to hardcode
	// the matching pubkey — keeps the test resilient to fixture rotation.
	x25519, ok := ids[0].(*age.X25519Identity)
	if !ok {
		t.Fatalf("expected X25519 identity, got %T", ids[0])
	}
	rcp := x25519.Recipient()

	plain := []byte("name: demo\nsecret: hunter2\nnested:\n  password: alpha\n  username: beta\nflag: true\ncount: 42\n")

	enc, err := Encrypt(plain, []age.Recipient{rcp}, EncryptionRules{
		EncryptedRegex: "^(secret|password)$",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !IsEncrypted(enc) {
		t.Fatalf("Encrypt output not detected as encrypted:\n%s", enc)
	}

	got, err := Decrypt(enc, ids)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if normalizeYAML(t, got) != normalizeYAML(t, plain) {
		t.Fatalf("round-trip mismatch:\ngot:\n%s\nwant:\n%s\nintermediate:\n%s",
			got, plain, enc)
	}
}

// TestEncrypt_NoRules_EncryptsNothing confirms that calling Encrypt with
// an empty rule set yields a sops-format file with every leaf still
// readable in plaintext. That's the contract `ztpctl secrets seal` relies
// on when the operator only wants the metadata wrapper (e.g. for diffing).
func TestEncrypt_NoRules_EncryptsNothing(t *testing.T) {
	keyBytes, err := os.ReadFile("testdata/upstream.key.txt")
	if err != nil {
		t.Skipf("key missing: %v", err)
	}
	ids, _ := age.ParseIdentities(strings.NewReader(string(keyBytes)))
	rcp := ids[0].(*age.X25519Identity).Recipient()

	plain := []byte("name: demo\nsecret: hunter2\n")
	enc, err := Encrypt(plain, []age.Recipient{rcp}, EncryptionRules{})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// The MAC itself is always sealed (so an attacker can't read it),
	// so we expect exactly one ENC[…] token in the output: the MAC.
	// Anything more would mean a data leaf got sealed despite empty rules.
	if n := strings.Count(string(enc), "ENC["); n != 1 {
		t.Fatalf("expected exactly one ENC[…] (the mac), got %d:\n%s", n, enc)
	}

	if _, err := Decrypt(enc, ids); err != nil {
		t.Fatalf("decrypt empty-rules file: %v", err)
	}
}

// TestEncrypt_SkipsInterpolationPlaceholders verifies that scalar values
// which are pure ${VAR} / ${VAR:-default} placeholders are NOT sealed,
// even when their key matches the encrypt rule. The placeholder string is
// not a secret — the actual value is supplied by the env at load time —
// so encrypting it would just bloat the file and obscure intent.
//
// Strings that merely *contain* a placeholder among other characters are
// still sealed: a literal prefix could itself carry sensitive bytes.
func TestEncrypt_SkipsInterpolationPlaceholders(t *testing.T) {
	keyBytes, err := os.ReadFile("testdata/upstream.key.txt")
	if err != nil {
		t.Skipf("key missing: %v", err)
	}
	ids, _ := age.ParseIdentities(strings.NewReader(string(keyBytes)))
	rcp := ids[0].(*age.X25519Identity).Recipient()

	plain := []byte(`name: demo
placeholder_simple: ${ZTP_WIFI_PASSWORD}
placeholder_default: ${ZTP_WIFI_PASSWORD:-example}
mixed: prefix-${ZTP_WIFI_PASSWORD}-suffix
real_secret: hunter2
`)

	enc, err := Encrypt(plain, []age.Recipient{rcp}, EncryptionRules{
		// Match every key in the doc except `name`, so the only thing
		// keeping the placeholders plaintext is the new skip predicate.
		EncryptedRegex: "^(placeholder_simple|placeholder_default|mixed|real_secret)$",
	})
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	s := string(enc)
	// Pure placeholders survive verbatim.
	if !strings.Contains(s, "placeholder_simple: ${ZTP_WIFI_PASSWORD}") {
		t.Errorf("expected ${VAR} placeholder to be left plaintext:\n%s", s)
	}
	if !strings.Contains(s, "placeholder_default: ${ZTP_WIFI_PASSWORD:-example}") {
		t.Errorf("expected ${VAR:-default} placeholder to be left plaintext:\n%s", s)
	}
	// Mixed and real_secret get sealed.
	if strings.Contains(s, "prefix-${ZTP_WIFI_PASSWORD}-suffix") {
		t.Errorf("expected mixed string to be encrypted, got plaintext:\n%s", s)
	}
	if strings.Contains(s, "hunter2") {
		t.Errorf("expected real_secret to be encrypted, got plaintext:\n%s", s)
	}

	// And the file still round-trips.
	got, err := Decrypt(enc, ids)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if normalizeYAML(t, got) != normalizeYAML(t, plain) {
		t.Fatalf("round-trip mismatch:\ngot:\n%s\nwant:\n%s", got, plain)
	}
}
