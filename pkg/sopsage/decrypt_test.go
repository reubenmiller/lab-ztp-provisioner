package sopsage

import (
	"os"
	"strings"
	"testing"

	"filippo.io/age"
)

// TestDecrypt_FixtureFromUpstreamSOPS exercises the decrypt path against
// a file produced by the upstream `sops` CLI. The fixture lives in
// testdata/upstream.enc.yaml together with the age key; if the fixture
// is missing the test skips so we don't tie CI to having sops installed.
func TestDecrypt_FixtureFromUpstreamSOPS(t *testing.T) {
	enc, err := os.ReadFile("testdata/upstream.enc.yaml")
	if err != nil {
		t.Skipf("fixture missing: %v", err)
	}
	keyBytes, err := os.ReadFile("testdata/upstream.key.txt")
	if err != nil {
		t.Skipf("key missing: %v", err)
	}
	ids, err := age.ParseIdentities(strings.NewReader(string(keyBytes)))
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}

	plain, err := Decrypt(enc, ids)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	want, err := os.ReadFile("testdata/upstream.plain.yaml")
	if err != nil {
		t.Fatalf("read expected: %v", err)
	}

	// Tolerance for YAML reformatting: yaml.v3 emits 4-space indents,
	// the upstream sops CLI also emits 4-space indents, and string
	// quoting may differ on edge cases. Do an equal-after-canonicalise
	// check by re-marshalling the want side through yaml as well.
	if normalizeYAML(t, plain) != normalizeYAML(t, want) {
		t.Fatalf("decrypt mismatch:\ngot:\n%s\nwant:\n%s", plain, want)
	}
}
