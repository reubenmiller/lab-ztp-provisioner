package profiles

import (
	"bytes"
	"context"
	"fmt"

	"filippo.io/age"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/sopsage"
)

// IsSOPS returns true if the YAML bytes look like a SOPS-encrypted document.
// SOPS embeds a top-level `sops:` mapping containing key-management metadata
// (lastmodified, mac, version, …). The check is conservative: real SOPS
// files always have one, and unencrypted profiles never need a top-level
// `sops:` key.
func IsSOPS(yamlBytes []byte) bool {
	// We deliberately keep this duplicate of sopsage.IsEncrypted's
	// substring check rather than calling through, so the loader's
	// detection path stays a leaf-level test that doesn't drag in any
	// crypto packages on its hot loop.
	return bytes.Contains(yamlBytes, []byte("\nsops:")) ||
		bytes.HasPrefix(yamlBytes, []byte("sops:"))
}

// DecryptSOPS decrypts a SOPS-age YAML document using the server's
// configured age identity. Replaces the previous `sops` CLI shellout —
// no subprocess, no PATH dependency, no key-file plumbing through
// environment variables.
//
// ctx is currently unused (decryption is in-process and never blocks on
// I/O) but is preserved in the signature so the callsite can keep its
// existing context wiring without churn.
func DecryptSOPS(ctx context.Context, yamlBytes []byte, identity age.Identity) ([]byte, error) {
	_ = ctx
	if identity == nil {
		// No identity means the operator either forgot to configure
		// age_key_file or deleted the bootstrap key. Either way the
		// server can't make progress; surface the misconfig clearly
		// rather than producing a confusing decryption error.
		return nil, fmt.Errorf("no age identity configured; set age_key_file in ztp-server.yaml")
	}
	return sopsage.Decrypt(yamlBytes, []age.Identity{identity})
}
