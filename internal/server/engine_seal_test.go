package server_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload/c8yissuer"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/trust"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// TestEnroll_SealsCumulocityToken verifies that:
//   - the c8y enrollment token never appears in the signed bundle bytes,
//   - the device can decrypt it with its ephemeral X25519 private key,
//   - other (non-sensitive) modules in the same bundle pass through clear.
func TestEnroll_SealsCumulocityToken(t *testing.T) {
	st := store.NewMemory()
	if err := st.AddAllowlist(context.Background(), store.AllowlistEntry{DeviceID: "dev-c8y"}); err != nil {
		t.Fatal(err)
	}

	c8y := &payload.Cumulocity{
		URL:              "https://example.cumulocity.com",
		Tenant:           "t12345",
		ExternalIDPrefix: "factory",
	}
	c8y.SetIssuer(c8yissuer.NewStaticIssuer("super-secret-token-DO-NOT-LEAK", time.Minute, nil))

	pub, priv := newDeviceKeys(t)
	e := newEngine(t, st, payload.Registry{
		&payload.SSH{Keys: []string{"ssh-ed25519 AAAA fake"}}, // non-sensitive
		c8y,
	}, trust.Chain{&trust.Allowlist{Store: st}})

	// Build a request with an ephemeral X25519 key, like the real agent does.
	devEphPriv, devEphPub, err := protocol.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	nonce, _ := protocol.NewNonce()
	req := protocol.EnrollRequest{
		ProtocolVersion: protocol.Version,
		Nonce:           nonce,
		Timestamp:       time.Now().UTC(),
		DeviceID:        "dev-c8y",
		PublicKey:       protocol.EncodePublicKey(pub),
		EphemeralX25519: base64.StdEncoding.EncodeToString(devEphPub[:]),
	}
	env, err := protocol.Sign(req, priv, "device")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := e.Enroll(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusAccepted || resp.Bundle == nil {
		t.Fatalf("expected accepted, got %s (%s)", resp.Status, resp.Reason)
	}

	// The signed bundle bytes must NOT contain the plaintext token.
	bundleBytes, _ := base64.StdEncoding.DecodeString(resp.Bundle.Payload)
	if strings.Contains(string(bundleBytes), "super-secret-token-DO-NOT-LEAK") {
		t.Fatalf("plaintext token leaked in signed bundle: %s", string(bundleBytes))
	}

	var bundle protocol.ProvisioningBundle
	if err := json.Unmarshal(bundleBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	var c8yMod *protocol.Module
	var sshMod *protocol.Module
	for i := range bundle.Modules {
		switch bundle.Modules[i].Type {
		case "c8y.v2":
			c8yMod = &bundle.Modules[i]
		case "ssh.authorized_keys.v2":
			sshMod = &bundle.Modules[i]
		}
	}
	if c8yMod == nil || c8yMod.Sealed == nil {
		t.Fatalf("expected sealed c8y.v2 module, got %+v", c8yMod)
	}
	if c8yMod.Payload != nil || len(c8yMod.RawPayload) > 0 {
		t.Fatalf("sealed module must not carry plaintext payload, got payload=%+v raw=%d", c8yMod.Payload, len(c8yMod.RawPayload))
	}
	if sshMod == nil || sshMod.Sealed != nil {
		t.Fatalf("expected ssh.authorized_keys.v2 module to be in clear, got sealed=%v", sshMod != nil && sshMod.Sealed != nil)
	}

	// Decrypt with the device's ephemeral private key — token must come back.
	// v2 modules carry an INI body, not JSON; we just check the expected
	// key=value lines are present.
	plaintext, format, err := protocol.OpenSealedModule(devEphPriv, c8yMod.Sealed)
	if err != nil {
		t.Fatalf("open sealed: %v", err)
	}
	// v2 modules use the "raw" format hint (the INI body is opaque
	// bytes from the protocol layer's perspective; the device
	// applier does the parsing).
	if format != "raw" {
		t.Errorf("expected format raw, got %q", format)
	}
	body := string(plaintext)
	if !strings.Contains(body, "one_time_password=super-secret-token-DO-NOT-LEAK") {
		t.Errorf("one_time_password not found in unsealed INI:\n%s", body)
	}
	if !strings.Contains(body, "external_id=factory-dev-c8y") {
		t.Errorf("external_id not found in unsealed INI:\n%s", body)
	}
}

// TestEnroll_RejectsSensitiveWithoutEphemeralKey ensures we never leak a
// secret in the clear when the device did not provide an ephemeral key.
func TestEnroll_RejectsSensitiveWithoutEphemeralKey(t *testing.T) {
	st := store.NewMemory()
	_ = st.AddAllowlist(context.Background(), store.AllowlistEntry{DeviceID: "dev-no-eph"})

	c8y := &payload.Cumulocity{URL: "https://example.cumulocity.com", Tenant: "t1"}
	c8y.SetIssuer(c8yissuer.NewStaticIssuer("secret", time.Minute, nil))

	pub, priv := newDeviceKeys(t)
	e := newEngine(t, st, payload.Registry{c8y}, trust.Chain{&trust.Allowlist{Store: st}})

	resp, err := e.Enroll(context.Background(), newRequest(t, pub, priv, "dev-no-eph", ""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusRejected {
		t.Fatalf("expected rejected, got %s", resp.Status)
	}
	if !strings.Contains(resp.Reason, "ephemeral_x25519") {
		t.Errorf("expected rejection reason to mention ephemeral key, got %q", resp.Reason)
	}
}

// fields that depend on randomness across runs need a stable refresh of nonce
// machinery; the helpers above (newDeviceKeys, newEngine, newRequest) live in
// engine_test.go.
