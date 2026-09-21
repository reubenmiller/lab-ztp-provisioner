package server_test

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload/c8yissuer"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/profiles"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/trust"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// p256Engine builds an engine whose single profile selects the p256 suite.
func p256Engine(t *testing.T, st store.Store, providers payload.Registry, verifiers trust.Chain) *server.Engine {
	t.Helper()
	set := &payload.Set{}
	for _, p := range providers {
		switch v := p.(type) {
		case *payload.WiFi:
			set.WiFi = v
		case *payload.SSH:
			set.SSH = v
		case *payload.Cumulocity:
			set.Cumulocity = v
		}
	}
	prof := profiles.Profile{
		Name:    profiles.DefaultName,
		Payload: set,
		Source:  profiles.SourceFile,
		Crypto:  &profiles.CryptoOptions{Suite: string(protocol.SuiteP256)},
	}
	resolver := profiles.NewResolver(
		profiles.NewStaticLoader([]profiles.Profile{prof}), profiles.DefaultName, nil)

	edPriv := mustEd25519(t)
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	e, err := server.NewEngine(server.EngineConfig{
		Store:          st,
		Verifiers:      verifiers,
		Resolver:       resolver,
		SigningKey:     edPriv,
		SigningKeyP256: ecPriv,
		SigningKeyID:   "server-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func mustEd25519(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

// p256DeviceEnvelope signs an EnrollRequest the way a constrained device would:
// P-256 ECDSA, an uncompressed-point public key, and an ephemeral P-256 key
// for sealing.
func p256DeviceEnvelope(t *testing.T, req protocol.EnrollRequest) (*protocol.SignedEnvelope, *ecdh.PrivateKey) {
	t.Helper()
	ephPriv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req.EphemeralP256 = base64.StdEncoding.EncodeToString(ephPriv.PublicKey().Bytes())
	return signP256Request(t, req), ephPriv
}

// signP256Request signs whatever request it is given, filling only the fields
// every request needs. Unlike p256DeviceEnvelope it does not add an ephemeral
// key, so a caller can construct the mismatch cases.
func signP256Request(t *testing.T, req protocol.EnrollRequest) *protocol.SignedEnvelope {
	t.Helper()
	idKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pubB64, err := protocol.EncodePublicKeyForSuite(&idKey.PublicKey, protocol.SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := protocol.NewNonce()
	if err != nil {
		t.Fatal(err)
	}
	req.ProtocolVersion = protocol.Version
	req.Nonce = nonce
	req.Timestamp = time.Now().UTC()
	req.PublicKey = pubB64

	env, err := protocol.SignWithSuite(req, idKey, "device", protocol.SuiteP256)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// TestEnroll_P256ProfileSealsAndSigns is the end-to-end shape a Zephyr device
// sees: it signs with P-256, the server verifies, resolves a p256 profile,
// seals the Cumulocity token to the device's P-256 ephemeral key, and signs
// the bundle with P-256.
func TestEnroll_P256ProfileSealsAndSigns(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: "dev-mcu"}); err != nil {
		t.Fatal(err)
	}

	c8y := &payload.Cumulocity{
		URL:              "https://example.cumulocity.com",
		Tenant:           "t12345",
		ExternalIDPrefix: "zephyr",
	}
	c8y.SetIssuer(c8yissuer.NewStaticIssuer("mcu-token-DO-NOT-LEAK", time.Minute, nil))

	e := p256Engine(t, st, payload.Registry{c8y}, trust.Chain{&trust.Allowlist{Store: st}})
	env, ephPriv := p256DeviceEnvelope(t, protocol.EnrollRequest{DeviceID: "dev-mcu"})

	resp, err := e.Enroll(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusAccepted {
		t.Fatalf("status = %s (%s)", resp.Status, resp.Reason)
	}
	if resp.Bundle.Algorithm != protocol.AlgECDSAP256 {
		t.Errorf("bundle alg = %q, want %q", resp.Bundle.Algorithm, protocol.AlgECDSAP256)
	}
	if resp.TextManifest.Algorithm != protocol.AlgECDSAP256 {
		t.Errorf("manifest alg = %q, want %q", resp.TextManifest.Algorithm, protocol.AlgECDSAP256)
	}

	// The token must not appear anywhere in the signed bundle.
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "mcu-token-DO-NOT-LEAK") {
		t.Fatal("plaintext token leaked into the response")
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(resp.Bundle.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var bundle protocol.ProvisioningBundle
	if err := json.Unmarshal(payloadBytes, &bundle); err != nil {
		t.Fatal(err)
	}
	var c8yMod *protocol.Module
	for i := range bundle.Modules {
		if bundle.Modules[i].Type == "c8y.v2" {
			c8yMod = &bundle.Modules[i]
		}
	}
	if c8yMod == nil || c8yMod.Sealed == nil {
		t.Fatal("c8y.v2 module missing or not sealed")
	}
	if c8yMod.Sealed.Algorithm != protocol.AlgP256ChaCha20 {
		t.Fatalf("sealed alg = %q, want %q", c8yMod.Sealed.Algorithm, protocol.AlgP256ChaCha20)
	}

	plaintext, format, err := protocol.OpenSealedModuleP256(ephPriv, c8yMod.Sealed)
	if err != nil {
		t.Fatalf("open sealed: %v", err)
	}
	if format != "raw" {
		t.Errorf("format = %q, want raw", format)
	}
	body := string(plaintext)
	for _, want := range []string{
		"url=https://example.cumulocity.com",
		"tenant=t12345",
		"external_id=zephyr-dev-mcu",
		"one_time_password=mcu-token-DO-NOT-LEAK",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in unsealed INI:\n%s", want, body)
		}
	}
}

// A device that sends only an X25519 ephemeral key to a p256 profile is a
// misconfiguration. The rejection must name the field the suite expected, or
// the operator has no way to tell which side is wrong.
func TestEnroll_P256ProfileRejectsX25519Ephemeral(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: "dev-mismatch"}); err != nil {
		t.Fatal(err)
	}
	c8y := &payload.Cumulocity{URL: "https://example.cumulocity.com", Tenant: "t1"}
	c8y.SetIssuer(c8yissuer.NewStaticIssuer("tok", time.Minute, nil))

	e := p256Engine(t, st, payload.Registry{c8y}, trust.Chain{&trust.Allowlist{Store: st}})

	// Sign with P-256 (so the request verifies) but advertise only an X25519
	// ephemeral key, as an agent on the default suite would.
	_, x25519Pub, err := protocol.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	env := signP256Request(t, protocol.EnrollRequest{
		DeviceID:        "dev-mismatch",
		EphemeralX25519: base64.StdEncoding.EncodeToString(x25519Pub[:]),
	})

	resp, err := e.Enroll(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusRejected {
		t.Fatalf("status = %s, want rejected", resp.Status)
	}
	if !strings.Contains(resp.Reason, "ephemeral_p256") {
		t.Errorf("reason %q does not name the expected field", resp.Reason)
	}
}

// TestEnroll_P256ProfileWithoutServerKey checks that a profile asking for a
// suite the server has no key for fails loudly instead of silently signing
// with an algorithm the device cannot verify.
func TestEnroll_P256ProfileWithoutServerKey(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: "dev-nokey"}); err != nil {
		t.Fatal(err)
	}
	prof := profiles.Profile{
		Name:    profiles.DefaultName,
		Payload: &payload.Set{SSH: &payload.SSH{Keys: []string{"ssh-ed25519 AAAA fake"}}},
		Source:  profiles.SourceFile,
		Crypto:  &profiles.CryptoOptions{Suite: string(protocol.SuiteP256)},
	}
	e, err := server.NewEngine(server.EngineConfig{
		Store:     st,
		Verifiers: trust.Chain{&trust.Allowlist{Store: st}},
		Resolver: profiles.NewResolver(
			profiles.NewStaticLoader([]profiles.Profile{prof}), profiles.DefaultName, nil),
		SigningKey:   mustEd25519(t),
		SigningKeyID: "server-test",
		// SigningKeyP256 deliberately nil.
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := e.PublicKeyP256(); got != "" {
		t.Fatalf("PublicKeyP256 without a key = %q, want empty", got)
	}
	env, _ := p256DeviceEnvelope(t, protocol.EnrollRequest{DeviceID: "dev-nokey"})
	if _, err := e.Enroll(ctx, env); err == nil {
		t.Fatal("enrollment succeeded without a P-256 signing key")
	}
}

// TestEngine_PublicKeyP256 checks the key /v1/server-info advertises to P-256
// devices is a well-formed point they can pin.
func TestEngine_PublicKeyP256(t *testing.T) {
	e := p256Engine(t, store.NewMemory(), nil, nil)
	pub := e.PublicKeyP256()
	if _, err := protocol.DecodePublicKeyForAlg(pub, protocol.AlgECDSAP256); err != nil {
		t.Fatalf("PublicKeyP256 %q: %v", pub, err)
	}
}

// TestEnroll_MaxResponseBytes covers the bounded-response contract a device
// with a fixed receive buffer relies on.
func TestEnroll_MaxResponseBytes(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: "dev-small"}); err != nil {
		t.Fatal(err)
	}
	c8y := &payload.Cumulocity{URL: "https://example.cumulocity.com", Tenant: "t1"}
	c8y.SetIssuer(c8yissuer.NewStaticIssuer("tok", time.Minute, nil))
	e := p256Engine(t, st, payload.Registry{c8y}, trust.Chain{&trust.Allowlist{Store: st}})

	env, _ := p256DeviceEnvelope(t, protocol.EnrollRequest{
		DeviceID:         "dev-small",
		MaxResponseBytes: 32, // far smaller than any real bundle
	})
	resp, err := e.Enroll(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusRejected {
		t.Fatalf("status = %s, want rejected", resp.Status)
	}
	if !strings.Contains(resp.Reason, "accepts at most") {
		t.Errorf("reason %q does not explain the size limit", resp.Reason)
	}
}

// TestEnroll_TextResponseFormat checks the flag the API layer uses to pick the
// line-based manifest for a device with no content negotiation of its own.
func TestEnroll_TextResponseFormat(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: "dev-text"}); err != nil {
		t.Fatal(err)
	}
	c8y := &payload.Cumulocity{URL: "https://example.cumulocity.com", Tenant: "t1"}
	c8y.SetIssuer(c8yissuer.NewStaticIssuer("tok", time.Minute, nil))
	e := p256Engine(t, st, payload.Registry{c8y}, trust.Chain{&trust.Allowlist{Store: st}})

	env, _ := p256DeviceEnvelope(t, protocol.EnrollRequest{
		DeviceID:       "dev-text",
		ResponseFormat: "text",
	})
	resp, err := e.Enroll(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusAccepted {
		t.Fatalf("status = %s (%s)", resp.Status, resp.Reason)
	}
	if !resp.WantsText {
		t.Error("WantsText not set for response_format=text")
	}
	if resp.TextManifest == nil {
		t.Fatal("no text manifest produced")
	}
	body, err := base64.StdEncoding.DecodeString(resp.TextManifest.Payload)
	if err != nil {
		t.Fatal(err)
	}
	// The sealed module must be a single line the device can split on spaces.
	if !strings.Contains(string(body), "module-sealed=c8y.v2 raw ") {
		t.Errorf("manifest lacks a sealed c8y line:\n%s", body)
	}
}

// TestEnroll_TextResponseEncrypted covers a text-format device that asked for
// whole-bundle encryption, as a Zephyr device behind a BLE relay does. The
// relay must see neither rendering of the bundle in the clear, and what the
// device decrypts must be the manifest.* records it already knows how to parse.
func TestEnroll_TextResponseEncrypted(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	if err := st.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: "dev-text-enc"}); err != nil {
		t.Fatal(err)
	}
	e := p256Engine(t, st, payload.Registry{&payload.SSH{Keys: []string{"ssh-ed25519 AAAA relay-must-not-see"}}},
		trust.Chain{&trust.Allowlist{Store: st}})

	env, ephPriv := p256DeviceEnvelope(t, protocol.EnrollRequest{
		DeviceID:       "dev-text-enc",
		ResponseFormat: "text",
		EncryptBundle:  true,
	})
	resp, err := e.Enroll(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusAccepted {
		t.Fatalf("status = %s (%s)", resp.Status, resp.Reason)
	}

	wire := string(protocol.MarshalEnrollText(resp))
	for _, leak := range []string{"manifest.", "bundle."} {
		if strings.Contains(wire, leak) {
			t.Errorf("encrypted text response carries plaintext %s records:\n%s", leak, wire)
		}
	}
	if !strings.Contains(wire, "encrypted.alg="+protocol.AlgP256ChaCha20+"\n") {
		t.Errorf("no encrypted.* records:\n%s", wire)
	}
	if !strings.Contains(wire, "server_time=") {
		t.Errorf("no server_time record:\n%s", wire)
	}

	plain, err := protocol.OpenForDeviceP256(ephPriv, resp.EncryptedBundle)
	if err != nil {
		t.Fatal(err)
	}
	fields := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(plain)), "\n") {
		k, v, _ := strings.Cut(line, "=")
		fields[k] = v
	}
	man := &protocol.SignedEnvelope{
		ProtocolVersion: protocol.Version,
		KeyID:           fields["manifest.key_id"],
		Algorithm:       fields["manifest.alg"],
		Payload:         fields["manifest.payload"],
		Signature:       fields["manifest.signature"],
	}
	pub, err := protocol.DecodePublicKeyForAlg(e.PublicKeyP256(), protocol.AlgECDSAP256)
	if err != nil {
		t.Fatal(err)
	}
	body, err := protocol.Verify(man, pub)
	if err != nil {
		t.Fatalf("decrypted manifest does not verify: %v\n%s", err, plain)
	}
	if !strings.Contains(string(body), "module=ssh.authorized_keys.v2 ") {
		t.Errorf("manifest lacks the ssh module:\n%s", body)
	}
}

// TestEnroll_MaxResponseBytesText checks the limit is measured against the
// text rendering a text-format device will actually receive.
func TestEnroll_MaxResponseBytesText(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	for _, id := range []string{"dev-fits", "dev-too-big"} {
		if err := st.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: id}); err != nil {
			t.Fatal(err)
		}
	}
	e := p256Engine(t, st, payload.Registry{&payload.SSH{Keys: []string{"ssh-ed25519 AAAA k"}}},
		trust.Chain{&trust.Allowlist{Store: st}})

	// Learn the real size from an unbounded request, then ask again with
	// exactly that limit (accepted) and one byte less (rejected).
	env, _ := p256DeviceEnvelope(t, protocol.EnrollRequest{DeviceID: "dev-fits", ResponseFormat: "text"})
	resp, err := e.Enroll(ctx, env)
	if err != nil || resp.Status != protocol.StatusAccepted {
		t.Fatalf("unbounded enroll: %v %+v", err, resp)
	}
	size := len(protocol.MarshalEnrollText(resp))
	if resp.TextManifest == nil || size == 0 {
		t.Fatal("no text rendering")
	}

	env, _ = p256DeviceEnvelope(t, protocol.EnrollRequest{
		DeviceID: "dev-too-big", ResponseFormat: "text", MaxResponseBytes: size / 2,
	})
	resp, err = e.Enroll(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusRejected || !strings.Contains(resp.Reason, "accepts at most") {
		t.Fatalf("status = %s reason = %q, want size rejection", resp.Status, resp.Reason)
	}
}
