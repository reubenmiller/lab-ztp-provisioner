package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestCanonicalize_SortsKeys(t *testing.T) {
	in := map[string]any{"b": 1, "a": map[string]any{"y": 2, "x": 3}}
	got, err := Canonicalize(in)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"x":3,"y":2},"b":1}`
	if string(got) != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestCanonicalize_StableAcrossInputOrder(t *testing.T) {
	a, _ := Canonicalize(map[string]any{"x": 1, "y": 2})
	b, _ := Canonicalize(map[string]any{"y": 2, "x": 1})
	if string(a) != string(b) {
		t.Fatalf("canonical forms differ: %s vs %s", a, b)
	}
}

func TestSignAndVerify_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bundle := ProvisioningBundle{
		ProtocolVersion: Version,
		DeviceID:        "dev-1",
		IssuedAt:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Modules: []Module{
			{Type: "ssh.authorized_keys.v2", Payload: map[string]any{"keys": []any{"ssh-ed25519 AAA..."}}},
		},
	}
	env, err := Sign(bundle, priv, "server-1")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := Verify(env, pub)
	if err != nil {
		t.Fatal(err)
	}
	var got ProvisioningBundle
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != bundle.DeviceID {
		t.Errorf("device id mismatch")
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	env, _ := Sign(map[string]any{"x": 1}, priv, "k")
	// Re-encode a different payload but keep the original signature.
	tampered, _ := Canonicalize(map[string]any{"x": 2})
	env.Payload = base64.StdEncoding.EncodeToString(tampered)
	if _, err := Verify(env, pub); err == nil {
		t.Fatal("expected verification failure")
	}
}
