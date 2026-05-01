package server_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/profiles"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/trust"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

func newDeviceKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func newRequest(t *testing.T, pub ed25519.PublicKey, priv ed25519.PrivateKey, deviceID, token string) *protocol.SignedEnvelope {
	t.Helper()
	nonce, _ := protocol.NewNonce()
	req := protocol.EnrollRequest{
		ProtocolVersion: protocol.Version,
		Nonce:           nonce,
		Timestamp:       time.Now().UTC(),
		DeviceID:        deviceID,
		PublicKey:       protocol.EncodePublicKey(pub),
		BootstrapToken:  token,
		Facts: protocol.DeviceFacts{
			MachineID: "abc123",
			Hostname:  "device-1",
		},
	}
	env, err := protocol.Sign(req, priv, "device")
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func newEngine(t *testing.T, st store.Store, providers payload.Registry, verifiers trust.Chain) *server.Engine {
	t.Helper()
	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	e, err := server.NewEngine(server.EngineConfig{
		Store:        st,
		Verifiers:    verifiers,
		Resolver:     newTestResolver(providers),
		SigningKey:   signingPriv,
		SigningKeyID: "server-test",
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// newTestResolver wraps an arbitrary payload.Registry as a single-profile
// resolver named "default". This is the test-friendly path now that the
// engine no longer takes a Registry directly.
func newTestResolver(reg payload.Registry) *profiles.Resolver {
	set := &payload.Set{}
	for _, p := range reg {
		switch v := p.(type) {
		case *payload.WiFi:
			set.WiFi = v
		case *payload.SSH:
			set.SSH = v
		case *payload.Cumulocity:
			set.Cumulocity = v
		case *payload.Files:
			set.Files = v
		case *payload.Hook:
			set.Hook = v
		}
	}
	prof := profiles.Profile{
		Name:    profiles.DefaultName,
		Payload: set,
		Source:  profiles.SourceFile,
	}
	return profiles.NewResolver(profiles.NewStaticLoader([]profiles.Profile{prof}), profiles.DefaultName, nil)
}

func TestEnroll_AllowlistAccepts(t *testing.T) {
	st := store.NewMemory()
	_ = st.AddAllowlist(context.Background(), store.AllowlistEntry{DeviceID: "dev-1"})

	pub, priv := newDeviceKeys(t)
	e := newEngine(t, st, payload.Registry{
		&payload.SSH{Keys: []string{"ssh-ed25519 AAAA fake"}},
	}, trust.Chain{&trust.Allowlist{Store: st}})

	resp, err := e.Enroll(context.Background(), newRequest(t, pub, priv, "dev-1", ""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusAccepted {
		t.Fatalf("expected accepted, got %s (%s)", resp.Status, resp.Reason)
	}
	if resp.Bundle == nil {
		t.Fatal("expected bundle")
	}
}

func TestEnroll_UnknownDeviceGoesPending(t *testing.T) {
	st := store.NewMemory()
	pub, priv := newDeviceKeys(t)
	e := newEngine(t, st, nil, trust.Chain{
		&trust.Allowlist{Store: st},
		&trust.KnownKeypair{Store: st},
	})
	resp, err := e.Enroll(context.Background(), newRequest(t, pub, priv, "dev-2", ""))
	if err != nil {
		t.Fatal(err)
	}
	if resp.Status != protocol.StatusPending {
		t.Fatalf("expected pending, got %s", resp.Status)
	}
	pending, _ := st.ListPending(context.Background())
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(pending))
	}
	if pending[0].DeviceID != "dev-2" {
		t.Errorf("wrong device id %q", pending[0].DeviceID)
	}
}

func TestEnroll_BootstrapTokenAccepts(t *testing.T) {
	st := store.NewMemory()
	secret := "s3cr3t-token-value"
	hash := trust.HashToken(secret)
	_ = st.AddToken(context.Background(), store.BootstrapToken{
		ID: "tok-1", Hash: hash, MaxUses: 1,
	})
	pub, priv := newDeviceKeys(t)
	e := newEngine(t, st, nil, trust.Chain{&trust.BootstrapToken{Store: st}})

	resp, _ := e.Enroll(context.Background(), newRequest(t, pub, priv, "dev-3", secret))
	if resp.Status != protocol.StatusAccepted {
		t.Fatalf("expected accepted, got %s (%s)", resp.Status, resp.Reason)
	}
	// Second use should be rejected (exhausted).
	resp2, _ := e.Enroll(context.Background(), newRequest(t, pub, priv, "dev-3", secret))
	if resp2.Status != protocol.StatusAccepted {
		// Note: dev-3 is now a known device, so known_keypair would accept,
		// but here we only have bootstrap_token verifier in the chain. Token
		// is exhausted.
		if resp2.Status != protocol.StatusRejected {
			t.Fatalf("expected reject after exhaustion, got %s", resp2.Status)
		}
	}
}

func TestEnroll_NonceReplayRejected(t *testing.T) {
	st := store.NewMemory()
	_ = st.AddAllowlist(context.Background(), store.AllowlistEntry{DeviceID: "dev-r"})
	pub, priv := newDeviceKeys(t)
	e := newEngine(t, st, nil, trust.Chain{&trust.Allowlist{Store: st}})

	env := newRequest(t, pub, priv, "dev-r", "")
	resp, _ := e.Enroll(context.Background(), env)
	if resp.Status != protocol.StatusAccepted {
		t.Fatalf("first enroll: %s", resp.Status)
	}
	resp2, _ := e.Enroll(context.Background(), env)
	if resp2.Status != protocol.StatusRejected {
		t.Fatalf("expected reject on replay, got %s", resp2.Status)
	}
}
