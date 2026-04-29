package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/appliers"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/identity"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/api"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/profiles"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/trust"
)

// TestEndToEnd_HTTPSAllowlist spins up the server (httptest), pre-registers a
// device id, runs the agent against it, and verifies the resulting bundle's
// modules are processed by drop-in shell appliers.
func TestEndToEnd_HTTPSAllowlist(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("requires POSIX shell")
	}

	tmp := t.TempDir()
	scriptsDir := filepath.Join(tmp, "appliers")
	if err := os.MkdirAll(scriptsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Drop-in shell applier that records its stdin to a file.
	out := filepath.Join(tmp, "wifi.received")
	script := "#!/bin/sh\ncat > " + out + "\necho applied\n"
	if err := os.WriteFile(filepath.Join(scriptsDir, "wifi.v2.sh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	st := store.NewMemory()
	_ = st.AddAllowlist(context.Background(), store.AllowlistEntry{DeviceID: "dev-e2e"})

	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	eng, err := server.NewEngine(server.EngineConfig{
		Store: st,
		Verifiers: trust.Chain{
			&trust.Allowlist{Store: st},
			&trust.KnownKeypair{Store: st},
		},
		Resolver: newE2EResolver(&payload.WiFi{Networks: []payload.WiFiConfig{
			{SSID: "MyNet", Password: "supersecret", KeyMgmt: "WPA-PSK"},
		}}),
		SigningKey: signingPriv,
	})
	if err != nil {
		t.Fatal(err)
	}
	apiSrv := &api.Server{Engine: eng, Store: st}
	ts := httptest.NewServer(apiSrv.Routes())
	defer ts.Close()

	idp, err := identity.LoadOrCreateFile(filepath.Join(tmp, "id.key"))
	if err != nil {
		t.Fatal(err)
	}
	disp := appliers.New(nil)
	disp.ScriptsDir = scriptsDir

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = agent.Run(ctx, agent.Config{
		ServerURL:    ts.URL,
		DeviceID:     "dev-e2e",
		ServerPubKey: serverPub,
		Insecure:     true,
		Identity:     idp,
		Dispatcher:   disp,
		MaxAttempts:  2,
		AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("agent: %v", err)
	}

	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("applier output: %v", err)
	}
	if !strings.Contains(string(got), "MyNet") {
		t.Errorf("expected applier to receive ssid; got %q", got)
	}
	if !strings.Contains(string(got), "supersecret") {
		t.Errorf("expected applier to receive password; got %q", got)
	}
}

// newE2EResolver returns a resolver containing a single "default" profile
// whose payload is set from a single WiFi provider — enough to drive the
// e2e tests through the engine.
func newE2EResolver(wifi *payload.WiFi) *profiles.Resolver {
	prof := profiles.Profile{
		Name:    profiles.DefaultName,
		Source:  profiles.SourceDB,
		Payload: &payload.Set{WiFi: wifi},
	}
	return profiles.NewResolver(nil, &e2eStaticStore{m: map[string]profiles.Profile{prof.Name: prof}}, profiles.DefaultName, nil)
}

type e2eStaticStore struct{ m map[string]profiles.Profile }

func (s *e2eStaticStore) ListProfiles(_ context.Context) ([]profiles.Profile, error) {
	out := make([]profiles.Profile, 0, len(s.m))
	for _, p := range s.m {
		out = append(out, p)
	}
	return out, nil
}

func (s *e2eStaticStore) GetProfile(_ context.Context, name string) (*profiles.Profile, error) {
	if p, ok := s.m[name]; ok {
		return &p, nil
	}
	return nil, nil
}

// TestEndToEnd_PendingThenApprove walks an unknown device through the manual
// approval flow.
func TestEndToEnd_PendingThenApprove(t *testing.T) {
	tmp := t.TempDir()
	st := store.NewMemory()
	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	eng, _ := server.NewEngine(server.EngineConfig{
		Store: st,
		Verifiers: trust.Chain{
			&trust.Allowlist{Store: st},
			&trust.KnownKeypair{Store: st},
		},
		SigningKey: signingPriv,
	})
	apiSrv := &api.Server{Engine: eng, Store: st}
	ts := httptest.NewServer(apiSrv.Routes())
	defer ts.Close()

	idp, _ := identity.LoadOrCreateFile(filepath.Join(tmp, "id.key"))
	disp := appliers.New(nil)
	disp.ScriptsDir = "" // no scripts

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Run the agent in a goroutine; it should keep retrying while pending.
	done := make(chan error, 1)
	go func() {
		done <- agent.Run(ctx, agent.Config{
			ServerURL:    ts.URL,
			DeviceID:     "dev-pending",
			ServerPubKey: serverPub,
			Insecure:     true,
			Identity:     idp,
			Dispatcher:   disp,
			PendingPoll:  100 * time.Millisecond,
			AgentVersion: "test",
		})
	}()

	// Wait for the pending entry to appear, then approve it.
	deadline := time.Now().Add(5 * time.Second)
	var pendingID string
	for time.Now().Before(deadline) {
		list, _ := st.ListPending(context.Background())
		if len(list) == 1 {
			pendingID = list[0].ID
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if pendingID == "" {
		t.Fatal("no pending entry appeared")
	}
	// Approve: copy pending into devices so known_keypair will trust it.
	p, _ := st.GetPending(context.Background(), pendingID)
	_ = st.UpsertDevice(context.Background(), &store.Device{
		ID:        p.DeviceID,
		PublicKey: p.PublicKey,
		Facts:     p.Facts,
	})
	_ = st.DeletePending(context.Background(), pendingID)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("agent: %v", err)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("agent did not finish after approval")
	}
}
