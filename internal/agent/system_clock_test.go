package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/clock"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// recordingSetter swaps clock.SetClockFunc and records every call so the test
// can assert what the agent attempted, without actually touching the host.
type recordingSetter struct {
	mu    sync.Mutex
	calls []time.Time
}

func (r *recordingSetter) set(t time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, t)
	return nil
}

func swapSetter(t *testing.T, r *recordingSetter) {
	t.Helper()
	prev := clock.SetClockFunc
	clock.SetClockFunc = r.set
	t.Cleanup(func() { clock.SetClockFunc = prev })
}

// TestRun_SystemClockAdjustedFromBundle verifies the clock-set hook fires
// inside agent.Run() once the bundle is verified, using a target IssuedAt
// well beyond the threshold.
func TestRun_SystemClockAdjustedFromBundle(t *testing.T) {
	r := &recordingSetter{}
	swapSetter(t, r)

	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	target := time.Now().Add(2 * time.Hour).UTC()
	bundle := protocol.ProvisioningBundle{
		DeviceID: "dev-clock-test",
		IssuedAt: target,
	}
	signed, err := protocol.Sign(bundle, signingPriv, "server")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
			Status: protocol.StatusAccepted,
			Bundle: signed,
		})
	}))
	defer ts.Close()

	cfg := newMinimalConfig(t, ts, serverPub)
	cfg.SystemClockPolicy = clock.PolicyAuto

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := agent.Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(r.calls) != 1 {
		t.Fatalf("expected one clock-set call, got %d", len(r.calls))
	}
	if !r.calls[0].Equal(target) {
		t.Errorf("clock set to %v, want %v", r.calls[0], target)
	}
}

// TestRun_SystemClockOffPolicy verifies that PolicyOff suppresses the call.
func TestRun_SystemClockOffPolicy(t *testing.T) {
	r := &recordingSetter{}
	swapSetter(t, r)

	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	bundle := protocol.ProvisioningBundle{
		DeviceID: "dev-clock-off-test",
		IssuedAt: time.Now().Add(2 * time.Hour).UTC(),
	}
	signed, _ := protocol.Sign(bundle, signingPriv, "server")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
			Status: protocol.StatusAccepted,
			Bundle: signed,
		})
	}))
	defer ts.Close()

	cfg := newMinimalConfig(t, ts, serverPub)
	cfg.SystemClockPolicy = clock.PolicyOff

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := agent.Run(ctx, cfg); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(r.calls) != 0 {
		t.Errorf("PolicyOff must not invoke setter, got %d calls", len(r.calls))
	}
}

// TestApplyEnrollResponse_SystemClockAdjusted exercises the BLE path so we
// know the wiring is duplicated correctly there.
func TestApplyEnrollResponse_SystemClockAdjusted(t *testing.T) {
	r := &recordingSetter{}
	swapSetter(t, r)

	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	target := time.Now().Add(3 * time.Hour).UTC()
	bundle := protocol.ProvisioningBundle{
		DeviceID: "dev-ble-clock-test",
		IssuedAt: target,
	}
	signed, _ := protocol.Sign(bundle, signingPriv, "server")

	resp := protocol.EnrollResponse{
		Status: protocol.StatusAccepted,
		Bundle: signed,
	}
	respJSON, _ := json.Marshal(resp)

	cfg := newMinimalConfig(t, &httptest.Server{}, serverPub) // server unused
	cfg.SystemClockPolicy = clock.PolicyAuto
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	// Build a fresh ephemeral keypair so unsealing works on the empty bundle.
	_, ephPriv, err := agent.BuildEnrollEnvelope(cfg)
	if err != nil {
		t.Fatalf("BuildEnrollEnvelope: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := agent.ApplyEnrollResponse(ctx, cfg, ephPriv, respJSON); err != nil {
		t.Fatalf("ApplyEnrollResponse: %v", err)
	}

	if len(r.calls) != 1 {
		t.Fatalf("expected one clock-set call from BLE path, got %d", len(r.calls))
	}
	if !r.calls[0].Equal(target) {
		t.Errorf("BLE path set clock to %v, want %v", r.calls[0], target)
	}
}
