package main

import (
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/appliers"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/identity"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// ── parseTransportList ───────────────────────────────────────────────────────

func TestParseTransportList_Valid(t *testing.T) {
	cases := []struct {
		input string
		want  []string
	}{
		{"http", []string{"http"}},
		{"ble", []string{"ble"}},
		{"http,ble", []string{"http", "ble"}},
		{"ble,http", []string{"ble", "http"}},
		// auto expands to http only (bleCapable is false in test builds)
		{"auto", []string{"http"}},
		// duplicates are deduplicated preserving first-occurrence order
		{"http,http", []string{"http"}},
		{"http,auto", []string{"http"}}, // auto adds http which is already seen
	}
	for _, tc := range cases {
		got, err := parseTransportList(tc.input)
		if err != nil {
			t.Errorf("parseTransportList(%q): unexpected error: %v", tc.input, err)
			continue
		}
		if len(got) != len(tc.want) {
			t.Errorf("parseTransportList(%q) = %v, want %v", tc.input, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("parseTransportList(%q)[%d] = %q, want %q", tc.input, i, got[i], tc.want[i])
			}
		}
	}
}

func TestParseTransportList_Invalid(t *testing.T) {
	cases := []string{"ftp", "http,ftp", "HTTP", ""}
	for _, tc := range cases {
		_, err := parseTransportList(tc)
		if tc == "" {
			// empty string → splitCSV returns nothing → "must not be empty" error
			if err == nil {
				t.Errorf("parseTransportList(%q): expected error for empty input", tc)
			}
			continue
		}
		if err == nil {
			t.Errorf("parseTransportList(%q): expected error for unknown token", tc)
		}
	}
}

// ── buildHTTPCandidates ──────────────────────────────────────────────────────

// TestBuildHTTPCandidates_FiltersUnreachable verifies that unreachable servers
// are excluded and reachable ones are returned.
func TestBuildHTTPCandidates_FiltersUnreachable(t *testing.T) {
	// A server that accepts TCP connections.
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer live.Close()

	// Use a port that is very unlikely to have anything listening.
	dead := "http://127.0.0.1:19999"

	pubKey := ""
	candidates := buildHTTPCandidates(live.URL, []string{dead}, false, "_ztp._tcp", &pubKey, testLogger(t))
	if len(candidates) != 1 {
		t.Fatalf("expected 1 live candidate, got %d: %v", len(candidates), candidates)
	}
	if candidates[0].url != live.URL {
		t.Errorf("expected %q, got %q", live.URL, candidates[0].url)
	}
}

func TestBuildHTTPCandidates_ServerURLFirst(t *testing.T) {
	s1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer s1.Close()
	s2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer s2.Close()

	pubKey := ""
	candidates := buildHTTPCandidates(s1.URL, []string{s2.URL}, false, "_ztp._tcp", &pubKey, testLogger(t))
	if len(candidates) < 2 {
		t.Fatalf("expected 2 candidates, got %d", len(candidates))
	}
	if candidates[0].url != s1.URL {
		t.Errorf("expected --server URL to be first; got %q", candidates[0].url)
	}
}

// ── runMultiTransport ────────────────────────────────────────────────────────

// newTestAcceptEnrollServer starts an httptest server that signs enrollment
// requests and returns accept responses using the provided signing key.
func newTestAcceptEnrollServer(t *testing.T, signingPriv ed25519.PrivateKey) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server-info" {
			w.Header().Set("Content-Type", "application/json")
			pub := signingPriv.Public().(ed25519.PublicKey)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"public_key": protocol.EncodePublicKey(pub),
			})
			return
		}
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		// Sign an empty bundle and return accepted.
		bundle := protocol.ProvisioningBundle{DeviceID: "test"}
		signed, err := protocol.Sign(bundle, signingPriv, "server")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
			Status: protocol.StatusAccepted,
			Bundle: signed,
		})
	}))
}

func newTestBaseCfg(t *testing.T, serverPub ed25519.PublicKey) agent.Config {
	t.Helper()
	tmp := t.TempDir()
	idp, _ := identity.LoadOrCreateFile(filepath.Join(tmp, "id.key"))
	disp := appliers.New(nil)
	return agent.Config{
		ServerPubKey: serverPub,
		Insecure:     true,
		Identity:     idp,
		Dispatcher:   disp,
		PendingPoll:  10 * time.Millisecond,
		AgentVersion: "test",
		DeviceID:     "test-device",
	}
}

// TestRunMultiTransport_HTTPSucceeds verifies that a reachable HTTP server
// is used and the overall call succeeds.
func TestRunMultiTransport_HTTPSucceeds(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	ts := newTestAcceptEnrollServer(t, signingPriv)
	defer ts.Close()

	candidates := []httpCandidate{{url: ts.URL, dialAddr: ""}}
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pubKeyStr := protocol.EncodePublicKey(serverPub)
	err := runHTTPCandidates(ctx, candidates, baseCfg, pubKeyStr, "", true, testLogger(t))
	if err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}

// TestRunMultiTransport_HTTPFails_BLECalled verifies that when all HTTP
// candidates fail with ErrServerUnreachable, runMultiTransport continues to
// the BLE transport.
func TestRunMultiTransport_HTTPFails_BLECalled(t *testing.T) {
	// Use a server that immediately returns 500 (network error in agent.Run).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	candidates := []httpCandidate{{url: ts.URL}}
	baseCfg := newTestBaseCfg(t, serverPub)
	// 1 network failure to trigger ErrServerUnreachable quickly per candidate.
	baseCfg.MaxNetworkFailures = 1 // overridden per-candidate in runHTTPCandidates, but baseCfg field unused there

	bleCalled := false
	savedBLERunner := bleRunner
	savedBLECapable := bleCapable
	bleCapable = true
	bleRunner = func(_ context.Context, _ agent.Config, _ *slog.Logger) error {
		bleCalled = true
		return nil
	}
	t.Cleanup(func() {
		bleRunner = savedBLERunner
		bleCapable = savedBLECapable
	})

	pubKeyStr := protocol.EncodePublicKey(serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scanCfg := scanConfig{serverPubKey: pubKeyStr}
	err := runMultiTransport(ctx, []string{"http", "ble"}, candidates, baseCfg, scanCfg, 0, "", true, testLogger(t))
	if err != nil {
		t.Fatalf("expected BLE to succeed, got: %v", err)
	}
	if !bleCalled {
		t.Error("expected BLE runner to be called after HTTP candidates exhausted")
	}
}

// TestRunMultiTransport_RejectedNoBLE verifies that a server rejection
// propagates immediately and BLE is not attempted.
func TestRunMultiTransport_RejectedNoBLE(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server-info" {
			_, sigPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
			pub := sigPriv.Public().(ed25519.PublicKey)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"public_key": protocol.EncodePublicKey(pub)})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
			Status: protocol.StatusRejected,
			Reason: "device denied",
		})
	}))
	defer ts.Close()

	bleCalled := false
	savedBLERunner := bleRunner
	savedBLECapable := bleCapable
	bleCapable = true
	bleRunner = func(_ context.Context, _ agent.Config, _ *slog.Logger) error {
		bleCalled = true
		return nil
	}
	t.Cleanup(func() {
		bleRunner = savedBLERunner
		bleCapable = savedBLECapable
	})

	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	candidates := []httpCandidate{{url: ts.URL}}
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Empty pubKeyStr forces per-candidate fetch from /v1/server-info.
	err := runMultiTransport(ctx, []string{"http", "ble"}, candidates, baseCfg, scanConfig{}, 0, "", true, testLogger(t))
	if err == nil {
		t.Fatal("expected rejection error, got nil")
	}
	var rejected agent.ErrEnrollRejected
	if !errors.As(err, &rejected) {
		t.Errorf("expected ErrEnrollRejected, got: %T: %v", err, err)
	}
	if bleCalled {
		t.Error("BLE must not be called after a server rejection")
	}
}

// TestRunMultiTransport_PendingNotFallenBack verifies that a server that
// eventually approves after pending responses does not cause a transport switch.
func TestRunMultiTransport_PendingNotFallenBack(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	bundle := protocol.ProvisioningBundle{DeviceID: "pend-test"}
	signedBundle, _ := protocol.Sign(bundle, signingPriv, "server")

	attempt := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server-info" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"public_key": protocol.EncodePublicKey(serverPub)})
			return
		}
		attempt++
		w.Header().Set("Content-Type", "application/json")
		if attempt <= 2 {
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{Status: protocol.StatusPending, Reason: "hold on"})
		} else {
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{Status: protocol.StatusAccepted, Bundle: signedBundle})
		}
	}))
	defer ts.Close()

	bleCalled := false
	savedBLERunner := bleRunner
	savedBLECapable := bleCapable
	bleCapable = true
	bleRunner = func(_ context.Context, _ agent.Config, _ *slog.Logger) error {
		bleCalled = true
		return nil
	}
	t.Cleanup(func() {
		bleRunner = savedBLERunner
		bleCapable = savedBLECapable
	})

	candidates := []httpCandidate{{url: ts.URL}}
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err := runMultiTransport(ctx, []string{"http", "ble"}, candidates, baseCfg, scanConfig{}, 0, "", true, testLogger(t))
	if err != nil {
		t.Fatalf("expected success after pending→accepted, got: %v", err)
	}
	if bleCalled {
		t.Error("BLE must not be called when HTTP eventually succeeds via pending")
	}
}

// ── scanAndEnroll ────────────────────────────────────────────────────────────

// TestScanAndEnroll_PicksUpServerOnLaterTick verifies that scanAndEnroll keeps
// rescanning until a previously-unhealthy server starts accepting enrollments.
// Models the real-world scenario: agent starts before network is up; later
// ticks of the scanner finally see a reachable, healthy server.
func TestScanAndEnroll_PicksUpServerOnLaterTick(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)
	pubKeyStr := protocol.EncodePublicKey(serverPub)

	stage := &atomicStage{}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if stage.healthy() {
			if r.URL.Path == "/v1/server-info" {
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"public_key": pubKeyStr})
				return
			}
			bundle := protocol.ProvisioningBundle{DeviceID: "test"}
			signed, _ := protocol.Sign(bundle, signingPriv, "server")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
				Status: protocol.StatusAccepted,
				Bundle: signed,
			})
			return
		}
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer ts.Close()

	// Flip the server to healthy after the scanner has had a chance to fail
	// at least once.
	time.AfterFunc(150*time.Millisecond, stage.flip)

	scanCfg := scanConfig{fallbacks: []string{ts.URL}, serverPubKey: pubKeyStr}
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := scanAndEnroll(ctx, 50*time.Millisecond, scanCfg, baseCfg, "", true, testLogger(t))
	if err != nil {
		t.Fatalf("expected scanAndEnroll to succeed once the server became healthy, got: %v", err)
	}
}

// TestScanAndEnroll_PropagatesTerminalError verifies that a server rejection
// (non-network error) is surfaced immediately rather than retried.
func TestScanAndEnroll_PropagatesTerminalError(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/server-info" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"public_key": protocol.EncodePublicKey(serverPub)})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
			Status: protocol.StatusRejected,
			Reason: "device denied",
		})
	}))
	defer ts.Close()

	scanCfg := scanConfig{fallbacks: []string{ts.URL}}
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := scanAndEnroll(ctx, 30*time.Millisecond, scanCfg, baseCfg, "", true, testLogger(t))
	if err == nil {
		t.Fatal("expected rejection error, got nil")
	}
	var rejected agent.ErrEnrollRejected
	if !errors.As(err, &rejected) {
		t.Errorf("expected ErrEnrollRejected, got: %T: %v", err, err)
	}
}

// TestScanAndEnroll_RespectsContextCancel verifies that scanAndEnroll exits
// promptly when its context is cancelled.
func TestScanAndEnroll_RespectsContextCancel(t *testing.T) {
	scanCfg := scanConfig{fallbacks: []string{"http://127.0.0.1:19999"}}
	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(80 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := scanAndEnroll(ctx, 30*time.Millisecond, scanCfg, baseCfg, "", true, testLogger(t))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Errorf("scanAndEnroll took too long to exit on cancel: %v", elapsed)
	}
}

// ── runMultiTransport: race phase ────────────────────────────────────────────

// TestRunMultiTransport_ScannerWinsBLECancelled verifies that when the
// rescanner finds a reachable server during Phase 2, BLE is cancelled (via
// context) and the call returns success.
func TestRunMultiTransport_ScannerWinsBLECancelled(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	ts := newTestAcceptEnrollServer(t, signingPriv)
	defer ts.Close()

	bleCancelled := make(chan struct{})
	savedBLERunner := bleRunner
	savedBLECapable := bleCapable
	bleCapable = true
	bleRunner = func(ctx context.Context, _ agent.Config, _ *slog.Logger) error {
		<-ctx.Done()
		close(bleCancelled)
		return ctx.Err()
	}
	t.Cleanup(func() {
		bleRunner = savedBLERunner
		bleCapable = savedBLECapable
	})

	scanCfg := scanConfig{
		fallbacks:    []string{ts.URL},
		serverPubKey: protocol.EncodePublicKey(serverPub),
	}
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Empty initial candidates forces entry into Phase 2 (race).
	err := runMultiTransport(ctx, []string{"http", "ble"}, nil, baseCfg, scanCfg, 50*time.Millisecond, "", true, testLogger(t))
	if err != nil {
		t.Fatalf("expected scanner to win, got: %v", err)
	}
	select {
	case <-bleCancelled:
	case <-time.After(2 * time.Second):
		t.Error("BLE was not cancelled after scanner won the race")
	}
}

// TestRunMultiTransport_BLEWinsScannerCancelled verifies that when BLE
// completes first, the scanner goroutine is cancelled and the call returns
// success.
func TestRunMultiTransport_BLEWinsScannerCancelled(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	savedBLERunner := bleRunner
	savedBLECapable := bleCapable
	bleCapable = true
	bleRunner = func(_ context.Context, _ agent.Config, _ *slog.Logger) error {
		return nil // succeed promptly
	}
	t.Cleanup(func() {
		bleRunner = savedBLERunner
		bleCapable = savedBLECapable
	})

	scanCfg := scanConfig{
		fallbacks:    []string{"http://127.0.0.1:19999"}, // unreachable
		serverPubKey: protocol.EncodePublicKey(serverPub),
	}
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := runMultiTransport(ctx, []string{"http", "ble"}, nil, baseCfg, scanCfg, 50*time.Millisecond, "", true, testLogger(t))
	if err != nil {
		t.Fatalf("expected BLE to win, got: %v", err)
	}
}

// TestRunMultiTransport_ScanIntervalZeroLegacy verifies that scan_interval=0
// preserves the legacy one-shot behaviour: BLE is invoked exactly once, no
// rescanner is spawned.
func TestRunMultiTransport_ScanIntervalZeroLegacy(t *testing.T) {
	bleCalls := 0
	savedBLERunner := bleRunner
	savedBLECapable := bleCapable
	bleCapable = true
	bleRunner = func(_ context.Context, _ agent.Config, _ *slog.Logger) error {
		bleCalls++
		return nil
	}
	t.Cleanup(func() {
		bleRunner = savedBLERunner
		bleCapable = savedBLECapable
	})

	_, signingPriv, _ := ed25519.GenerateKey(cryptorand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)
	baseCfg := newTestBaseCfg(t, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := runMultiTransport(ctx, []string{"http", "ble"}, nil, baseCfg, scanConfig{}, 0, "", true, testLogger(t))
	if err != nil {
		t.Fatalf("expected BLE to succeed, got: %v", err)
	}
	if bleCalls != 1 {
		t.Errorf("expected exactly 1 BLE call in legacy mode, got %d", bleCalls)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// atomicStage flips a boolean once, used to model "server became healthy at
// some point during the test".
type atomicStage struct {
	healthyN int32
}

func (s *atomicStage) flip()         { atomic.StoreInt32(&s.healthyN, 1) }
func (s *atomicStage) healthy() bool { return atomic.LoadInt32(&s.healthyN) == 1 }

// testLogger returns a slog.Logger that writes through testing.T.
func testLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.New(slog.NewTextHandler(testWriter{t}, nil))
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}
