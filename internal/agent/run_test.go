package agent_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/appliers"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/identity"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// newMinimalConfig returns a base agent.Config wired up against the given
// httptest server. The server is trusted insecurely (no CA pinning).
func newMinimalConfig(t *testing.T, ts *httptest.Server, serverPub ed25519.PublicKey) agent.Config {
	t.Helper()
	tmp := t.TempDir()
	idp, err := identity.LoadOrCreateFile(filepath.Join(tmp, "id.key"))
	if err != nil {
		t.Fatalf("identity: %v", err)
	}
	disp := appliers.New(nil)
	disp.ScriptsDir = ""
	return agent.Config{
		ServerURL:    ts.URL,
		ServerPubKey: serverPub,
		Insecure:     true,
		Identity:     idp,
		Dispatcher:   disp,
		PendingPoll:  10 * time.Millisecond,
		AgentVersion: "test",
		DeviceID:     "test-device",
	}
}

// enrollHandler returns a handler that always replies with the given
// EnrollResponse JSON.
func enrollHandler(resp protocol.EnrollResponse) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	})
}

// TestRun_MaxNetworkFailures verifies that Run returns ErrServerUnreachable
// (wrapped) after MaxNetworkFailures consecutive network-level failures.
func TestRun_MaxNetworkFailures(t *testing.T) {
	// Server that always returns HTTP 500 (mapped to a network error by Run).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer ts.Close()

	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	cfg := newMinimalConfig(t, ts, serverPub)
	cfg.MaxNetworkFailures = 3
	cfg.MaxAttempts = 10 // won't be reached

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := agent.Run(ctx, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, agent.ErrServerUnreachable) {
		t.Errorf("expected ErrServerUnreachable in error chain, got: %v", err)
	}
}

// TestRun_MaxNetworkFailures_ConnRefused verifies the same using a server that
// is stopped before Run begins (connection refused).
func TestRun_MaxNetworkFailures_ConnRefused(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	url := ts.URL
	ts.Close() // close immediately so every connection attempt is refused

	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	tmp := t.TempDir()
	idp, _ := identity.LoadOrCreateFile(filepath.Join(tmp, "id.key"))
	disp := appliers.New(nil)

	cfg := agent.Config{
		ServerURL:          url,
		ServerPubKey:       serverPub,
		Insecure:           true,
		Identity:           idp,
		Dispatcher:         disp,
		PendingPoll:        5 * time.Millisecond,
		MaxNetworkFailures: 2,
		AgentVersion:       "test",
		DeviceID:           "test-device",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := agent.Run(ctx, cfg)
	if !errors.Is(err, agent.ErrServerUnreachable) {
		t.Errorf("expected ErrServerUnreachable in error chain, got: %v", err)
	}
}

// TestRun_RejectedErrorType verifies that a server rejection returns an
// ErrEnrollRejected that is matchable with errors.As and carries the reason.
func TestRun_RejectedErrorType(t *testing.T) {
	ts := httptest.NewServer(enrollHandler(protocol.EnrollResponse{
		Status: protocol.StatusRejected,
		Reason: "device banned",
	}))
	defer ts.Close()

	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	cfg := newMinimalConfig(t, ts, serverPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := agent.Run(ctx, cfg)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var rejected agent.ErrEnrollRejected
	if !errors.As(err, &rejected) {
		t.Fatalf("expected ErrEnrollRejected in error chain, got: %T: %v", err, err)
	}
	if rejected.Reason != "device banned" {
		t.Errorf("expected reason %q, got %q", "device banned", rejected.Reason)
	}

	// Also verify errors.Is works (type-only match).
	if !errors.Is(err, agent.ErrEnrollRejected{}) {
		t.Error("errors.Is(err, ErrEnrollRejected{}) should be true")
	}
	// ErrServerUnreachable must NOT be set.
	if errors.Is(err, agent.ErrServerUnreachable) {
		t.Error("rejection should not wrap ErrServerUnreachable")
	}
}

// TestRun_PendingNeverFallsBack verifies that a "pending" response keeps
// retrying the same server rather than triggering a transport switch.
// The server returns pending twice, then accepted (with a real signed bundle).
func TestRun_PendingNeverFallsBack(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	// Build a minimal signed empty bundle so the accepted response validates.
	bundle := protocol.ProvisioningBundle{DeviceID: "dev-pending-test"}
	signedBundle, err := protocol.Sign(bundle, signingPriv, "server")
	if err != nil {
		t.Fatalf("sign bundle: %v", err)
	}

	attempt := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		attempt++
		w.Header().Set("Content-Type", "application/json")
		var resp protocol.EnrollResponse
		if attempt <= 2 {
			resp = protocol.EnrollResponse{Status: protocol.StatusPending, Reason: "awaiting approval"}
		} else {
			resp = protocol.EnrollResponse{Status: protocol.StatusAccepted, Bundle: signedBundle}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer ts.Close()

	cfg := newMinimalConfig(t, ts, serverPub)
	cfg.MaxNetworkFailures = 1 // if a network error occurred it would trigger; pending must not

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := agent.Run(ctx, cfg); err != nil {
		t.Fatalf("expected success after pending → accepted, got: %v", err)
	}
	if attempt < 3 {
		t.Errorf("expected at least 3 attempts (2 pending + 1 accepted), got %d", attempt)
	}
	// No ErrServerUnreachable should appear.
	if errors.Is(err, agent.ErrServerUnreachable) {
		t.Error("pending should not trigger ErrServerUnreachable")
	}
}

// TestRun_NetworkFailures_ResetOnSuccess verifies that the consecutive-failure
// counter resets after a successful HTTP response, so isolated blips do not
// trigger ErrServerUnreachable.
func TestRun_NetworkFailures_ResetOnSuccess(t *testing.T) {
	_, signingPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverPub := signingPriv.Public().(ed25519.PublicKey)

	bundle := protocol.ProvisioningBundle{DeviceID: "dev-reset-test"}
	signedBundle, _ := protocol.Sign(bundle, signingPriv, "server")

	attempt := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/enroll" {
			http.NotFound(w, r)
			return
		}
		attempt++
		w.Header().Set("Content-Type", "application/json")
		switch attempt {
		case 1:
			// First attempt: 500 error (network failure)
			http.Error(w, "oops", http.StatusInternalServerError)
		case 2:
			// Second attempt: pending (resets network counter)
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
				Status: protocol.StatusPending, Reason: "hold on",
			})
		case 3:
			// Third attempt: another 500 (failure counter starts from 0)
			http.Error(w, "oops", http.StatusInternalServerError)
		default:
			// Eventually accepted
			_ = json.NewEncoder(w).Encode(protocol.EnrollResponse{
				Status: protocol.StatusAccepted, Bundle: signedBundle,
			})
		}
	}))
	defer ts.Close()

	cfg := newMinimalConfig(t, ts, serverPub)
	cfg.MaxNetworkFailures = 2 // would trigger on attempt 1+3 if counter wasn't reset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := agent.Run(ctx, cfg); err != nil {
		t.Fatalf("expected success, got: %v", err)
	}
}
