package protocol

import (
	"strings"
	"testing"
	"time"
)

func TestMarshalEnrollText(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 6, time.UTC)
	got := string(MarshalEnrollText(&EnrollResponse{
		ProtocolVersion: Version,
		Status:          StatusPending,
		Reason:          "awaiting\napproval",
		RetryAfter:      30,
		ServerTime:      &now,
	}))
	want := "protocol_version=1\nstatus=pending\nreason=awaiting\\napproval\nretry_after=30\nserver_time=2026-01-02T03:04:05Z\n"
	if got != want {
		t.Fatalf("got\n%q\nwant\n%q", got, want)
	}
}

// The JSON bundle is dead weight next to a manifest for a text reader, and a
// BLE device pays for every byte of it; it is dropped then, and only then.
func TestMarshalEnrollText_BundleOnlyWithoutManifest(t *testing.T) {
	bundle := &SignedEnvelope{Algorithm: AlgEd25519, KeyID: "k", Payload: "YnVuZGxl", Signature: "cw=="}
	manifest := &SignedEnvelope{Algorithm: AlgEd25519, KeyID: "k", Payload: "bWFuaWZlc3Q=", Signature: "cw=="}

	both := string(MarshalEnrollText(&EnrollResponse{
		ProtocolVersion: Version, Status: StatusAccepted, Bundle: bundle, TextManifest: manifest,
	}))
	if strings.Contains(both, "bundle.") {
		t.Errorf("bundle.* rendered next to a manifest:\n%s", both)
	}
	if !strings.Contains(both, "manifest.payload=bWFuaWZlc3Q=\n") {
		t.Errorf("manifest missing:\n%s", both)
	}

	only := string(MarshalEnrollText(&EnrollResponse{
		ProtocolVersion: Version, Status: StatusAccepted, Bundle: bundle,
	}))
	if !strings.Contains(only, "bundle.payload=YnVuZGxl\n") {
		t.Errorf("bundle dropped although there is no manifest:\n%s", only)
	}
}

func TestParseEnrollStatus(t *testing.T) {
	for name, tc := range map[string]struct {
		body   string
		status string
		reason string
		retry  int
	}{
		"json":    {`{"protocol_version":"1","status":"pending","reason":"wait","retry_after":15}`, "pending", "wait", 15},
		"text":    {"protocol_version=1\nstatus=pending\nreason=wait\\nmore\nretry_after=15\n", "pending", "wait\nmore", 15},
		"crlf":    {"status=accepted\r\nmanifest.payload=abc=\r\n", "accepted", "", 0},
		"garbage": {"<html>bad gateway</html>", "", "", 0},
		"empty":   {"", "", "", 0},
	} {
		t.Run(name, func(t *testing.T) {
			s, r, ra := ParseEnrollStatus([]byte(tc.body))
			if s != tc.status || r != tc.reason || ra != tc.retry {
				t.Fatalf("got (%q, %q, %d), want (%q, %q, %d)", s, r, ra, tc.status, tc.reason, tc.retry)
			}
		})
	}
}

// The rendering is shared by every text reader; an envelope must round-trip
// through the same key names the shell agent reads with kv_get.
func TestMarshalEnvelopeText(t *testing.T) {
	got := string(MarshalEnvelopeText("manifest", &SignedEnvelope{
		Algorithm: AlgECDSAP256, KeyID: "k", Payload: "cA==", Signature: "cw==",
	}))
	for _, want := range []string{"manifest.alg=ecdsa-p256-sha256\n", "manifest.key_id=k\n",
		"manifest.payload=cA==\n", "manifest.signature=cw==\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}
