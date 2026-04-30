package payload

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

type stubIssuer struct{}

func (stubIssuer) Mint(_ context.Context, _ string, _ time.Duration) (string, time.Time, error) {
	return "otp-token", time.Now().UTC().Add(10 * time.Minute), nil
}

func (stubIssuer) Revoke(_ context.Context, _ string) error { return nil }

func TestCumulocityBuild_MintToken(t *testing.T) {
	c := &Cumulocity{
		URL:              "https://example.cumulocity.com",
		Tenant:           "t12345",
		ExternalIDPrefix: "sn",
	}
	c.SetIssuer(stubIssuer{})
	dev := &store.Device{ID: "dev-1"}

	mods, err := c.Build(context.Background(), dev)
	if err != nil {
		t.Fatalf("Build failed: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 module, got %d", len(mods))
	}
	payload := string(mods[0].RawPayload)
	if !strings.Contains(payload, "url=https://example.cumulocity.com") {
		t.Fatalf("expected url in payload, got: %s", payload)
	}
	if !strings.Contains(payload, "tenant=t12345") {
		t.Fatalf("expected tenant in payload, got: %s", payload)
	}
	if !strings.Contains(payload, "external_id=sn-dev-1") {
		t.Fatalf("expected external_id in payload, got: %s", payload)
	}
}

func TestResolveCredentialRef_UsesRegisteredLookup(t *testing.T) {
	SetCredentialLookup(func(ref string) (CredentialMaterial, bool) {
		if ref != "prod-eu" {
			return CredentialMaterial{}, false
		}
		return CredentialMaterial{
			URL:      "https://tenant.example.com",
			Tenant:   "t12345",
			Username: "svc-user",
			Password: "top-secret",
		}, true
	})
	defer SetCredentialLookup(nil)

	resolved, material, err := resolveCredentialRef(IssuerConfig{CredentialRef: "prod-eu"})
	if err != nil {
		t.Fatalf("resolveCredentialRef returned error: %v", err)
	}
	if resolved.CredentialRef != "prod-eu" {
		t.Fatalf("unexpected resolved config: %#v", resolved)
	}
	if material.URL != "https://tenant.example.com" || material.Username != "svc-user" || material.Password != "top-secret" {
		t.Fatalf("unexpected material: %#v", material)
	}
}

func TestResolveCredentialRef_FailsWhenReferenceMissing(t *testing.T) {
	SetCredentialLookup(func(ref string) (CredentialMaterial, bool) {
		return CredentialMaterial{}, false
	})
	defer SetCredentialLookup(nil)

	_, _, err := resolveCredentialRef(IssuerConfig{CredentialRef: "missing-ref"})
	if err == nil || !strings.Contains(err.Error(), "missing-ref") {
		t.Fatalf("expected missing credential_ref error, got %v", err)
	}
}
