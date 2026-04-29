package profiles

import (
	"testing"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
)

func TestRedact_StringFieldReplaced(t *testing.T) {
	w := &payload.WiFi{Networks: []payload.WiFiConfig{
		{SSID: "net1", Password: "supersecret", KeyMgmt: "WPA-PSK"},
	}}
	out := Redact(w).(*payload.WiFi)
	if out.Networks[0].Password != RedactedSentinel {
		t.Errorf("password not redacted: %q", out.Networks[0].Password)
	}
	if out.Networks[0].SSID != "net1" {
		t.Errorf("ssid was modified: %q", out.Networks[0].SSID)
	}
	// Original must not be mutated.
	if w.Networks[0].Password != "supersecret" {
		t.Errorf("input mutated: %q", w.Networks[0].Password)
	}
}

func TestRedact_EmptyStringStaysEmpty(t *testing.T) {
	w := &payload.WiFi{Networks: []payload.WiFiConfig{{SSID: "n", Password: ""}}}
	out := Redact(w).(*payload.WiFi)
	if out.Networks[0].Password != "" {
		t.Errorf("empty password should remain empty, got %q", out.Networks[0].Password)
	}
}

func TestRedact_FilesContents(t *testing.T) {
	f := &payload.Files{Files: []payload.FileSpec{
		{Path: "/etc/x", Mode: "0644", Contents: "secret"},
	}}
	out := Redact(f).(*payload.Files)
	if out.Files[0].Contents != RedactedSentinel {
		t.Errorf("file contents not redacted: %q", out.Files[0].Contents)
	}
	if out.Files[0].Path != "/etc/x" {
		t.Errorf("path mutated: %q", out.Files[0].Path)
	}
}

func TestRedact_NilSafe(t *testing.T) {
	if Redact(nil) != nil {
		t.Error("Redact(nil) should be nil")
	}
	var w *payload.WiFi
	out := Redact(w)
	if out == nil {
		// Redact may return a typed nil pointer wrapped in interface; accept either.
		return
	}
	if pw, ok := out.(*payload.WiFi); ok && pw != nil {
		t.Errorf("expected nil pointer, got %+v", pw)
	}
}

func TestRedact_FullProfile(t *testing.T) {
	p := Profile{
		Name: "default",
		Payload: &payload.Set{
			WiFi: &payload.WiFi{Networks: []payload.WiFiConfig{{SSID: "n", Password: "p"}}},
		},
	}
	out := Redact(p).(Profile)
	if out.Payload.WiFi.Networks[0].Password != RedactedSentinel {
		t.Errorf("nested redact failed: %q", out.Payload.WiFi.Networks[0].Password)
	}
}
