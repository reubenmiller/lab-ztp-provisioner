package profiles

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileLoader_LoadAndInterpolate(t *testing.T) {
	dir := t.TempDir()
	yaml := `name: lab-a
description: "Lab profile"
priority: 5
payload:
  wifi:
    networks:
      - ssid: "${ZTP_TEST_SSID}"
        password: "${ZTP_TEST_PASS:-fallback}"
        key_mgmt: "WPA-PSK"
`
	if err := os.WriteFile(filepath.Join(dir, "lab.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewFileLoader(dir, nil)
	l.GetEnv = func(k string) (string, bool) {
		if k == "ZTP_TEST_SSID" {
			return "lab-net", true
		}
		return "", false
	}
	n, err := l.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 profile, got %d", n)
	}
	p := l.Get("lab-a")
	if p == nil {
		t.Fatal("profile not loaded")
	}
	if p.Source != SourceFile {
		t.Errorf("source = %q, want file", p.Source)
	}
	if p.Priority != 5 {
		t.Errorf("priority = %d, want 5", p.Priority)
	}
	if p.Payload == nil || p.Payload.WiFi == nil {
		t.Fatal("wifi payload missing")
	}
	if p.Payload.WiFi.Networks[0].SSID != "lab-net" {
		t.Errorf("ssid = %q, want lab-net", p.Payload.WiFi.Networks[0].SSID)
	}
	if p.Payload.WiFi.Networks[0].Password != "fallback" {
		t.Errorf("password = %q, want fallback", p.Payload.WiFi.Networks[0].Password)
	}
}

func TestFileLoader_NameDefaultsToFilename(t *testing.T) {
	dir := t.TempDir()
	yaml := `description: no name field`
	if err := os.WriteFile(filepath.Join(dir, "site-b.yaml"), []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	l := NewFileLoader(dir, nil)
	if _, err := l.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	if l.Get("site-b") == nil {
		t.Error("expected profile name to default to filename stem")
	}
}

func TestFileLoader_InterpolationFailureSkipsFile(t *testing.T) {
	dir := t.TempDir()
	bad := `name: bad
payload:
  wifi:
    networks:
      - ssid: "${REQUIRED_BUT_UNSET}"
`
	good := `name: good`
	_ = os.WriteFile(filepath.Join(dir, "bad.yaml"), []byte(bad), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "good.yaml"), []byte(good), 0o600)
	l := NewFileLoader(dir, nil)
	l.GetEnv = func(string) (string, bool) { return "", false }
	n, err := l.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("expected 1 loaded (good only), got %d", n)
	}
	if l.Get("good") == nil {
		t.Error("good profile should be loaded")
	}
	if l.Get("bad") != nil {
		t.Error("bad profile should be skipped")
	}
}

func TestFileLoader_EmptyDirNoOp(t *testing.T) {
	l := NewFileLoader("", nil)
	n, err := l.Load(context.Background())
	if err != nil || n != 0 {
		t.Errorf("got n=%d err=%v", n, err)
	}
}

func TestIsSOPS(t *testing.T) {
	if IsSOPS([]byte("name: x\n")) {
		t.Error("plain yaml should not be detected as sops")
	}
	if !IsSOPS([]byte("name: x\nsops:\n  version: 3.x\n")) {
		t.Error("sops yaml should be detected")
	}
	if !IsSOPS([]byte("sops:\n  version: 3.x\n")) {
		t.Error("sops at start should be detected")
	}
}
