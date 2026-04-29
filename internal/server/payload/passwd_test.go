package payload

import (
	"context"
	"strings"
	"testing"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

func TestPasswdBuild(t *testing.T) {
	p := &Passwd{
		Users: []PasswdUser{{Name: "alice", Password: "secret"}},
	}
	mods, err := p.Build(context.Background(), &store.Device{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 module, got %d", len(mods))
	}
	if mods[0].Type != "passwd.v2" {
		t.Errorf("expected module type passwd.v2, got %s", mods[0].Type)
	}
	got := string(mods[0].RawPayload)
	if !strings.Contains(got, "name=alice") {
		t.Errorf("expected INI to contain name=alice, got: %q", got)
	}
	if !strings.Contains(got, "password=secret") {
		t.Errorf("expected INI to contain password=secret, got: %q", got)
	}
}

func TestPasswdBuildEmpty(t *testing.T) {
	mods, err := (&Passwd{}).Build(context.Background(), &store.Device{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mods) != 0 {
		t.Errorf("expected 0 modules for empty users, got %d", len(mods))
	}
}

func TestPasswdBuildMultipleUsers(t *testing.T) {
	p := &Passwd{
		Users: []PasswdUser{
			{Name: "alice", Password: "s3cr3t"},
			{Name: "bob", Password: "p@ssw0rd"},
		},
	}
	mods, err := p.Build(context.Background(), &store.Device{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mods) != 1 {
		t.Fatalf("expected 1 module, got %d", len(mods))
	}
	got := string(mods[0].RawPayload)
	for _, want := range []string{"name=alice", "password=s3cr3t", "name=bob", "password=p@ssw0rd"} {
		if !strings.Contains(got, want) {
			t.Errorf("expected INI to contain %q, got: %q", want, got)
		}
	}
}
