package sqlitestore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

func TestSQLiteStore(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "ztp.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	// device upsert + get
	if err := s.UpsertDevice(ctx, &store.Device{ID: "dev1", PublicKey: "pk1"}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	d, err := s.GetDevice(ctx, "dev1")
	if err != nil || d.PublicKey != "pk1" {
		t.Fatalf("get: %v %#v", err, d)
	}
	if _, err := s.GetDevice(ctx, "missing"); err != store.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// pending lifecycle
	if err := s.CreatePending(ctx, &store.PendingRequest{ID: "p1", DeviceID: "dev2", PublicKey: "pk2", Fingerprint: "fp"}); err != nil {
		t.Fatalf("pending: %v", err)
	}
	if found, err := s.FindPendingByPublicKey(ctx, "pk2"); err != nil || found.ID != "p1" {
		t.Fatalf("find pending: %v %#v", err, found)
	}
	if err := s.DeletePending(ctx, "p1"); err != nil {
		t.Fatalf("delete pending: %v", err)
	}

	// allowlist
	if err := s.AddAllowlist(ctx, store.AllowlistEntry{DeviceID: "dev3", MAC: "aa:bb"}); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if e, err := s.LookupAllowlist(ctx, "dev3"); err != nil || e.MAC != "aa:bb" {
		t.Fatalf("lookup allow: %v %#v", err, e)
	}

	// nonces
	fresh, err := s.RememberNonce(ctx, "n1", time.Minute)
	if err != nil || !fresh {
		t.Fatalf("nonce first: fresh=%v err=%v", fresh, err)
	}
	fresh, err = s.RememberNonce(ctx, "n1", time.Minute)
	if err != nil || fresh {
		t.Fatalf("nonce replay: fresh=%v err=%v", fresh, err)
	}

	// audit
	if err := s.AppendAudit(ctx, store.AuditEntry{Actor: "system", Action: "test"}); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if list, err := s.ListAudit(ctx, 10); err != nil || len(list) != 1 {
		t.Fatalf("audit list: %v %#v", err, list)
	}
}
