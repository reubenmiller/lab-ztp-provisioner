package logging_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/logging"
)

func TestRotatingFile_DoesNotRotateBelowThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	rf, err := logging.OpenRotating(path, 1024, 3)
	if err != nil {
		t.Fatalf("OpenRotating: %v", err)
	}
	defer rf.Close()

	for range 10 {
		if _, err := rf.Write([]byte("small line\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Error("backup .1 should not exist below threshold")
	}
}

func TestRotatingFile_RotatesAtThreshold(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	rf, err := logging.OpenRotating(path, 32, 2)
	if err != nil {
		t.Fatalf("OpenRotating: %v", err)
	}
	defer rf.Close()

	// Each line is 16 bytes; the third line would push over 32 → rotate.
	for range 4 {
		if _, err := rf.Write([]byte("0123456789ABCDE\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// .1 must exist (rotation happened) and .2 must not yet (single rotation).
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected backup .1 to exist after rotation, got: %v", err)
	}
	if _, err := os.Stat(path + ".2"); err == nil {
		t.Error("backup .2 should not exist after a single rotation")
	}
}

func TestRotatingFile_CascadesBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	rf, err := logging.OpenRotating(path, 16, 2)
	if err != nil {
		t.Fatalf("OpenRotating: %v", err)
	}
	defer rf.Close()

	// Force three rotations. After:
	//   - current   = data from rotation 3 (and onwards)
	//   - .1        = data from rotation 2
	//   - .2        = data from rotation 1
	//   - .3        = does not exist (maxBackups=2)
	for range 8 {
		if _, err := rf.Write([]byte("0123456789ABCDE\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	for _, name := range []string{".1", ".2"} {
		if _, err := os.Stat(path + name); err != nil {
			t.Errorf("expected backup %s to exist, got: %v", name, err)
		}
	}
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Error("backup .3 must not exist when maxBackups=2")
	}
}

func TestRotatingFile_DisabledWhenMaxBytesZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	rf, err := logging.OpenRotating(path, 0, 3)
	if err != nil {
		t.Fatalf("OpenRotating: %v", err)
	}
	defer rf.Close()

	for range 1000 {
		if _, err := rf.Write([]byte("filler line content here\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Error("rotation must not happen when maxBytes=0")
	}
}

func TestRotatingFile_TruncatesInPlaceWhenNoBackups(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	rf, err := logging.OpenRotating(path, 32, 0)
	if err != nil {
		t.Fatalf("OpenRotating: %v", err)
	}
	defer rf.Close()

	for range 10 {
		if _, err := rf.Write([]byte("0123456789ABCDE\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// No backup expected; current file capped near maxBytes.
	if _, err := os.Stat(path + ".1"); err == nil {
		t.Error("no backup should be created when maxBackups=0")
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat current: %v", err)
	}
	if st.Size() > 32+16 {
		t.Errorf("current file %d bytes exceeds cap+1 record (~48)", st.Size())
	}
}

func TestRotatingFile_RetainsLatestRecordsAcrossRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")
	rf, err := logging.OpenRotating(path, 32, 1)
	if err != nil {
		t.Fatalf("OpenRotating: %v", err)
	}
	defer rf.Close()

	for range 5 {
		if _, err := rf.Write([]byte("0123456789ABCDE\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	rf.Close()

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read current: %v", err)
	}
	if !strings.Contains(string(current), "0123456789ABCDE") {
		t.Errorf("expected newest line in current file, got: %q", current)
	}
	backup, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatalf("read .1: %v", err)
	}
	if !strings.Contains(string(backup), "0123456789ABCDE") {
		t.Errorf("expected pre-rotation lines in backup, got: %q", backup)
	}
}

// TestRotatingFile_ReopenCountsExistingSize verifies that reopening an
// existing file picks up its size, so a restart in the middle of a busy
// session still rotates on schedule rather than after another full cycle.
func TestRotatingFile_ReopenCountsExistingSize(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.log")

	// Pre-populate the file close to (but under) the cap.
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 25)+"\n"), 0o640); err != nil {
		t.Fatalf("seed: %v", err)
	}
	rf, err := logging.OpenRotating(path, 32, 1)
	if err != nil {
		t.Fatalf("OpenRotating: %v", err)
	}
	defer rf.Close()

	// One more record should now push over the cap and trigger rotation.
	if _, err := rf.Write([]byte("0123456789\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Errorf("expected rotation triggered by inherited size, got: %v", err)
	}
}
