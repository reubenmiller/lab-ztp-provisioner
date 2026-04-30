package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadResolvesRelativePathsFromConfigDir(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "cfg")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatalf("mkdir cfg dir: %v", err)
	}

	cfgPath := filepath.Join(cfgDir, "ztp-app.yaml")
	content := "admin_token_file: data/admin.token\n" +
		"signing_key_file: keys/signing.key\n" +
		"age_key_file: keys/age.key\n" +
		"profiles_dir: profiles.d\n" +
		"store:\n" +
		"  driver: sqlite\n" +
		"  dsn: data/ztp.db\n" +
		"tls:\n" +
		"  cert: certs/server.crt\n" +
		"  key: certs/server.key\n" +
		"web:\n" +
		"  dir: web/build\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	assertEqualPath(t, filepath.Join(cfgDir, "data/admin.token"), cfg.AdminTokenFile)
	assertEqualPath(t, filepath.Join(cfgDir, "keys/signing.key"), cfg.SigningKeyFile)
	assertEqualPath(t, filepath.Join(cfgDir, "keys/age.key"), cfg.AgeKeyFile)
	assertEqualPath(t, filepath.Join(cfgDir, "profiles.d"), cfg.ProfilesDir)
	assertEqualPath(t, filepath.Join(cfgDir, "data/ztp.db"), cfg.Store.DSN)
	assertEqualPath(t, filepath.Join(cfgDir, "certs/server.crt"), cfg.TLS.Cert)
	assertEqualPath(t, filepath.Join(cfgDir, "certs/server.key"), cfg.TLS.Key)
	assertEqualPath(t, filepath.Join(cfgDir, "web/build"), cfg.Web.Dir)
}

func TestLoadKeepsSpecialSQLiteDSNsUnchanged(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "ztp-app.yaml")
	content := "store:\n" +
		"  driver: sqlite\n" +
		"  dsn: \":memory:\"\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Store.DSN != ":memory:" {
		t.Fatalf("expected :memory:, got %q", cfg.Store.DSN)
	}

	content = "store:\n" +
		"  driver: sqlite\n" +
		"  dsn: file:ztp.db?mode=rwc\n"
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err = Load(cfgPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Store.DSN != "file:ztp.db?mode=rwc" {
		t.Fatalf("expected file URI DSN to be unchanged, got %q", cfg.Store.DSN)
	}
}

func assertEqualPath(t *testing.T, want, got string) {
	t.Helper()
	if got != want {
		t.Fatalf("path mismatch: want %q, got %q", want, got)
	}
}
