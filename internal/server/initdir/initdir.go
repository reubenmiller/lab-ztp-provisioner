// Package initdir scaffolds a working ZTP server data directory:
// config YAML, signing key, age key, default profile, and admin token.
//
// Used by both `ztp-server init <dir>` and `ztp-app -init <dir>` so a
// new operator can go from `git clone` (or just an installed binary)
// to a running server with one command. Idempotent: existing files
// are left in place so re-running on a partially-bootstrapped tree
// fills in the gaps without clobbering keys or edited configs.
package initdir

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
)

// Options controls how Scaffold writes the tree.
type Options struct {
	// Dir is the target directory. Created with mode 0700 if missing.
	// All other paths in the scaffolded tree are relative to this.
	Dir string

	// AdminToken, when set, is written verbatim into <Dir>/.env. Empty
	// means generate a fresh 32-byte random token.
	AdminToken string

	// Logger receives info-level "wrote X" / "skipped X (exists)"
	// messages. nil falls back to slog.Default.
	Logger *slog.Logger
}

// Result describes what Scaffold produced. The caller typically prints
// it so the operator knows where keys ended up and what the admin
// token is.
type Result struct {
	Dir            string
	ConfigPath     string // <Dir>/ztp-server.yaml
	AdminTokenFile string // <Dir>/data/admin.token (referenced from the YAML)
	SigningKeyFile string
	SigningPubB64  string
	AgeKeyFile     string
	AgeRecipient   string
	AdminToken     string
	ProfilePath    string // <Dir>/profiles.d/default.yaml

	// Created lists the paths Scaffold actually wrote this run (i.e.
	// excluded files that already existed). Useful for telling the
	// operator which secrets are NEW and need to be redistributed.
	Created []string
	// Skipped lists paths Scaffold left untouched because they were
	// already present.
	Skipped []string
}

// Scaffold creates (or completes) a ZTP data directory tree at
// opts.Dir. Returns the resulting paths and credentials. The function
// is idempotent — re-running it on an existing tree fills in only the
// missing pieces and leaves keys, configs, and profiles intact.
func Scaffold(opts Options) (*Result, error) {
	if opts.Dir == "" {
		return nil, errors.New("initdir: Dir is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	absDir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, fmt.Errorf("resolve dir: %w", err)
	}
	if err := os.MkdirAll(absDir, 0o700); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}
	dataDir := filepath.Join(absDir, "data")
	profilesDir := filepath.Join(absDir, "profiles.d")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(profilesDir, 0o700); err != nil {
		return nil, fmt.Errorf("create profiles dir: %w", err)
	}

	res := &Result{
		Dir:            absDir,
		ConfigPath:     filepath.Join(absDir, "ztp-server.yaml"),
		AdminTokenFile: filepath.Join(dataDir, "admin.token"),
		SigningKeyFile: filepath.Join(dataDir, "signing.key"),
		AgeKeyFile:     filepath.Join(dataDir, "age.key"),
		ProfilePath:    filepath.Join(profilesDir, "default.yaml"),
	}

	track := func(path string, created bool) {
		rel, err := filepath.Rel(absDir, path)
		if err != nil {
			rel = path
		}
		if created {
			res.Created = append(res.Created, rel)
			logger.Info("wrote", "path", rel)
		} else {
			res.Skipped = append(res.Skipped, rel)
			logger.Info("skipped (exists)", "path", rel)
		}
	}

	// Reuse config.LoadOrCreate{Signing,Age}Key — they already do the
	// "create if missing, load if present, persist on creation" dance
	// the runtime relies on. We only need to detect whether they
	// generated or loaded so the operator knows what's new.
	cfg := &config.Config{
		SigningKeyFile: res.SigningKeyFile,
		AgeKeyFile:     res.AgeKeyFile,
	}
	signingExisted := fileExists(res.SigningKeyFile)
	signingKey, err := cfg.LoadOrCreateSigningKey()
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	res.SigningPubB64 = base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey))
	if err := cfg.WritePublicKey(res.SigningPubB64); err != nil {
		return nil, fmt.Errorf("write signing pubkey: %w", err)
	}
	track(res.SigningKeyFile, !signingExisted)

	ageExisted := fileExists(res.AgeKeyFile)
	ageID, err := cfg.LoadOrCreateAgeKey()
	if err != nil {
		return nil, fmt.Errorf("age key: %w", err)
	}
	res.AgeRecipient = ageID.Recipient().String()
	track(res.AgeKeyFile, !ageExisted)

	// Admin token — read existing file if present (idempotent), else
	// mint and persist. The YAML config references this file via
	// admin_token_file so `ztp-server -config …` is fully self-
	// contained: no env var, no shell incantation, no token leakage
	// onto a process command line.
	if data, err := os.ReadFile(res.AdminTokenFile); err == nil {
		res.AdminToken = strings.TrimSpace(string(data))
		track(res.AdminTokenFile, false)
	} else if os.IsNotExist(err) {
		token := opts.AdminToken
		if token == "" {
			token, err = generateAdminToken()
			if err != nil {
				return nil, fmt.Errorf("generate admin token: %w", err)
			}
		}
		if err := os.WriteFile(res.AdminTokenFile, []byte(token+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("write admin token: %w", err)
		}
		res.AdminToken = token
		track(res.AdminTokenFile, true)
	} else {
		return nil, fmt.Errorf("read admin token: %w", err)
	}

	created, err := writeIfMissing(res.ConfigPath, []byte(serverConfigYAML), 0o644)
	if err != nil {
		return nil, fmt.Errorf("write config: %w", err)
	}
	track(res.ConfigPath, created)

	created, err = writeIfMissing(res.ProfilePath, []byte(defaultProfileYAML), 0o644)
	if err != nil {
		return nil, fmt.Errorf("write default profile: %w", err)
	}
	track(res.ProfilePath, created)

	return res, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// writeIfMissing writes data to path with the given mode, but only if
// path doesn't already exist. Returns whether the file was created.
func writeIfMissing(path string, data []byte, mode os.FileMode) (bool, error) {
	if fileExists(path) {
		return false, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return false, err
	}
	return true, os.WriteFile(path, data, mode)
}

func generateAdminToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// serverConfigYAML is the template written to <Dir>/ztp-server.yaml.
// Paths are relative to the directory the file lives in, which is how
// ztp-server resolves them when started with `-config <Dir>/ztp-server.yaml`
// from that directory. For a launch from elsewhere, callers should
// either `cd <Dir>` first or rewrite to absolute paths.
const serverConfigYAML = `# ZTP server configuration — generated by 'ztp-server init'.
# Edit freely; re-running init will not overwrite this file.

listen: ":8080"

# Bearer token for /v1/admin and SPA login. Stored on disk so the
# server can read it without an env var; rotate by overwriting the
# file (mode 0600). The ZTP_ADMIN_TOKEN env var still wins over this
# for container deployments that prefer 12-factor injection.
admin_token_file: "data/admin.token"

# Ed25519 signing key — devices verify provisioning bundles against
# the matching public key (data/signing.key.pub).
signing_key_file: "data/signing.key"
signing_key_id: "ztp-server-1"

# age (X25519) identity used to decrypt SOPS-age sealed profile files.
age_key_file: "data/age.key"

clock_skew: "5m"

verifiers:
  - allowlist
  - bootstrap_token
  - known_keypair

# Persistent SQLite store. Pending requests, allowlist entries, issued
# tokens, and audit log all live here.
store:
  driver: "sqlite"
  dsn: "data/ztp.db"

# File-backed profiles (read-only via the admin UI; edit on disk and
# either restart or POST /v1/admin/profiles/reload).
profiles_dir: "profiles.d"
default_profile: "default"

# Advertise on the LAN as _ztp._tcp so devices running ztp-agent
# without a -server flag discover this server automatically.
mdns:
  enabled: true
`

// defaultProfileYAML is the bare-minimum profile written to
// <Dir>/profiles.d/default.yaml. It only writes a marker file so the
// operator can confirm enrollment end-to-end without first having to
// pick SSH keys / wifi creds / a Cumulocity tenant. Real deployments
// replace this with their own profile (or add new ones alongside).
const defaultProfileYAML = `# Default provisioning profile — generated by 'ztp-server init'.
#
# Used as the fallback when no other selector or assignment matches.
# Edit freely or replace with your own; ` + "`kill -HUP <pid>`" + ` (or
# POST /v1/admin/profiles/reload) picks up changes without a restart.
#
# Common payload modules:
#   ssh:        authorized_keys for a user
#   wifi:       wpa_supplicant networks
#   cumulocity: c8y bootstrap-token issuance
#   files:      arbitrary file drops
#   passwd:     local user/password rotation
#   hook:       a one-shot shell script run on the device

name: default
description: "Minimal default profile — confirms an enrollment by
  dropping a marker file. Replace with real provisioning content."
priority: 0

payload:
  files:
    files:
      - path: /etc/ztp/provisioned.marker
        mode: "0644"
        contents: "provisioned-by-ztp"
`
