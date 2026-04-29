// Package paths resolves OS-native default locations for the server's
// state files (SQLite database, signing key, age key, TLS cache).
//
// The goal is that `./ztp-server` "just runs" on a clean Windows, macOS,
// or Linux machine without an operator pre-creating any directories or
// pointing at explicit paths in YAML. Every default is rooted in
// os.UserConfigDir():
//
//	Linux:   ~/.config/ztp/
//	macOS:   ~/Library/Application Support/ztp/
//	Windows: %AppData%\ztp\
//
// The functions in this package compute paths only — they never create
// the directory or touch the filesystem. Callers that persist state are
// expected to MkdirAll the parent themselves (typically with mode 0700
// for secret-bearing dirs).
//
// This package is wired in opportunistically: callers fall back to a
// resolved default only when the operator left the corresponding YAML
// field empty, so existing deployments with explicit paths are
// unaffected.
package paths

import (
	"os"
	"path/filepath"
)

// appDirName is the leaf segment of every default path. Kept as a
// constant so renames are a one-line change.
const appDirName = "ztp"

// ConfigDir returns the OS-native config directory for the server,
// e.g. ~/.config/ztp on Linux. Falls back to "./ztp" if
// os.UserConfigDir() fails (which generally means $HOME / %APPDATA%
// is unset — the only sensible recovery is a CWD-relative path).
func ConfigDir() string {
	base, err := os.UserConfigDir()
	if err != nil || base == "" {
		return appDirName
	}
	return filepath.Join(base, appDirName)
}

// DBPath returns the default SQLite DSN. Replaces the historical
// CWD-relative "ztp.db" once the runtime opts into path defaults.
func DBPath() string {
	return filepath.Join(ConfigDir(), "ztp.db")
}

// SigningKeyPath returns the default location for the Ed25519
// server-signing key (base64-encoded private key). Operators can
// still override via signing_key_file in YAML.
func SigningKeyPath() string {
	return filepath.Join(ConfigDir(), "signing.key")
}

// AgeKeyPath returns the default location for the SOPS-age identity
// used to decrypt sealed profile files. Operators can still override
// via age_key_file in YAML.
func AgeKeyPath() string {
	return filepath.Join(ConfigDir(), "age.key")
}

// TLSCacheDir returns the directory under which generated/cached TLS
// material lives — self-signed certs and the autocert cache. Reserved
// for the TLS-mode work in PR 2; defined here so the path layout
// stays in one place.
func TLSCacheDir() string {
	return filepath.Join(ConfigDir(), "tls")
}
