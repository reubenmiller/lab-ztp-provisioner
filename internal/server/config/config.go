// Package config loads server configuration from YAML.
package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
	"gopkg.in/yaml.v3"
)

// Config is the YAML-loaded server configuration.
type Config struct {
	Listen     string    `yaml:"listen"` // e.g. ":8443"
	TLS        TLSConfig `yaml:"tls"`
	AdminToken string    `yaml:"admin_token"` // bearer token for /v1/admin (inline; takes precedence over file/env)
	// AdminTokenFile is a path to a file whose first non-empty line is
	// the bearer token. Mirrors signing_key_file / age_key_file: makes
	// the token easy to source from Docker secrets (mounted at
	// /run/secrets/…), `ztp-server init` (writes data/admin.token),
	// or any other secret-management tool. Resolved AFTER inline
	// admin_token but BEFORE the ZTP_ADMIN_TOKEN env var.
	AdminTokenFile string `yaml:"admin_token_file"`
	SigningKey     string `yaml:"signing_key"`      // base64 Ed25519 priv (inline; takes precedence over file)
	SigningKeyFile string `yaml:"signing_key_file"` // path to a base64 Ed25519 priv key; created on first start
	SigningKeyID   string `yaml:"signing_key_id"`

	// AgeKey is the inline AGE-SECRET-KEY-… string used to decrypt
	// SOPS-age sealed profile files. Takes precedence over AgeKeyFile.
	// Generated automatically on first start if neither is provided.
	AgeKey string `yaml:"age_key"`
	// AgeKeyFile is the on-disk location of the server's age private
	// key. Created with mode 0600 on first start when no key material
	// is otherwise configured. The matching public key is written to
	// "<file>.pub" so operators can read it without grepping logs.
	AgeKeyFile string `yaml:"age_key_file"`
	// AgeRecipients is the list of additional age recipients who will
	// be allowed to decrypt files re-sealed by the server (e.g. via a
	// future "rotate" admin endpoint) AND who are exposed via
	// /v1/admin/profiles/encryption-key for ztpctl to seal to. Useful
	// when a team of operators wants to share decryption capability
	// alongside the server's own keypair.
	AgeRecipients []string `yaml:"age_recipients"`

	ClockSkew time.Duration `yaml:"clock_skew"` // max allowed delta between request timestamp and server time (default 5m)
	Verifiers []string      `yaml:"verifiers"`  // ordered list, e.g. ["allowlist","bootstrap_token","known_keypair"]

	// ProfilesDir is the directory of file-backed profile YAML files. When set,
	// every *.yaml/*.yml in the directory is loaded as a profile. File-backed
	// profiles are read-only in the admin UI; operators edit them via git.
	ProfilesDir string `yaml:"profiles_dir"`

	// DefaultProfile names the profile to use when neither the device, the
	// verifier nor a selector picked one. Empty falls back to literal "default".
	DefaultProfile string `yaml:"default_profile"`

	// C8YCredentials is the optional shared credential catalog used by
	// payload.cumulocity.issuer.credential_ref in file-backed and DB-backed
	// profiles. Secrets may be provided inline, via credentials_file, or by
	// an entrypoint-specific external lookup such as the desktop app keyring.
	C8YCredentials map[string]C8YCredential `yaml:"c8y_credentials"`

	Store StoreConfig `yaml:"store"`
	MDNS  MDNSConfig  `yaml:"mdns"`
	Web   WebConfig   `yaml:"web"`
}

// C8YCredential is one named shared credential entry available to
// payload.cumulocity.issuer.credential_ref.
type C8YCredential struct {
	URL             string `yaml:"url,omitempty"`
	Tenant          string `yaml:"tenant,omitempty"`
	Username        string `yaml:"username,omitempty"`
	Password        string `yaml:"password,omitempty"`
	CredentialsFile string `yaml:"credentials_file,omitempty"`
}

// StoreConfig selects the persistence backend.
//
//	driver: "memory" (default; ephemeral, for tests/dev)
//	driver: "sqlite", dsn: "/var/lib/ztp/ztp.db"
type StoreConfig struct {
	Driver string `yaml:"driver"`
	DSN    string `yaml:"dsn"`
}

// MDNSConfig configures DNS-SD advertising on the LAN. When Enabled, the
// server publishes "_ztp._tcp" so agents with no preconfigured URL can
// discover it via standard mDNS/DNS-SD lookups.
type MDNSConfig struct {
	Enabled bool   `yaml:"enabled"`
	Service string `yaml:"service"` // default "_ztp._tcp"
	Port    int    `yaml:"port"`    // default: parsed from Listen

	// When the server runs behind a reverse proxy (e.g. Caddy), the address
	// the server binds to differs from the address clients should connect to.
	// Set these to advertise the proxy's public-facing address instead of the
	// server's own host/port. Any field left empty falls back to the default.
	PublicHost   string `yaml:"public_host"`   // e.g. "ztp.local" or Docker alias "ztp"
	PublicPort   int    `yaml:"public_port"`   // e.g. 443 (Caddy internal) or 8443 (host)
	PublicScheme string `yaml:"public_scheme"` // "https" or "http"; overrides TLS auto-detect
}

// TLSConfig configures the HTTPS listener.
//
// Mode selects the strategy:
//
//	off | "" | plain | http  → plain HTTP (default)
//	cert                     → use Cert + Key paths
//	selfsigned               → autogenerate, cache under paths.TLSCacheDir()
//
// For backwards compatibility with deployments that predate Mode,
// leaving Mode empty while Cert is set is treated as Mode=cert. New
// configs should set Mode explicitly.
type TLSConfig struct {
	Mode string `yaml:"mode"` // off|cert|selfsigned (empty = inferred from Cert)
	Cert string `yaml:"cert"` // path to PEM cert (Mode=cert)
	Key  string `yaml:"key"`  // path to PEM key  (Mode=cert)

	// Hostnames is the optional list of DNS SANs added to a generated
	// self-signed cert (Mode=selfsigned). "localhost" and the system
	// hostname are always included.
	Hostnames []string `yaml:"hostnames"`
}

// WebConfig controls how the embedded admin SPA is served.
//
//	dir       — when set, serve the SPA from this on-disk directory
//	            instead of the embed.FS. Useful for live editing
//	            against a running ztp-server without rebuilding it.
//	disabled  — when true, do not register the SPA at all. The
//	            JSON API at /v1/* is unaffected; / returns 404.
//	            Use when an external HTTP server (Caddy etc.) serves
//	            the SPA and you want a clean separation.
type WebConfig struct {
	Dir      string `yaml:"dir"`
	Disabled bool   `yaml:"disabled"`
}

// PayloadConfig is removed. Built-in provider configuration now lives in
// per-profile YAML files under ProfilesDir. See package profiles.

// Load reads and parses a YAML config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	baseDir := filepath.Dir(path)
	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.resolveRelativePaths(baseDir)
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Store.Driver == "" {
		c.Store.Driver = "memory"
	}
	if c.MDNS.Service == "" {
		c.MDNS.Service = "_ztp._tcp"
	}
	return &c, nil
}

func (c *Config) resolveRelativePaths(baseDir string) {
	c.AdminTokenFile = resolvePath(baseDir, c.AdminTokenFile)
	c.SigningKeyFile = resolvePath(baseDir, c.SigningKeyFile)
	c.AgeKeyFile = resolvePath(baseDir, c.AgeKeyFile)
	c.ProfilesDir = resolvePath(baseDir, c.ProfilesDir)
	c.TLS.Cert = resolvePath(baseDir, c.TLS.Cert)
	c.TLS.Key = resolvePath(baseDir, c.TLS.Key)
	c.Web.Dir = resolvePath(baseDir, c.Web.Dir)

	// SQLite DSN is usually a filesystem path. Keep URI-like and
	// special in-memory DSNs untouched.
	if strings.EqualFold(c.Store.Driver, "sqlite") && isLikelyFilePathDSN(c.Store.DSN) {
		c.Store.DSN = resolvePath(baseDir, c.Store.DSN)
	}
	for name, cred := range c.C8YCredentials {
		cred.CredentialsFile = resolvePath(baseDir, cred.CredentialsFile)
		c.C8YCredentials[name] = cred
	}
}

func resolvePath(baseDir, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Clean(filepath.Join(baseDir, p))
}

func isLikelyFilePathDSN(dsn string) bool {
	if dsn == "" || dsn == ":memory:" {
		return false
	}
	if strings.HasPrefix(strings.ToLower(dsn), "file:") {
		return false
	}
	return true
}

// LoadOrCreateSigningKey returns the Ed25519 signing key, in order of
// preference:
//  1. inline SigningKey (base64) if set,
//  2. SigningKeyFile if it exists,
//  3. otherwise generate a fresh key and persist it to SigningKeyFile (if set).
func (c *Config) LoadOrCreateSigningKey() (ed25519.PrivateKey, error) {
	if c.SigningKey != "" {
		b, err := base64.StdEncoding.DecodeString(c.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("signing_key: %w", err)
		}
		if len(b) != ed25519.PrivateKeySize {
			return nil, errors.New("signing_key: wrong length")
		}
		return ed25519.PrivateKey(b), nil
	}
	if c.SigningKeyFile != "" {
		if b, err := os.ReadFile(c.SigningKeyFile); err == nil {
			dec, err := base64.StdEncoding.DecodeString(string(b))
			if err != nil {
				return nil, fmt.Errorf("signing_key_file: %w", err)
			}
			if len(dec) != ed25519.PrivateKeySize {
				return nil, errors.New("signing_key_file: wrong length")
			}
			return ed25519.PrivateKey(dec), nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	if c.SigningKeyFile != "" {
		if err := os.MkdirAll(filepath.Dir(c.SigningKeyFile), 0o700); err != nil {
			return nil, err
		}
		enc := base64.StdEncoding.EncodeToString(priv)
		if err := os.WriteFile(c.SigningKeyFile, []byte(enc), 0o600); err != nil {
			return nil, fmt.Errorf("write signing_key_file: %w", err)
		}
	}
	return priv, nil
}

// WritePublicKey writes the base64 public key alongside SigningKeyFile (as
// "<key>.pub") for tooling that needs to hand it to devices. No-op when
// SigningKeyFile is empty.
func (c *Config) WritePublicKey(pubB64 string) error {
	if c.SigningKeyFile == "" {
		return nil
	}
	pubPath := c.SigningKeyFile + ".pub"
	return os.WriteFile(pubPath, []byte(pubB64+"\n"), 0o644)
}

// SigningKeyOrGenerate is kept for backwards compatibility with earlier code.
// New callers should prefer LoadOrCreateSigningKey.
func (c *Config) SigningKeyOrGenerate() (ed25519.PrivateKey, error) {
	return c.LoadOrCreateSigningKey()
}

// LoadOrCreateAgeKey returns the server's age identity, in order of
// preference: inline AgeKey, then AgeKeyFile if it exists, otherwise
// generate a fresh X25519 identity and persist it to AgeKeyFile (when
// set). Mirrors LoadOrCreateSigningKey's UX — same auto-bootstrap
// philosophy applies.
//
// The matching recipient (public key) is written to "<file>.pub" with
// mode 0644 so operators can read it without grepping logs and so
// `ztpctl` can fetch it via the admin API.
func (c *Config) LoadOrCreateAgeKey() (*age.X25519Identity, error) {
	if c.AgeKey != "" {
		id, err := age.ParseX25519Identity(strings.TrimSpace(c.AgeKey))
		if err != nil {
			return nil, fmt.Errorf("age_key: %w", err)
		}
		return id, nil
	}
	if c.AgeKeyFile != "" {
		if b, err := os.ReadFile(c.AgeKeyFile); err == nil {
			id, err := age.ParseX25519Identity(strings.TrimSpace(string(b)))
			if err != nil {
				return nil, fmt.Errorf("age_key_file: %w", err)
			}
			return id, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate age key: %w", err)
	}
	if c.AgeKeyFile != "" {
		if err := os.MkdirAll(filepath.Dir(c.AgeKeyFile), 0o700); err != nil {
			return nil, err
		}
		// 0600 because the secret-key string is itself the secret.
		if err := os.WriteFile(c.AgeKeyFile, []byte(id.String()+"\n"), 0o600); err != nil {
			return nil, fmt.Errorf("write age_key_file: %w", err)
		}
		// World-readable pub file so unprivileged tooling can fetch
		// the recipient without escalating.
		pubPath := c.AgeKeyFile + ".pub"
		if err := os.WriteFile(pubPath, []byte(id.Recipient().String()+"\n"), 0o644); err != nil {
			return nil, fmt.Errorf("write age public key: %w", err)
		}
	}
	return id, nil
}

// AgeRecipientsParsed parses AgeRecipients into typed age.Recipient values.
// Errors are aggregated so a single bad entry doesn't drop silently.
func (c *Config) AgeRecipientsParsed() ([]age.Recipient, error) {
	out := make([]age.Recipient, 0, len(c.AgeRecipients))
	for _, s := range c.AgeRecipients {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		r, err := age.ParseX25519Recipient(s)
		if err != nil {
			return nil, fmt.Errorf("age_recipients %q: %w", s, err)
		}
		out = append(out, r)
	}
	return out, nil
}
