package payload

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload/c8yissuer"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// IssuerConfig selects which c8yissuer.Issuer implementation backs the
// Cumulocity provider. Mode values:
//
//	"local"  — talk to Cumulocity directly. Reads credentials from
//	           CredentialsFile (mode 0600). The ZTP server then holds C8Y
//	           credentials in the same blast radius as the signing key.
//
//	"remote" — talk to a separate `ztp-c8y-issuer` sidecar over mTLS.
//	           The ZTP server holds NO Cumulocity credentials. Recommended
//	           for production.
//
//	"static" — return a fixed token. INSECURE; tests / local dev only.
//
//	""       — disable token minting entirely. The Cumulocity provider then
//	           emits a module with url/tenant only and the device must obtain
//	           its enrollment token by some out-of-band mechanism.
type IssuerConfig struct {
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// Local-mode fields.
	BaseURL         string `yaml:"base_url,omitempty" json:"base_url,omitempty"`
	Tenant          string `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	CredentialsFile string `yaml:"credentials_file,omitempty" json:"credentials_file,omitempty"`

	// Remote-mode fields.
	Endpoint       string `yaml:"endpoint,omitempty" json:"endpoint,omitempty"`
	ClientCertFile string `yaml:"client_cert,omitempty" json:"client_cert,omitempty"`
	ClientKeyFile  string `yaml:"client_key,omitempty" json:"client_key,omitempty"`
	CACertFile     string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`

	// Static-mode field. INSECURE. The package logs a warning when used.
	StaticToken string `yaml:"static_token,omitempty" json:"static_token,omitempty" ztp:"sensitive"`
}

// Cumulocity emits a c8y.v2 (INI) module containing connection
// details and (when an Issuer is configured) a freshly-minted,
// per-device enrollment token. Modules carrying a token are flagged
// Sensitive, which causes the engine to seal them with the device's
// ephemeral X25519 key before signing the bundle. The plaintext token only
// ever exists in:
//
//   - the Issuer's HTTP response (in transit, TLS-protected)
//   - this provider's local stack frame (cleared at the end of Build)
//   - the device's RAM (after unsealing in the agent)
//
// In particular: signed bundle JSON, server logs, audit records, persisted
// store rows, reverse proxy access logs, and any BLE relay see only
// ciphertext.
type Cumulocity struct {
	URL              string       `yaml:"url,omitempty" json:"url,omitempty"`
	Tenant           string       `yaml:"tenant,omitempty" json:"tenant,omitempty"`
	ExternalIDPrefix string       `yaml:"external_id_prefix,omitempty" json:"external_id_prefix,omitempty"`
	DeviceIDPrefix   string       `yaml:"device_id_prefix,omitempty" json:"device_id_prefix,omitempty"` // legacy alias for ExternalIDPrefix
	TokenTTL         duration     `yaml:"token_ttl,omitempty" json:"token_ttl,omitempty"`
	Issuer           IssuerConfig `yaml:"issuer,omitempty" json:"issuer"`

	// resolved at startup by ResolveIssuer; not loaded from YAML.
	issuer c8yissuer.Issuer
	logger *slog.Logger
}

func (Cumulocity) Name() string { return "cumulocity" }

// ResolveIssuer constructs the Issuer implementation selected by Issuer.Mode
// and stores it on the provider. Call this once at server startup, after
// loading the config and before serving requests. Returns an error early so
// misconfiguration is caught before the first device contacts the server.
//
// As a convenience, the provider's URL and Tenant also fall back to the
// standard go-c8y environment variables (C8Y_BASEURL / C8Y_URL / C8Y_HOST,
// C8Y_TENANT) when they are unset in the YAML. This makes the docker-compose
// + go-c8y-cli session workflow zero-config: just declare an empty
// `cumulocity: { issuer: { mode: local } }` block.
func (c *Cumulocity) ResolveIssuer(logger *slog.Logger) error {
	if c == nil {
		return nil
	}
	c.logger = logger
	if c.logger == nil {
		c.logger = slog.Default()
	}
	// Fall back to env for URL / Tenant so go-c8y-cli sessions Just Work.
	if c.URL == "" {
		c.URL = firstNonEmpty(os.Getenv("C8Y_BASEURL"), os.Getenv("C8Y_URL"), os.Getenv("C8Y_HOST"))
	}
	if c.Tenant == "" {
		c.Tenant = os.Getenv("C8Y_TENANT")
	}
	switch strings.ToLower(strings.TrimSpace(c.Issuer.Mode)) {
	case "":
		c.logger.Warn("cumulocity provider: no issuer configured; emitted modules will not contain an enrollment token")
		return nil
	case "local":
		// Credential resolution (file vs env) and reachability are entirely
		// the issuer's concern. We just attempt to construct it; on any
		// failure (no creds, can't reach c8y, bad creds, …), soft-degrade so
		// the rest of the stack stays up. The c8y provider then emits modules
		// without an enrollment token, just like mode="".
		iss, err := c8yissuer.NewLocalIssuer(c8yissuer.LocalConfig{
			BaseURL:         firstNonEmpty(c.Issuer.BaseURL, c.URL),
			Tenant:          firstNonEmpty(c.Issuer.Tenant, c.Tenant),
			CredentialsFile: c.Issuer.CredentialsFile,
			Logger:          c.logger.With("component", "c8yissuer.local"),
		})
		if err != nil {
			c.logger.Warn("cumulocity issuer: skipping (cumulocity unreachable or not configured); c8y modules will be emitted without an enrollment token", "err", err)
			return nil
		}
		c.issuer = iss
		// Pull URL / tenant back from the live client so the bundle modules
		// reflect what the issuer actually authenticated against.
		if c.URL == "" {
			c.URL = iss.BaseURL()
		}
		if c.Tenant == "" {
			c.Tenant = iss.TenantName()
		}
	case "remote":
		iss, err := c8yissuer.NewRemoteIssuer(c8yissuer.RemoteConfig{
			Endpoint:       c.Issuer.Endpoint,
			ClientCertFile: c.Issuer.ClientCertFile,
			ClientKeyFile:  c.Issuer.ClientKeyFile,
			CACertFile:     c.Issuer.CACertFile,
			Logger:         c.logger.With("component", "c8yissuer.remote"),
		})
		if err != nil {
			return err
		}
		c.issuer = iss
	case "static":
		if c.Issuer.StaticToken == "" {
			return errors.New("cumulocity issuer: mode=static requires static_token")
		}
		c.issuer = c8yissuer.NewStaticIssuer(c.Issuer.StaticToken, time.Duration(c.TokenTTL),
			c.logger.With("component", "c8yissuer.static"))
	default:
		return fmt.Errorf("cumulocity issuer: unknown mode %q", c.Issuer.Mode)
	}
	return nil
}

// SetIssuer is exposed for tests; production code uses ResolveIssuer.
func (c *Cumulocity) SetIssuer(iss c8yissuer.Issuer) { c.issuer = iss }

func (c *Cumulocity) Build(ctx context.Context, device *store.Device) ([]protocol.Module, error) {
	if c.URL == "" {
		return nil, nil
	}

	externalID := externalIDFor(c, device)
	// expiresAt was rendered as an extra v1-only payload field
	// (`expires_at`); v2 carries only the token itself, so we discard
	// the expiry. The token's TTL is still tracked server-side and the
	// device exchanges it for a permanent cert immediately on first
	// boot — long enough that a few seconds of clock drift between
	// here and the device doesn't matter.
	token, _, err := c.mintToken(ctx, externalID)
	if err != nil {
		return nil, fmt.Errorf("cumulocity: mint enrollment token for %s: %w", externalID, err)
	}

	// Per-device override still wins (operator forced a specific token via
	// the admin API). Use case: an operator pre-registered the device in C8Y
	// by hand and wants the bundle to carry exactly that token.
	if device != nil && device.Overrides != nil {
		if v, ok := device.Overrides["c8y_enrollment_token"]; ok {
			if s, ok := v.(string); ok && s != "" {
				token = s
			}
		}
		// Legacy override key.
		if v, ok := device.Overrides["c8y_otp"]; ok {
			if s, ok := v.(string); ok && s != "" {
				token = s
			}
		}
	}

	var sb strings.Builder
	iniSection(&sb, false, "c8y",
		"url", c.URL,
		"tenant", c.Tenant,
		"external_id", externalID,
		"one_time_password", token,
	)
	return []protocol.Module{{
		Type:       "c8y.v2",
		RawPayload: []byte(sb.String()),
		Sensitive:  token != "",
	}}, nil
}

// mintToken delegates to the configured Issuer, or returns an empty token if
// none is wired up (provider becomes informational only).
func (c *Cumulocity) mintToken(ctx context.Context, externalID string) (string, time.Time, error) {
	if c.issuer == nil {
		return "", time.Time{}, nil
	}
	ttl := time.Duration(c.TokenTTL)
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return c.issuer.Mint(ctx, externalID, ttl)
}

// RevokeForDevice is a convenience wrapper used by callers that want to
// proactively invalidate a token (e.g. on bundle delivery failure).
func (c *Cumulocity) RevokeForDevice(ctx context.Context, device *store.Device) error {
	if c == nil || c.issuer == nil {
		return nil
	}
	return c.issuer.Revoke(ctx, externalIDFor(c, device))
}

// externalIDFor derives the C8Y external id for the device, preferring an
// explicit Override, falling back to <prefix>-<device.ID>.
func externalIDFor(c *Cumulocity, d *store.Device) string {
	if d != nil && d.Overrides != nil {
		if v, ok := d.Overrides["c8y_external_id"]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	prefix := c.ExternalIDPrefix
	if prefix == "" {
		prefix = c.DeviceIDPrefix
	}
	if d == nil || d.ID == "" {
		return prefix
	}
	if prefix == "" {
		return d.ID
	}
	return prefix + "-" + d.ID
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

// duration is a YAML- and JSON-friendly time.Duration that accepts strings
// like "10m" or a number-of-seconds integer. It serialises to JSON as a
// human-readable Go duration string (e.g. "10m0s").
type duration time.Duration

func (d *duration) UnmarshalYAML(unmarshal func(any) error) error {
	var s string
	if err := unmarshal(&s); err == nil && s != "" {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = duration(v)
		return nil
	}
	var n int64
	if err := unmarshal(&n); err != nil {
		return err
	}
	*d = duration(time.Duration(n) * time.Second)
	return nil
}

func (d duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		v, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = duration(v)
		return nil
	}
	var n int64
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*d = duration(time.Duration(n) * time.Second)
	return nil
}
