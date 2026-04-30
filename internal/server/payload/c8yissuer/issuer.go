// Package c8yissuer mints per-device Cumulocity enrollment tokens.
//
// The ZTP server itself never holds long-lived Cumulocity credentials; the
// Issuer is the only component that does. Splitting this out as a separate
// interface (and recommending it run as a separate process / container, with
// its own credentials file and its own egress firewall rule) limits the
// blast radius of a ZTP server compromise: an attacker who steals the ZTP
// signing key still cannot mint device requests in your Cumulocity tenant,
// because they do not have the issuer's Cumulocity credentials.
//
// The token returned by Mint is intentionally short-lived and single-use: it
// is consumed by `tedge cert download c8y` on the device, after which the
// device authenticates to Cumulocity with its own X.509 certificate and the
// token is moot.
//
// Three implementations ship with the project:
//
//   - LocalIssuer talks to the Cumulocity REST API in-process. Use this when
//     it is acceptable for the ZTP server to hold Cumulocity credentials
//     (small / single-tenant deployments).
//
//   - RemoteIssuer talks to a separate ztp-c8y-issuer process over mTLS. Use
//     this when separation of duties matters; the ZTP server then holds no
//     Cumulocity credentials at all.
//
//   - StaticIssuer returns a fixed token. INSECURE — for tests and local
//     development only. The package logs a warning when it is constructed.
package c8yissuer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	c8yapi "github.com/reubenmiller/go-c8y/v2/pkg/c8y/api"
	"github.com/reubenmiller/go-c8y/v2/pkg/c8y/api/authentication"
	"github.com/reubenmiller/go-c8y/v2/pkg/c8y/api/devices/registration"
	"github.com/reubenmiller/go-c8y/v2/pkg/c8y/api/tenants/currenttenant"
	"github.com/reubenmiller/go-c8y/v2/pkg/password"
)

// Issuer mints (and optionally revokes) per-device Cumulocity enrollment
// tokens.
//
// Implementations must NOT persist the plaintext token: it should travel only
// from the issuer's HTTP client to the caller (the c8y payload provider) and
// then into the sealed module ciphertext. The issuer may persist a hash of
// the token (e.g. for an audit trail) but never the token itself.
type Issuer interface {
	// Mint creates a fresh single-use enrollment token bound to externalID.
	// ttl is a hint; the issuer is allowed to clamp it to whatever range the
	// underlying API supports.
	Mint(ctx context.Context, externalID string, ttl time.Duration) (token string, expiresAt time.Time, err error)

	// Revoke invalidates a previously-minted token. Best-effort: an issuer
	// that cannot revoke (e.g. once Cumulocity has consumed the OTP) returns
	// nil. Callers should call Revoke when the bundle that carried the token
	// could not be delivered to the device.
	Revoke(ctx context.Context, externalID string) error
}

// HTTPDoer is the minimal subset of *http.Client used by LocalIssuer. It
// exists so tests can swap in a fake without spinning up an HTTP server.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// LocalConfig configures a LocalIssuer.
//
// Two credential-source modes are supported:
//
//  1. CredentialsFile (recommended for production): path to a 0600-mode file
//     with the C8Y credentials. The file is the only place secrets live.
//
//  2. Environment variables (convenient for docker-compose / go-c8y-cli
//     workflows): when CredentialsFile is empty, the issuer falls back to the
//     standard go-c8y env vars — C8Y_BASEURL / C8Y_URL / C8Y_HOST,
//     C8Y_TENANT, C8Y_USERNAME / C8Y_USER, C8Y_PASSWORD. BaseURL on the
//     config still wins over the env when set.
type LocalConfig struct {
	// BaseURL of the Cumulocity tenant, e.g. https://t12345.cumulocity.com.
	// Optional when CredentialsFile is empty AND C8Y_BASEURL / C8Y_URL /
	// C8Y_HOST is set in the environment.
	BaseURL string
	// Tenant is the C8Y tenant id (e.g. "t12345"). Optional — used to build
	// the basic-auth username when CredentialsFile carries only user/pass.
	Tenant string
	// CredentialsFile is a 0600-mode file with the C8Y credentials in
	// "username:password" form, or KEY=VALUE lines (C8Y_USER / C8Y_PASSWORD).
	// When empty, the issuer reads credentials from the standard go-c8y
	// environment variables instead. Keep this file on a tmpfs / mounted
	// secret and do not check it in.
	CredentialsFile string
	// Username and Password allow callers (e.g. desktop keyring-backed flows)
	// to provide credentials in-memory without relying on environment variables
	// or an on-disk credentials file.
	Username string
	Password string
	// Logger is used for non-secret operational logging (token sha256,
	// outcomes). Must never log the plaintext token.
	Logger *slog.Logger
	// TokenLength is the length (in characters) of the generated enrollment
	// OTP. The Cumulocity bulk-registration API accepts 8–32; the default is
	// 32. The token is built from URL-safe ASCII (alphanumerics + a small
	// set of symbols that need no URL encoding), so it can travel through
	// query strings, JSON, and shell args without escaping.
	TokenLength int
}

// LocalIssuer mints OTPs by calling the Cumulocity newDeviceRequests API
// via the go-c8y/v2 SDK.
//
// Wire flow (simplified):
//
//  1. Generate a random URL-safe ASCII token via password.NewRandomPassword
//     (the same generator the SDK uses for DeviceEnrollment.GenerateOneTimePassword).
//  2. POST /devicecontrol/newDeviceRequests with {id: externalID,
//     enrollmentToken: otp} via registration.Service.Create.
//  3. Return otp + expiresAt to the caller.
//
// The function deliberately does not persist otp anywhere on disk. A truncated
// SHA-256 of the token is logged for audit purposes.
type LocalIssuer struct {
	cfg     LocalConfig
	reg     *registration.Service
	baseURL string
	tenant  string
}

// BaseURL returns the resolved Cumulocity base URL the issuer is talking to.
// Useful when the calling provider wants to surface the URL to clients
// without requiring it to be set in YAML separately.
func (l *LocalIssuer) BaseURL() string { return l.baseURL }

// TenantName returns the Cumulocity tenant id the issuer authenticated as,
// as reported by the /tenant/currentTenant probe at startup.
func (l *LocalIssuer) TenantName() string { return l.tenant }

// NewLocalIssuer reads credentials and validates the configuration.
//
// Credential resolution is delegated to the go-c8y SDK:
//
//   - When CredentialsFile is set, credentials come from that file.
//   - Otherwise, the SDK reads them from its standard environment variables
//     (C8Y_HOST/C8Y_BASEURL/C8Y_URL, C8Y_TENANT, C8Y_USER/C8Y_USERNAME,
//     C8Y_PASSWORD, optionally C8Y_TOKEN). The issuer does not pre-validate
//     individual env vars; it just constructs the client and immediately
//     probes /tenant/currentTenant. If the probe fails, the returned error
//     describes the actual failure (network down, 401, missing host, …),
//     which is more useful than a synthetic "FOO env var is unset" message.
func NewLocalIssuer(c LocalConfig) (*LocalIssuer, error) {
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.TokenLength < 8 || c.TokenLength > 32 {
		c.TokenLength = 32
	}

	var client *c8yapi.Client
	if c.CredentialsFile != "" {
		tenant, user, pass, err := readCredentials(c.CredentialsFile, c.Tenant)
		if err != nil {
			return nil, fmt.Errorf("c8yissuer: %w", err)
		}
		baseURL := c.BaseURL
		if baseURL == "" {
			baseURL = authentication.HostFromEnvironment()
		}
		if baseURL == "" {
			return nil, errors.New("c8yissuer: base_url is required when using credentials_file")
		}
		client = c8yapi.NewClient(c8yapi.ClientOptions{
			BaseURL: baseURL,
			Auth:    authentication.AuthOptions{Tenant: tenant, Username: user, Password: pass},
			Timeout: 30 * time.Second,
		})
	} else if c.Username != "" || c.Password != "" {
		if c.Username == "" || c.Password == "" {
			return nil, errors.New("c8yissuer: username and password must both be set when using inline credentials")
		}
		baseURL := c.BaseURL
		if baseURL == "" {
			baseURL = authentication.HostFromEnvironment()
		}
		if baseURL == "" {
			return nil, errors.New("c8yissuer: base_url is required when using inline credentials")
		}
		client = c8yapi.NewClient(c8yapi.ClientOptions{
			BaseURL: baseURL,
			Auth: authentication.AuthOptions{
				Tenant:   c.Tenant,
				Username: c.Username,
				Password: c.Password,
			},
			Timeout: 30 * time.Second,
		})
	} else {
		// Let the SDK pick up host + auth from the standard go-c8y env vars.
		client = c8yapi.NewClientFromEnvironment(c8yapi.ClientOptions{
			Timeout: 30 * time.Second,
		})
		if c.BaseURL != "" {
			// Explicit YAML override still wins.
			client = c8yapi.NewClient(c8yapi.ClientOptions{
				BaseURL: c.BaseURL,
				Auth:    client.Auth,
				Timeout: 30 * time.Second,
			})
		}
	}

	// Probe /tenant/currentTenant to verify the client is actually usable.
	// This catches missing host, missing/invalid credentials, and network
	// failures with a single descriptive error from the server, instead of
	// surfacing them later on the first device enrollment.
	probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	tenantInfo, err := client.Tenants.Current.Get(probeCtx, currenttenant.GetOptions{}).Unwrap()
	if err != nil {
		return nil, fmt.Errorf("c8yissuer: cannot reach cumulocity: %w", err)
	}

	iss := &LocalIssuer{
		cfg:    c,
		reg:    client.Devices.Registration,
		tenant: tenantInfo.Name(),
	}
	if iss.tenant == "" {
		iss.tenant = client.Auth.Tenant
	}
	if client.BaseURL != nil {
		iss.baseURL = strings.TrimRight(client.BaseURL.String(), "/")
	}
	c.Logger.Info("c8yissuer: connected to cumulocity",
		"base_url", iss.baseURL,
		"tenant", iss.tenant,
	)
	return iss, nil
}

// readCredentials accepts either a single "user:password" line or KEY=VALUE
// lines (C8Y_USER, C8Y_PASSWORD, optionally C8Y_TENANT). The file mode is
// checked: the issuer refuses to start if the file is world- or
// group-readable, to fail loud on accidentally committed secrets.
//
// It returns (tenant, user, password). The user value may be a bare username
// or a "tenant/user" form; if the latter, the tenant prefix is split out into
// the returned tenant value.
func readCredentials(path, tenant string) (string, string, string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", "", "", fmt.Errorf("credentials_file: %w", err)
	}
	if mode := st.Mode().Perm(); mode&0o077 != 0 {
		return "", "", "", fmt.Errorf("credentials_file %q has insecure mode %#o (want 0600)", path, mode)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", "", "", err
	}
	body := strings.TrimSpace(string(b))
	if body == "" {
		return "", "", "", errors.New("credentials_file is empty")
	}
	var user, pass string
	// "user:password" form.
	if !strings.ContainsAny(body, "\n=") && strings.Contains(body, ":") {
		u, p, _ := strings.Cut(body, ":")
		user, pass = u, p
	} else {
		// KEY=VALUE form.
		var fileTenant string
		for _, line := range strings.Split(body, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			k, v, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			switch strings.ToUpper(strings.TrimSpace(k)) {
			case "C8Y_USER":
				user = strings.TrimSpace(v)
			case "C8Y_PASSWORD":
				pass = strings.TrimSpace(v)
			case "C8Y_TENANT":
				fileTenant = strings.TrimSpace(v)
			}
		}
		if fileTenant != "" && tenant == "" {
			tenant = fileTenant
		}
	}
	if user == "" || pass == "" {
		return "", "", "", errors.New("credentials_file: C8Y_USER and C8Y_PASSWORD are required")
	}
	// If the username carries a "<tenant>/<user>" prefix, hoist it out.
	if t, u, ok := strings.Cut(user, "/"); ok {
		if tenant == "" {
			tenant = t
		}
		user = u
	}
	return tenant, user, pass, nil
}

// Mint generates a fresh OTP and registers it as a newDeviceRequest in
// Cumulocity via the go-c8y/v2 SDK. The plaintext token is returned to the
// caller and logged ONLY as a SHA-256 prefix.
func (l *LocalIssuer) Mint(ctx context.Context, externalID string, ttl time.Duration) (string, time.Time, error) {
	if externalID == "" {
		return "", time.Time{}, errors.New("c8yissuer: externalID is required")
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	// Mirror the SDK's DeviceEnrollment.GenerateOneTimePassword recipe:
	// URL-safe ASCII (alphanumerics + the URL-unreserved symbols `-_~`),
	// generated with crypto/rand under the hood. The result survives
	// shell/JSON/URL contexts without escaping, which matters because the
	// shell agent ultimately passes the token to `tedge cert download c8y`.
	token, err := password.NewRandomPassword(
		password.WithLengthConstraints(8, 32),
		password.WithLength(l.cfg.TokenLength),
		password.WithUrlCompatibleSymbols(2),
	)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("c8yissuer: generate token: %w", err)
	}

	result := l.reg.Create(ctx, registration.CreateOptions{
		ID:              externalID,
		EnrollmentToken: token,
	})
	if result.IsError() {
		// 422 means a newDeviceRequest already exists for this device ID
		// (e.g. a previous enrollment attempt or the device's own bootstrap).
		// Delete it and retry with our fresh token so the caller always gets
		// a valid, unused OTP that corresponds to what we put in the bundle.
		if isConflict(result.Err) {
			l.cfg.Logger.Info("c8y newDeviceRequest already exists, replacing it", "external_id", externalID)
			if delErr := l.Revoke(ctx, externalID); delErr != nil {
				// Log but proceed — the Create below will surface its own error.
				l.cfg.Logger.Warn("c8y: failed to delete existing newDeviceRequest", "external_id", externalID, "err", delErr)
			}
			result = l.reg.Create(ctx, registration.CreateOptions{
				ID:              externalID,
				EnrollmentToken: token,
			})
		}
	}
	if result.IsError() {
		return "", time.Time{}, fmt.Errorf("c8yissuer: post newDeviceRequests: %w", result.Err)
	}

	expiresAt := time.Now().UTC().Add(ttl)
	l.cfg.Logger.Info("c8y enrollment token minted",
		"external_id", externalID,
		"token_sha256", shortHash(token),
		"expires_at", expiresAt.Format(time.RFC3339),
	)
	return token, expiresAt, nil
}

// Revoke deletes the newDeviceRequest for externalID. Best-effort: a 404 is
// not an error (the v2 SDK Delete already calls IgnoreNotFound internally).
func (l *LocalIssuer) Revoke(ctx context.Context, externalID string) error {
	result := l.reg.Delete(ctx, externalID)
	if result.IsError() {
		return fmt.Errorf("c8yissuer: revoke %s: %w", externalID, result.Err)
	}
	l.cfg.Logger.Info("c8y enrollment token revoked", "external_id", externalID)
	return nil
}

// RemoteConfig configures a RemoteIssuer.
type RemoteConfig struct {
	// Endpoint of the sidecar issuer, e.g. https://issuer.internal:8443.
	Endpoint string
	// ClientCertFile / ClientKeyFile / CACertFile pin the sidecar by mTLS.
	// Plain HTTP is rejected.
	ClientCertFile string
	ClientKeyFile  string
	CACertFile     string
	Logger         *slog.Logger
	HTTPClient     HTTPDoer
}

// RemoteIssuer is a thin client for a sidecar `ztp-c8y-issuer` that owns the
// Cumulocity credentials. The wire format is:
//
//	POST /v1/mint   {external_id, ttl_seconds} → {token, expires_at}
//	POST /v1/revoke {external_id}              → 204
//
// All requests authenticate by mTLS — the sidecar verifies that the ZTP
// server presented a certificate signed by an operator-controlled CA.
type RemoteIssuer struct {
	cfg RemoteConfig
}

// NewRemoteIssuer constructs a RemoteIssuer and validates that mTLS is wired
// up. Plain HTTP is refused on purpose.
func NewRemoteIssuer(c RemoteConfig) (*RemoteIssuer, error) {
	if !strings.HasPrefix(c.Endpoint, "https://") {
		return nil, errors.New("c8yissuer: remote endpoint must be https://")
	}
	if c.ClientCertFile == "" || c.ClientKeyFile == "" {
		return nil, errors.New("c8yissuer: remote requires client_cert / client_key (mTLS)")
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.HTTPClient == nil {
		cert, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("c8yissuer: load client cert: %w", err)
		}
		tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		if c.CACertFile != "" {
			caBytes, err := os.ReadFile(c.CACertFile)
			if err != nil {
				return nil, fmt.Errorf("c8yissuer: load ca cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(caBytes) {
				return nil, errors.New("c8yissuer: ca cert: no PEM blocks")
			}
			tlsCfg.RootCAs = pool
		}
		c.HTTPClient = &http.Client{
			Timeout:   30 * time.Second,
			Transport: &http.Transport{TLSClientConfig: tlsCfg},
		}
	}
	return &RemoteIssuer{cfg: c}, nil
}

type remoteMintResp struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Mint asks the sidecar to mint a token. The token never lives in the ZTP
// server's logs (the sidecar's logs are the source of truth).
func (r *RemoteIssuer) Mint(ctx context.Context, externalID string, ttl time.Duration) (string, time.Time, error) {
	body, _ := json.Marshal(map[string]any{
		"external_id": externalID,
		"ttl_seconds": int(ttl / time.Second),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(r.cfg.Endpoint, "/")+"/v1/mint",
		bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("c8yissuer: remote mint: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		return "", time.Time{}, fmt.Errorf("c8yissuer: remote mint: %d %s", resp.StatusCode, strings.TrimSpace(string(rb)))
	}
	var out remoteMintResp
	if err := json.Unmarshal(rb, &out); err != nil {
		return "", time.Time{}, fmt.Errorf("c8yissuer: remote mint decode: %w", err)
	}
	r.cfg.Logger.Info("c8y enrollment token minted (remote)",
		"external_id", externalID,
		"token_sha256", shortHash(out.Token),
	)
	return out.Token, out.ExpiresAt, nil
}

// Revoke asks the sidecar to revoke a previously-minted token.
func (r *RemoteIssuer) Revoke(ctx context.Context, externalID string) error {
	body, _ := json.Marshal(map[string]any{"external_id": externalID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(r.cfg.Endpoint, "/")+"/v1/revoke",
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := r.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	rb, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("c8yissuer: remote revoke: %d %s", resp.StatusCode, strings.TrimSpace(string(rb)))
}

// StaticIssuer is an INSECURE issuer for tests / local development. It
// returns a configured fixed token regardless of externalID. NEVER use this
// in production: there is no per-device binding, and the token does not get
// registered with Cumulocity.
type StaticIssuer struct {
	Token  string
	TTL    time.Duration
	Logger *slog.Logger
}

// NewStaticIssuer constructs a StaticIssuer and emits a loud warning so the
// fact of its use ends up in the operator log.
func NewStaticIssuer(token string, ttl time.Duration, log *slog.Logger) *StaticIssuer {
	if log == nil {
		log = slog.Default()
	}
	log.Warn("c8yissuer: using StaticIssuer — INSECURE; do not use in production")
	return &StaticIssuer{Token: token, TTL: ttl, Logger: log}
}

func (s *StaticIssuer) Mint(_ context.Context, externalID string, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = s.TTL
	}
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	s.Logger.Info("c8y enrollment token minted (static)",
		"external_id", externalID,
		"token_sha256", shortHash(s.Token),
	)
	return s.Token, time.Now().UTC().Add(ttl), nil
}

func (s *StaticIssuer) Revoke(_ context.Context, _ string) error { return nil }

// shortHash returns a 16-hex-char prefix of SHA-256(token), enough to
// disambiguate audit log entries without leaking the token. We never log the
// plaintext.
func shortHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:8])
}

// isConflict reports whether err represents an HTTP 409 or 422 "already
// exists" response from Cumulocity. The go-c8y/v2 SDK wraps these as
// plain strings, so we check the stringified error.
func isConflict(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "[409]") || strings.Contains(s, "[422]")
}
