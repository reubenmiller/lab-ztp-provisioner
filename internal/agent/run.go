// Package agent contains the device-side enrollment loop.
package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/appliers"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/clock"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/facts"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/identity"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Config controls one provisioning attempt.
type Config struct {
	ServerURL      string
	DeviceID       string            // if empty, derived from machine-id
	BootstrapToken string            // optional
	ServerPubKey   ed25519.PublicKey // required to verify the bundle
	CACertFile     string            // optional; pins server TLS
	Insecure       bool              // skip TLS verification (dev only)
	// Profile is an optional advisory profile-name hint sent in
	// EnrollRequest.Metadata["profile"]. The server treats it as advisory:
	// any operator-side binding (allowlist/token, sticky persisted name,
	// device override, fact-based selector) wins over it. Empty string =
	// no hint sent.
	Profile string
	// DialAddr is an optional "ip:port" to use for the TCP connection when
	// ServerURL uses a hostname that is not resolvable via system DNS (e.g.
	// a .local mDNS name on a device without nss-mdns). When set, all HTTP
	// requests dial this address but the URL hostname is used for the Host
	// header and TLS SNI, so Caddy virtual-host routing and cert validation
	// both work correctly.
	DialAddr     string
	Identity     identity.Provider
	Dispatcher   *appliers.Dispatcher
	Logger       *slog.Logger
	AgentVersion string
	// Encrypt requests an end-to-end-encrypted bundle (X25519+ChaCha20-Poly1305).
	// Mostly useful when the transport is untrusted (BLE relay).
	Encrypt bool
	// Debug controls bundle-dump behaviour, mirroring the ZTP_DEBUG env variable
	// in the POSIX shell agent.
	//   "1" / "true" / "yes" / "on" — dump the bundle to stderr, then apply it.
	//   "only" / "dump" / "inspect" — dump to stderr, then exit without applying.
	// Empty string (the default) disables all debug output.
	Debug string
	// PendingPoll is how long to wait between retries when the server says
	// our request is pending manual approval.
	PendingPoll time.Duration
	// MaxAttempts caps total enrollment attempts. 0 = unlimited.
	MaxAttempts int
	// MaxNetworkFailures caps the number of consecutive network-level errors
	// (connection refused, timeout, 5xx response, etc.) before Run gives up
	// and returns ErrServerUnreachable. 0 = unlimited (existing behaviour).
	// The outer multi-transport dispatcher uses this to decide whether to try
	// another transport (e.g. BLE) instead of retrying indefinitely.
	MaxNetworkFailures int
	// ClockOffset is added to time.Now() when constructing the EnrollRequest
	// timestamp. It is set automatically when the server returns a ServerTime
	// in a rejection response, allowing devices with unsynced clocks (e.g.
	// before NTP is available) to self-correct and retry.
	ClockOffset time.Duration
	// BLENamePrefix is prepended to the device id when advertising over BLE.
	// Defaults to "ztp-" when empty, giving names like "ztp-<device-id>".
	// Set to a custom string (e.g. "acme-") to brand the peripheral name, or
	// to the empty string "-" sentinel to suppress any prefix.
	BLENamePrefix string
	// SystemClockPolicy controls whether the agent writes the system real-time
	// clock from the verified bundle's IssuedAt before dispatching appliers.
	// Defaults to clock.PolicyAuto (advance-only, gross-offset only) so that
	// downstream TLS NotBefore checks (e.g. tedge cert download c8y) succeed
	// on devices that boot before any time-sync mechanism is available.
	SystemClockPolicy clock.Policy
	// SystemClockThreshold is the minimum |target - now| difference at which
	// SystemClockPolicy will act. 0 means use clock.DefaultThreshold (60 s).
	SystemClockThreshold time.Duration
}

// Run executes the enroll → apply → ack loop until the bundle is applied or
// the context is cancelled. Returns nil on success, an error otherwise.
func Run(ctx context.Context, cfg Config) error {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.PendingPoll == 0 {
		cfg.PendingPoll = 10 * time.Second
	}
	if cfg.Identity == nil {
		return errors.New("identity provider is required")
	}
	if cfg.Dispatcher == nil {
		return errors.New("dispatcher is required")
	}
	if cfg.ServerURL == "" {
		return errors.New("server_url is required")
	}
	if len(cfg.ServerPubKey) == 0 {
		return errors.New("server_pubkey is required (devices must verify bundle signatures)")
	}

	httpClient, err := buildHTTPClient(cfg)
	if err != nil {
		return err
	}

	deviceID, err := resolveDeviceID(cfg.DeviceID)
	if err != nil {
		return fmt.Errorf("device-id: %w", err)
	}
	cfg.Logger.Info("enrolling device", "device_id", deviceID)

	attempts := 0
	netFailures := 0
	clockAdjusted := false
	for {
		attempts++
		if cfg.MaxAttempts > 0 && attempts > cfg.MaxAttempts {
			return fmt.Errorf("exceeded max attempts (%d)", cfg.MaxAttempts)
		}

		// Generate a fresh ephemeral X25519 keypair per attempt. This is
		// always done, regardless of cfg.Encrypt, because the server may seal
		// individual sensitive modules (e.g. a Cumulocity enrollment token)
		// even when the bundle as a whole is delivered in the clear over a
		// trusted transport. The keypair rotates per-attempt so a captured
		// ciphertext stays tied to a single, ephemeral key.
		priv, pub, err := protocol.GenerateX25519()
		if err != nil {
			return fmt.Errorf("generate ephemeral key: %w", err)
		}
		ephPriv := priv
		ephPubB64 := base64.StdEncoding.EncodeToString(pub[:])

		req := buildRequest(deviceID, cfg, ephPubB64)
		env, err := protocol.Sign(req, cfg.Identity.PrivateKey(), "device")
		if err != nil {
			return err
		}
		resp, err := postEnroll(ctx, httpClient, cfg.ServerURL, env)
		if err != nil {
			netFailures++
			cfg.Logger.Warn("enroll request failed", "err", err, "consecutive_failures", netFailures)
			if cfg.MaxNetworkFailures > 0 && netFailures >= cfg.MaxNetworkFailures {
				return fmt.Errorf("server unreachable after %d consecutive network failures: %w", netFailures, ErrServerUnreachable)
			}
			if err := sleepCtx(ctx, cfg.PendingPoll); err != nil {
				return err
			}
			continue
		}
		netFailures = 0 // reset on any successful HTTP response

		// Keep our clock offset in sync with the server on every response.
		if resp.ServerTime != nil {
			cfg.ClockOffset = resp.ServerTime.Sub(time.Now())
		}

		switch resp.Status {
		case protocol.StatusRejected:
			// If the rejection is a clock-skew error and we haven't already
			// self-corrected, adjust the offset (populated above from
			// ServerTime) and retry once immediately with a fresh timestamp.
			if !clockAdjusted && resp.ServerTime != nil &&
				strings.Contains(resp.Reason, "timestamp out of allowed skew") {
				cfg.Logger.Warn("clock skew detected, auto-correcting and retrying",
					"offset", cfg.ClockOffset, "reason", resp.Reason)
				clockAdjusted = true
				continue
			}
			return ErrEnrollRejected{Reason: resp.Reason}
		case protocol.StatusPending:
			cfg.Logger.Info("waiting for manual approval", "reason", resp.Reason)
			delay := cfg.PendingPoll
			if resp.RetryAfter > 0 {
				if hint := time.Duration(resp.RetryAfter) * time.Second; hint < delay {
					delay = hint
				}
			}
			if err := sleepCtx(ctx, delay); err != nil {
				return err
			}
			continue
		case protocol.StatusAccepted:
			signed := resp.Bundle
			if resp.EncryptedBundle != nil {
				if !cfg.Encrypt {
					return errors.New("server returned encrypted bundle but agent did not request encryption")
				}
				plain, err := protocol.OpenForDevice(ephPriv, resp.EncryptedBundle)
				if err != nil {
					return fmt.Errorf("decrypt bundle: %w", err)
				}
				signed = &protocol.SignedEnvelope{}
				if err := json.Unmarshal(plain, signed); err != nil {
					return fmt.Errorf("decode encrypted envelope: %w", err)
				}
			}
			if signed == nil {
				return errors.New("server returned accepted with no bundle")
			}
			payload, err := protocol.Verify(signed, cfg.ServerPubKey)
			if err != nil {
				return fmt.Errorf("verify bundle: %w", err)
			}
			var bundle protocol.ProvisioningBundle
			if err := json.Unmarshal(payload, &bundle); err != nil {
				return fmt.Errorf("decode bundle: %w", err)
			}
			// The bundle's IssuedAt is inside the signed payload, so it
			// carries the same trust as the rest of the bundle. Apply it to
			// the system clock now, before any applier runs, so that
			// downstream TLS validation (e.g. tedge cert download c8y) sees
			// a sane wall time on devices that booted with a stale clock.
			adjustSystemClockFromBundle(cfg, &bundle)
			// Unseal any per-module ciphertexts addressed to our ephemeral
			// key. Sealing is opt-in (server marks individual modules) so
			// most modules pass through untouched.
			if err := unsealModules(&bundle, ephPriv); err != nil {
				return fmt.Errorf("unseal bundle: %w", err)
			}
			// Debug dump — mirrors ZTP_DEBUG behaviour in the POSIX shell agent.
			if cfg.Debug != "" {
				debugDumpBundle(cfg.Logger, &bundle)
				switch cfg.Debug {
				case "only", "dump", "inspect":
					cfg.Logger.Info("debug mode: skipping applier dispatch", "debug", cfg.Debug)
					return nil
				}
			}
			results := cfg.Dispatcher.Apply(ctx, &bundle)
			anyFail := false
			for _, r := range results {
				if !r.OK && !r.Skipped {
					anyFail = true
				}
				cfg.Logger.Info("module applied", "type", r.Type, "ok", r.OK, "skipped", r.Skipped, "error", r.Error)
			}
			if anyFail {
				return fmt.Errorf("one or more modules failed to apply")
			}
			cfg.Logger.Info("provisioning complete", "modules", len(results))
			return nil
		default:
			return fmt.Errorf("unknown status %q", resp.Status)
		}
	}
}

// resolveDeviceID returns the device ID to use for enrollment.
// Precedence: explicit --device-id flag > /etc/device-id > /var/lib/ztp/device-id > tedge-identity command.
// Returns an error when none of the sources yields a non-empty value.
func resolveDeviceID(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	for _, path := range []string{"/etc/device-id", "/var/lib/ztp/device-id"} {
		if b, err := os.ReadFile(path); err == nil {
			if id := strings.TrimSpace(string(b)); id != "" {
				return id, nil
			}
		}
	}
	if out, err := exec.Command("tedge-identity").Output(); err == nil {
		if id := strings.TrimSpace(string(out)); id != "" {
			return id, nil
		}
	}
	return "", errors.New("could not determine device ID: set --device-id, create /etc/device-id, or install tedge-identity")
}

// ResolveDeviceID is the exported counterpart of resolveDeviceID, useful for
// ancillary code paths (e.g. setting the BLE advertised name) that need the
// same precedence rules as Run().
func ResolveDeviceID(configured string) (string, error) {
	return resolveDeviceID(configured)
}

func buildRequest(deviceID string, cfg Config, ephPubB64 string) protocol.EnrollRequest {
	nonce, _ := protocol.NewNonce()
	var metadata map[string]string
	if cfg.Profile != "" {
		metadata = map[string]string{"profile": cfg.Profile}
	}
	return protocol.EnrollRequest{
		ProtocolVersion: protocol.Version,
		Nonce:           nonce,
		Timestamp:       time.Now().UTC().Add(cfg.ClockOffset),
		DeviceID:        deviceID,
		PublicKey:       protocol.EncodePublicKey(cfg.Identity.PublicKey()),
		EphemeralX25519: ephPubB64,
		EncryptBundle:   cfg.Encrypt,
		BootstrapToken:  cfg.BootstrapToken,
		Facts:           facts.Collect(cfg.AgentVersion),
		Capabilities:    []string{"wifi.v2", "ssh.authorized_keys.v2", "c8y.v2", "files.v2", "hook.v2", "passwd.v2"},
		Metadata:        metadata,
	}
}

func buildHTTPClient(cfg Config) (*http.Client, error) {
	// In TOFU mode (no CA cert pinned), skip TLS verification. The provisioning
	// bundle is cryptographically signed, so a MITM delivering a fake bundle
	// will be rejected by bundle signature verification regardless.
	tofu := !cfg.Insecure && cfg.CACertFile == ""
	tlsCfg := &tls.Config{InsecureSkipVerify: cfg.Insecure || tofu} //nolint:gosec
	if cfg.CACertFile != "" {
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ca cert: no PEM blocks found")
		}
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	// When DialAddr is set (e.g. IP from mDNS, hostname not in system DNS),
	// override the dialer so TCP connects to that address. The URL keeps the
	// hostname, so Host header and TLS SNI (derived from the URL) are correct.
	if cfg.DialAddr != "" {
		target := cfg.DialAddr
		baseDialer := &net.Dialer{Timeout: 10 * time.Second}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return baseDialer.DialContext(ctx, network, target)
		}
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: transport,
	}, nil
}

func postEnroll(ctx context.Context, client *http.Client, url string, env *protocol.SignedEnvelope) (*protocol.EnrollResponse, error) {
	body, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("server error %d: %s", resp.StatusCode, string(respBody))
	}
	var er protocol.EnrollResponse
	if err := json.Unmarshal(respBody, &er); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &er, nil
}

// unsealModules decrypts any Module that arrived with a SealedPayload using
// the agent's ephemeral X25519 private key. A "json" sealed payload is
// unmarshalled into Module.Payload; a "raw" sealed payload is restored to
// Module.RawPayload (used when the dispatcher invokes a script applier that
// expects opaque bytes, e.g. an INI document). The Sealed field is cleared
// after a successful unseal so the rest of the pipeline does not see it.
func unsealModules(b *protocol.ProvisioningBundle, devicePriv [32]byte) error {
	for i := range b.Modules {
		m := &b.Modules[i]
		if m.Sealed == nil {
			continue
		}
		plaintext, format, err := protocol.OpenSealedModule(devicePriv, m.Sealed)
		if err != nil {
			return fmt.Errorf("module %s: %w", m.Type, err)
		}
		switch format {
		case "json":
			if len(plaintext) > 0 {
				m.Payload = map[string]any{}
				if err := json.Unmarshal(plaintext, &m.Payload); err != nil {
					return fmt.Errorf("module %s: decode sealed json: %w", m.Type, err)
				}
			}
		case "raw":
			m.RawPayload = plaintext
		default:
			return fmt.Errorf("module %s: unsupported sealed format %q", m.Type, format)
		}
		m.Sealed = nil
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// debugDumpBundle writes a human-readable summary of the provisioning bundle
// to stderr. It mirrors the ZTP_DEBUG dump in the POSIX shell agent.
// Payloads are pretty-printed as JSON; raw payloads are shown as plain text.
func debugDumpBundle(logger *slog.Logger, b *protocol.ProvisioningBundle) {
	fmt.Fprintf(os.Stderr, "=== provisioning bundle (%d modules, device=%s) ===\n",
		len(b.Modules), b.DeviceID)
	for i, m := range b.Modules {
		fmt.Fprintf(os.Stderr, "--- module[%d]: %s ---\n", i, m.Type)
		switch {
		case len(m.RawPayload) > 0:
			fmt.Fprintf(os.Stderr, "%s\n", m.RawPayload)
		case m.Payload != nil:
			pretty, err := json.MarshalIndent(m.Payload, "  ", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "  (marshal error: %v)\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "  %s\n", pretty)
			}
		default:
			fmt.Fprintf(os.Stderr, "  (empty payload)\n")
		}
	}
	fmt.Fprintf(os.Stderr, "=== end bundle ===\n")
}
