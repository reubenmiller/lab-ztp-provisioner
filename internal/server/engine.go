// Package server contains the Engine that orchestrates an enrollment
// transaction: verify the request signature, run the trust chain, build a
// signed provisioning bundle (or queue a manual approval), and persist the
// outcome to the audit log.
//
// The Engine is transport-agnostic: it consumes EnrollRequests and produces
// EnrollResponses. The HTTPS, mDNS, and BLE relay transports all share this
// implementation.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/profiles"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/trust"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// EngineConfig is everything the engine needs to do its job. Fields are wired
// up by main.go from the YAML config.
type EngineConfig struct {
	Store        store.Store
	Verifiers    trust.Chain
	Resolver     *profiles.Resolver
	SigningKey   ed25519.PrivateKey
	SigningKeyID string
	NonceTTL     time.Duration
	BundleTTL    time.Duration
	ClockSkew    time.Duration
	Logger       *slog.Logger
	OnPending    func(p *store.PendingRequest) // optional notifier (WS push)
}

// Engine processes EnrollRequests. Safe for concurrent use; the underlying
// store is expected to handle its own locking.
type Engine struct {
	cfg EngineConfig
}

// NewEngine constructs an Engine. Required fields: Store, SigningKey,
// SigningKeyID. Verifiers and Providers may be empty (everything will go to
// manual approval, no payloads will be issued).
func NewEngine(cfg EngineConfig) (*Engine, error) {
	if cfg.Store == nil {
		return nil, errors.New("store is required")
	}
	if len(cfg.SigningKey) == 0 {
		return nil, errors.New("signing key is required")
	}
	if cfg.NonceTTL == 0 {
		cfg.NonceTTL = 5 * time.Minute
	}
	if cfg.BundleTTL == 0 {
		cfg.BundleTTL = 24 * time.Hour
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 5 * time.Minute
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.SigningKeyID == "" {
		cfg.SigningKeyID = "server"
	}
	return &Engine{cfg: cfg}, nil
}

// PublicKey returns the server's Ed25519 signing public key. It is safe to
// expose publicly: devices need it to verify the bundles they receive, and
// the operator UI shows it in onboarding instructions.
func (e *Engine) PublicKey() ed25519.PublicKey {
	return e.cfg.SigningKey.Public().(ed25519.PublicKey)
}

// SigningKeyID returns the key identifier embedded in signed envelopes.
func (e *Engine) SigningKeyID() string { return e.cfg.SigningKeyID }

// Enroll is the main entry point. The signedRequest argument is the envelope
// the client posted; the engine verifies it against the public key the client
// claims to own (trust-on-first-use is acceptable here because subsequent
// verifiers decide whether the claim is meaningful).
func (e *Engine) Enroll(ctx context.Context, signedRequest *protocol.SignedEnvelope) (*protocol.EnrollResponse, error) {
	now := time.Now().UTC()
	req, err := e.parseAndVerify(ctx, signedRequest)
	if err != nil {
		_ = e.cfg.Store.AppendAudit(ctx, store.AuditEntry{
			Actor: "system", Action: "enroll.reject", Details: err.Error(),
		})
		return &protocol.EnrollResponse{
			ProtocolVersion: protocol.Version,
			Status:          protocol.StatusRejected,
			Reason:          err.Error(),
			ServerTime:      &now,
		}, nil
	}

	result, _ := e.cfg.Verifiers.Run(ctx, req)
	logger := e.cfg.Logger.With("device_id", req.DeviceID, "verifier", result.Verifier, "decision", string(result.Decision))

	switch result.Decision {
	case trust.Reject:
		logger.Info("enrollment rejected", "reason", result.Reason)
		_ = e.cfg.Store.AppendAudit(ctx, store.AuditEntry{
			Actor: "system", Action: "enroll.reject", DeviceID: req.DeviceID, Details: result.Reason,
		})
		return &protocol.EnrollResponse{
			ProtocolVersion: protocol.Version,
			Status:          protocol.StatusRejected,
			Reason:          result.Reason,
			ServerTime:      &now,
		}, nil

	case trust.Pending:
		if err := e.queuePending(ctx, req, result.Reason); err != nil {
			return nil, err
		}
		// Forget the nonce so the relay can re-submit the same signed envelope
		// once the operator approves the device, without hitting "nonce replay".
		_ = e.cfg.Store.ForgetNonce(ctx, req.Nonce)
		logger.Info("enrollment pending manual approval", "reason", result.Reason)
		return &protocol.EnrollResponse{
			ProtocolVersion: protocol.Version,
			Status:          protocol.StatusPending,
			Reason:          result.Reason,
			RetryAfter:      10,
			ServerTime:      &now,
		}, nil

	case trust.Trust:
		return e.issueBundle(ctx, req, result)
	}
	return nil, fmt.Errorf("unknown decision %q", result.Decision)
}

// parseAndVerify validates the envelope's signature, decodes the request,
// checks freshness and replay protection.
func (e *Engine) parseAndVerify(ctx context.Context, env *protocol.SignedEnvelope) (*protocol.EnrollRequest, error) {
	if env == nil {
		return nil, errors.New("missing signed envelope")
	}
	// We need the public key out of the payload to verify it: peek inside.
	peek, err := decodePayload(env)
	if err != nil {
		return nil, err
	}
	pub, err := protocol.DecodePublicKey(peek.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public key: %w", err)
	}
	canonical, err := protocol.Verify(env, pub)
	if err != nil {
		return nil, err
	}
	// canonical equals the bytes signed; decode again into a typed value.
	var req protocol.EnrollRequest
	if err := unmarshalCanonical(canonical, &req); err != nil {
		return nil, err
	}
	if req.ProtocolVersion != protocol.Version {
		return nil, fmt.Errorf("unsupported protocol version %q", req.ProtocolVersion)
	}
	if req.DeviceID == "" {
		return nil, errors.New("device_id is required")
	}
	now := time.Now()
	if !req.Timestamp.IsZero() {
		if d := now.Sub(req.Timestamp); d > e.cfg.ClockSkew || d < -e.cfg.ClockSkew {
			return nil, fmt.Errorf("request timestamp out of allowed skew (%s)", d.Round(time.Second))
		}
	}
	if req.Nonce == "" {
		return nil, errors.New("nonce is required")
	}
	if fresh, err := e.cfg.Store.RememberNonce(ctx, req.Nonce, e.cfg.NonceTTL); err != nil {
		return nil, fmt.Errorf("nonce store: %w", err)
	} else if !fresh {
		return nil, errors.New("nonce replay")
	}
	return &req, nil
}

func (e *Engine) queuePending(ctx context.Context, req *protocol.EnrollRequest, reason string) error {
	// If we already have a pending entry for this pubkey, just refresh it.
	if existing, err := e.cfg.Store.FindPendingByPublicKey(ctx, req.PublicKey); err == nil && existing != nil {
		existing.LastSeen = time.Now().UTC()
		existing.Facts = req.Facts
		existing.Reason = reason
		if err := e.cfg.Store.CreatePending(ctx, existing); err != nil {
			return err
		}
		return nil
	}
	p := &store.PendingRequest{
		ID:          uuid.NewString(),
		DeviceID:    req.DeviceID,
		PublicKey:   req.PublicKey,
		Facts:       req.Facts,
		FirstSeen:   time.Now().UTC(),
		LastSeen:    time.Now().UTC(),
		Fingerprint: shortFingerprint(req.PublicKey),
		Reason:      reason,
	}
	if err := e.cfg.Store.CreatePending(ctx, p); err != nil {
		return err
	}
	_ = e.cfg.Store.AppendAudit(ctx, store.AuditEntry{
		Actor: "system", Action: "enroll.pending", DeviceID: req.DeviceID, Details: reason,
	})
	if e.cfg.OnPending != nil {
		go e.cfg.OnPending(p)
	}
	return nil
}

func (e *Engine) issueBundle(ctx context.Context, req *protocol.EnrollRequest, result trust.Result) (*protocol.EnrollResponse, error) {
	// Persist / refresh the device record so subsequent contacts are recognised
	// by the known_keypair verifier.
	dev, err := e.cfg.Store.GetDevice(ctx, req.DeviceID)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}
	if dev == nil {
		dev = &store.Device{ID: req.DeviceID, EnrolledAt: time.Now().UTC()}
	}
	dev.PublicKey = req.PublicKey
	dev.Facts = req.Facts
	dev.LastSeen = time.Now().UTC()

	// Resolve the profile for this device. Precedence (handled inside the
	// resolver): per-device override -> persisted profile -> verifier hint ->
	// selector match -> default. If nothing matches we reject rather than
	// quietly issuing an empty bundle.
	var (
		profile       *profiles.Profile
		profileName   string
		profileSource profiles.Source
		registry      payload.Registry
	)
	if e.cfg.Resolver != nil {
		hints := profiles.ResolveHints{
			Profile:          result.Profile,
			PersistedProfile: dev.ProfileName,
			Override:         deviceOverrideProfile(dev),
			// Advisory hint from the device. Honoured only after operator-side
			// bindings (override, persisted, verifier, selector) have all
			// passed -- see resolver precedence chain.
			Requested: req.Metadata["profile"],
		}
		p, err := e.cfg.Resolver.Resolve(ctx, hints, req.Facts)
		if err != nil {
			_ = e.cfg.Store.AppendAudit(ctx, store.AuditEntry{
				Actor: "system", Action: "enroll.reject", DeviceID: req.DeviceID,
				Details: "profile resolve: " + err.Error(),
			})
			rejNow := time.Now().UTC()
			return &protocol.EnrollResponse{
				ProtocolVersion: protocol.Version,
				Status:          protocol.StatusRejected,
				Reason:          err.Error(),
				ServerTime:      &rejNow,
			}, nil
		}
		profile = p
		profileName = p.Name
		profileSource = p.Source
		registry = e.cfg.Resolver.BuildRegistry(p)
	}
	dev.ProfileName = profileName
	if err := e.cfg.Store.UpsertDevice(ctx, dev); err != nil {
		return nil, err
	}

	mods, err := registry.Build(ctx, dev)
	if err != nil {
		return nil, fmt.Errorf("build payloads: %w", err)
	}
	_ = profile // currently only name/source surfaced; full struct kept for future use

	// Seal sensitive modules (e.g. c8y enrollment tokens) per-device so the
	// secret is opaque to everything other than the device itself: the signed
	// bundle persisted in the audit log, any reverse proxy access log, and a
	// BLE relay all see ciphertext only. Sealing requires the device to have
	// presented an ephemeral X25519 key in its EnrollRequest; we refuse to
	// issue a bundle that would leak a sensitive payload on the wire.
	if err := e.sealSensitiveModules(req, mods); err != nil {
		_ = e.cfg.Store.AppendAudit(ctx, store.AuditEntry{
			Actor: "system", Action: "enroll.reject", DeviceID: req.DeviceID,
			Details: "seal sensitive module: " + err.Error(),
		})
		sealNow := time.Now().UTC()
		return &protocol.EnrollResponse{
			ProtocolVersion: protocol.Version,
			Status:          protocol.StatusRejected,
			Reason:          err.Error(),
			ServerTime:      &sealNow,
		}, nil
	}

	bundle := protocol.ProvisioningBundle{
		ProtocolVersion: protocol.Version,
		DeviceID:        req.DeviceID,
		IssuedAt:        time.Now().UTC(),
		ExpiresAt:       time.Now().UTC().Add(e.cfg.BundleTTL),
		Modules:         mods,
	}
	env, err := protocol.Sign(bundle, e.cfg.SigningKey, e.cfg.SigningKeyID)
	if err != nil {
		return nil, err
	}
	textEnv, err := protocol.SignTextManifest(&bundle, e.cfg.SigningKey, e.cfg.SigningKeyID)
	if err != nil {
		return nil, fmt.Errorf("sign text manifest: %w", err)
	}
	issuedAt := time.Now().UTC()
	resp := &protocol.EnrollResponse{
		ProtocolVersion: protocol.Version,
		Status:          protocol.StatusAccepted,
		Bundle:          env,
		TextManifest:    textEnv,
		ServerTime:      &issuedAt,
	}
	// If the device asked for whole-bundle encryption (e.g. transport is an
	// untrusted BLE relay) we wrap the SignedEnvelope in an
	// EncryptedPayload. Per-module sealing has already happened above; this
	// is independent and additive.
	if req.EncryptBundle && req.EphemeralX25519 != "" {
		envJSON, err := json.Marshal(env)
		if err != nil {
			return nil, fmt.Errorf("marshal envelope: %w", err)
		}
		enc, err := protocol.SealForDevice(req.EphemeralX25519, envJSON)
		if err != nil {
			return nil, fmt.Errorf("seal bundle: %w", err)
		}
		resp.EncryptedBundle = enc
		resp.Bundle = nil // when encryption is requested only encrypted form is returned
	}
	// Surface the device's advisory profile hint in the audit log so an
	// operator can see when the device asked for one profile but server-side
	// resolution picked a different one (e.g. allowlist binding overrode the
	// hint, or the requested profile was unknown). Only included when the
	// device actually supplied a hint, to keep the common case quiet.
	requestedDetail := ""
	if r := req.Metadata["profile"]; r != "" {
		if r == profileName {
			requestedDetail = fmt.Sprintf(" requested=%s requested_honoured=true", r)
		} else {
			requestedDetail = fmt.Sprintf(" requested=%s requested_honoured=false", r)
		}
	}
	_ = e.cfg.Store.AppendAudit(ctx, store.AuditEntry{
		Actor: "system", Action: "enroll.accept", DeviceID: req.DeviceID,
		Details: fmt.Sprintf("verifier=%s reason=%s profile=%s profile_source=%s modules=%d encrypted=%t%s",
			result.Verifier, result.Reason, profileName, profileSource, len(mods), resp.EncryptedBundle != nil, requestedDetail),
	})
	return resp, nil
}

func shortFingerprint(pubB64 string) string {
	sum := sha256.Sum256([]byte(pubB64))
	return hex.EncodeToString(sum[:6]) // 12 hex chars; enough for human comparison
}

// sealSensitiveModules walks the module list and replaces the plaintext
// payload of any module flagged Sensitive with a SealedPayload addressed to
// the device's ephemeral X25519 key. The plaintext is zeroed before return so
// it does not linger on the heap longer than necessary.
//
// Modules with no Sensitive flag are left untouched. If any sensitive module
// is encountered without a device ephemeral key the function returns an error
// and the engine rejects the enrollment — refusing to issue is safer than
// leaking the secret in clear text.
func (e *Engine) sealSensitiveModules(req *protocol.EnrollRequest, mods []protocol.Module) error {
	for i := range mods {
		if !mods[i].Sensitive {
			continue
		}
		if req.EphemeralX25519 == "" {
			return fmt.Errorf("module %s carries a sensitive payload but device did not provide ephemeral_x25519", mods[i].Type)
		}
		var (
			plaintext []byte
			format    string
		)
		switch {
		case mods[i].RawPayload != nil:
			plaintext = mods[i].RawPayload
			format = "raw"
		default:
			canon, err := protocol.Canonicalize(mods[i].Payload)
			if err != nil {
				return fmt.Errorf("canonicalize %s: %w", mods[i].Type, err)
			}
			plaintext = canon
			format = "json"
		}
		sealed, err := protocol.SealModuleForDevice(req.EphemeralX25519, plaintext, format)
		if err != nil {
			return fmt.Errorf("seal %s: %w", mods[i].Type, err)
		}
		// Best-effort scrub. Note that mods[i].Payload also held the secret
		// inside a map[string]any; clearing the map prevents it being marshalled
		// alongside the Sealed envelope.
		for k := range plaintext {
			plaintext[k] = 0
		}
		mods[i].Payload = nil
		mods[i].RawPayload = nil
		mods[i].Sealed = sealed
	}
	return nil
}

// deviceOverrideProfile returns an explicit per-device profile override stored
// in dev.Overrides under the well-known "_profile" key, or "" if none.
func deviceOverrideProfile(dev *store.Device) string {
	if dev == nil || dev.Overrides == nil {
		return ""
	}
	if v, ok := dev.Overrides["_profile"]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
