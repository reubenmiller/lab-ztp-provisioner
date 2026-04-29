package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// BuildEnrollEnvelope creates and signs a single EnrollRequest envelope for
// the calling device. It returns the raw JSON bytes suitable for handing to a
// BLE relay, plus the ephemeral X25519 private key needed to decrypt any
// sealed module payloads in the server's response.
//
// It mirrors the per-attempt setup in Run but returns the artifacts instead of
// immediately POSTing them over HTTP.
func BuildEnrollEnvelope(cfg Config) (envelopeJSON []byte, ephPriv [32]byte, err error) {
	deviceID, err := resolveDeviceID(cfg.DeviceID)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("device-id: %w", err)
	}
	if cfg.Logger != nil {
		cfg.Logger.Info("enrolling device", "device_id", deviceID)
	}

	priv, pub, err := protocol.GenerateX25519()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("generate ephemeral key: %w", err)
	}
	ephPriv = priv

	req := buildRequest(deviceID, cfg, base64.StdEncoding.EncodeToString(pub[:]))
	env, err := protocol.Sign(req, cfg.Identity.PrivateKey(), "device")
	if err != nil {
		return nil, [32]byte{}, err
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("marshal envelope: %w", err)
	}
	return b, ephPriv, nil
}

// IsRetryableEnrollResponse parses an EnrollResponse JSON and reports whether
// the server response is "rejected" or "pending" — meaning the device should
// regenerate its enrollment envelope (fresh timestamp) and wait for the relay
// to reconnect, rather than terminating.
//
// Returns (true, status, reason, serverTime, nil) for rejected/pending responses.
// Returns (false, status, reason, serverTime, nil) for accepted and unknown statuses.
// Returns (false, "", "", nil, err) when the JSON cannot be parsed.
func IsRetryableEnrollResponse(responseJSON []byte) (retryable bool, status, reason string, serverTime *time.Time, err error) {
	var er protocol.EnrollResponse
	if err = json.Unmarshal(responseJSON, &er); err != nil {
		return false, "", "", nil, fmt.Errorf("decode response: %w", err)
	}
	switch er.Status {
	case protocol.StatusRejected, protocol.StatusPending:
		return true, string(er.Status), er.Reason, er.ServerTime, nil
	}
	return false, string(er.Status), er.Reason, er.ServerTime, nil
}

// ApplyEnrollResponse deserialises the raw JSON bytes returned by the ZTP
// server (as forwarded by a BLE relay), verifies the bundle signature, and
// dispatches the provisioning modules.
//
// Returns nil on successful application. Returns a descriptive error for
// pending / rejected responses so the caller can propagate them back through
// the BLE status characteristic.
func ApplyEnrollResponse(ctx context.Context, cfg Config, ephPriv [32]byte, responseJSON []byte) error {
	var er protocol.EnrollResponse
	if err := json.Unmarshal(responseJSON, &er); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	switch er.Status {
	case protocol.StatusRejected:
		return fmt.Errorf("server rejected enrollment: %s", er.Reason)
	case protocol.StatusPending:
		return fmt.Errorf("enrollment pending manual approval: %s", er.Reason)
	case protocol.StatusAccepted:
		signed := er.Bundle
		if er.EncryptedBundle != nil {
			if !cfg.Encrypt {
				return errors.New("server returned encrypted bundle but -encrypt was not requested")
			}
			plain, err := protocol.OpenForDevice(ephPriv, er.EncryptedBundle)
			if err != nil {
				return fmt.Errorf("decrypt bundle: %w", err)
			}
			signed = &protocol.SignedEnvelope{}
			if err := json.Unmarshal(plain, signed); err != nil {
				return fmt.Errorf("decode encrypted bundle: %w", err)
			}
		}
		if signed == nil {
			return errors.New("server returned accepted with no bundle")
		}
		payload, err := func() ([]byte, error) {
			if len(cfg.ServerPubKey) == 0 {
				cfg.Logger.Warn("no server pubkey — bundle signature verification skipped (TOFU mode); provide --server-pubkey after first enrollment to pin the server key")
				return protocol.DecodePayloadUnverified(signed)
			}
			return protocol.Verify(signed, cfg.ServerPubKey)
		}()
		if err != nil {
			return fmt.Errorf("verify bundle: %w", err)
		}
		var bundle protocol.ProvisioningBundle
		if err := json.Unmarshal(payload, &bundle); err != nil {
			return fmt.Errorf("decode bundle: %w", err)
		}
		// Same as the HTTP path in Run(): the BLE relay can deliver the bundle
		// in seconds whether or not the device's clock has been corrected by
		// TimeSyncUUID first, so always re-anchor the system clock against the
		// signed IssuedAt before any applier validates a TLS NotBefore.
		adjustSystemClockFromBundle(cfg, &bundle)
		if err := unsealModules(&bundle, ephPriv); err != nil {
			return fmt.Errorf("unseal bundle: %w", err)
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
		cfg.Logger.Info("provisioning complete via BLE relay", "modules", len(results))
		return nil
	default:
		return fmt.Errorf("unknown status %q", er.Status)
	}
}
