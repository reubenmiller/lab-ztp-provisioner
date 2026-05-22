//go:build zenoh

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/discovery"
	zdiscovery "github.com/thin-edge/tedge-zerotouch-provisioning/internal/discovery/zenoh"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/api"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

// startZenohDiscovery starts a Zenoh server discoverer in a background
// goroutine and returns:
//
//   - stop: cancels the discoverer's context; safe to call multiple times.
//   - onApproved: must be assigned to api.Server.OnApproved so the HTTP
//     approve handler can publish approval notifications back to waiting agents.
//
// Returns (nil, nil) when cfg.Enabled is false.
func startZenohDiscovery(
	ctx context.Context,
	cfg config.ZenohConfig,
	serverURL string,
	st store.Store,
	hub *api.Hub,
	logger *slog.Logger,
) (stop func(), onApproved func(context.Context, string)) {
	if !cfg.Enabled {
		return nil, nil
	}

	disc := zdiscovery.NewServerDiscoverer(cfg.ListenAddr, cfg.RouterURL, logger, func(beacon discovery.BeaconPayload) {
		bCtx := context.Background()

		// Refresh an existing pending entry rather than creating a duplicate.
		if existing, findErr := st.FindPendingByPublicKey(bCtx, beacon.PublicKey); findErr == nil && existing != nil {
			existing.LastSeen = time.Now().UTC()
			existing.Facts = beacon.Facts
			existing.Reason = "zenoh-discovery"
			if upsertErr := st.CreatePending(bCtx, existing); upsertErr != nil {
				logger.Error("zenoh: refresh pending entry", "device", beacon.DeviceID, "err", upsertErr)
				return
			}
			if hub != nil {
				go hub.Notify(existing)
			}
			return
		}

		p := &store.PendingRequest{
			ID:          uuid.NewString(),
			DeviceID:    beacon.DeviceID,
			PublicKey:   beacon.PublicKey,
			Facts:       beacon.Facts,
			FirstSeen:   time.Now().UTC(),
			LastSeen:    time.Now().UTC(),
			Fingerprint: pubKeyFingerprint(beacon.PublicKey),
			Reason:      "zenoh-discovery",
		}
		if createErr := st.CreatePending(bCtx, p); createErr != nil {
			logger.Error("zenoh: create pending entry", "device", beacon.DeviceID, "err", createErr)
			return
		}
		_ = st.AppendAudit(bCtx, store.AuditEntry{
			Actor:    "system",
			Action:   "enroll.pending",
			DeviceID: beacon.DeviceID,
			Details:  "discovered via zenoh",
		})
		if hub != nil {
			go hub.Notify(p)
		}
		logger.Info("zenoh: device queued as pending", "device", beacon.DeviceID)
	})

	subCtx, cancel := context.WithCancel(ctx)
	go func() {
		if err := disc.Start(subCtx); err != nil && !errors.Is(err, context.Canceled) {
			logger.Error("zenoh server discovery exited with error", "err", err)
		}
	}()

	approve := func(approveCtx context.Context, deviceID string) {
		if err := disc.Approve(approveCtx, deviceID, serverURL); err != nil {
			logger.Error("zenoh: publish approval notification", "device", deviceID, "err", err)
		}
	}

	logger.Info("zenoh discovery started", "router", cfg.RouterURL)
	return cancel, approve
}

// pubKeyFingerprint returns the first 12 hex characters of the SHA-256 hash of
// the base64-encoded public key string — enough for human comparison in the UI.
// Mirrors the shortFingerprint function in internal/server/engine.go.
func pubKeyFingerprint(pubB64 string) string {
	sum := sha256.Sum256([]byte(pubB64))
	return hex.EncodeToString(sum[:6])
}
