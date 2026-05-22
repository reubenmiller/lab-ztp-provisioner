//go:build zenoh

package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/facts"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/discovery"
	zdiscovery "github.com/thin-edge/tedge-zerotouch-provisioning/internal/discovery/zenoh"
)

func init() {
	zenohDiscoveryRunner = runZenohDiscovery
}

// zenohDiscoveryRunner is set by init() on zenoh builds.
var zenohDiscoveryRunner func(ctx context.Context, cfg agent.Config, routerURL string, logger *slog.Logger) error

// runZenohDiscovery publishes a discovery beacon over Zenoh, waits for server
// approval, then delegates to agent.Run with the discovered HTTPS server URL.
func runZenohDiscovery(ctx context.Context, cfg agent.Config, routerURL string, logger *slog.Logger) error {
	deviceID, err := agent.ResolveDeviceID(cfg.DeviceID)
	if err != nil {
		return fmt.Errorf("zenoh discovery: resolve device ID: %w", err)
	}

	pubKeyB64 := base64.StdEncoding.EncodeToString(cfg.Identity.PublicKey())

	// Advertise all transports the device is capable of so the operator can
	// see which discovery channels are available (e.g. both LAN and BLE).
	beaconTransports := []string{"lan"}
	if bleCapable {
		beaconTransports = append(beaconTransports, "ble")
	}

	beacon := discovery.BeaconPayload{
		DeviceID:   deviceID,
		PublicKey:  pubKeyB64,
		Facts:      facts.Collect(cfg.AgentVersion),
		Transports: beaconTransports,
		IssuedAt:   time.Now().UTC(),
	}

	disc := &zdiscovery.AgentDiscoverer{
		RouterURL: routerURL,
		Logger:    logger,
	}

	logger.Info("zenoh discovery: publishing beacon", "device", deviceID, "router", routerURL)
	serverURL, err := disc.Discover(ctx, beacon)
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("zenoh discovery: %w", err)
	}

	logger.Info("zenoh discovery: server approved, enrolling via HTTP", "server_url", serverURL)
	cfg.ServerURL = serverURL
	cfg.DeviceID = deviceID

	return agent.Run(ctx, cfg)
}
