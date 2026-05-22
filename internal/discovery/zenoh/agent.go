//go:build zenoh

package zenoh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	zc "github.com/eclipse-zenoh/zenoh-go/zenoh"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/discovery"
)

// AgentDiscoverer connects to a Zenoh router, publishes a discovery beacon so
// the ZTP server can surface the device in its admin UI, and then waits until
// an operator approves the device.  On approval the server publishes an
// [discovery.ApprovalPayload] carrying the HTTPS URL the agent should use for
// the subsequent standard enrollment call.
//
// The flow is non-blocking from the Zenoh perspective: the beacon is published
// immediately, then re-published every BeaconInterval (default 30 s) until
// either an approval is received or the context is cancelled.
type AgentDiscoverer struct {
	// RouterURL is the Zenoh router endpoint in zenoh format, e.g.
	// "tcp/localhost:7447".  When empty the default Zenoh scouting is used.
	RouterURL string

	// BeaconInterval is how often the discovery beacon is re-published.
	// Defaults to 30 s when zero.
	BeaconInterval time.Duration

	// Logger is used for informational and error messages.  When nil a
	// no-op slog.Logger is used.
	Logger *slog.Logger
}

func (a *AgentDiscoverer) logger() *slog.Logger {
	if a.Logger != nil {
		return a.Logger
	}
	return slog.Default()
}

func (a *AgentDiscoverer) beaconInterval() time.Duration {
	if a.BeaconInterval > 0 {
		return a.BeaconInterval
	}
	return 30 * time.Second
}

// Discover publishes the beacon and blocks until the server approves the
// device (returning the server URL), or until ctx is cancelled.
func (a *AgentDiscoverer) Discover(ctx context.Context, beacon discovery.BeaconPayload) (string, error) {
	cfg := zc.NewConfigDefault()
	if a.RouterURL != "" {
		endpointsJSON := fmt.Sprintf(`["%s"]`, a.RouterURL)
		if err := cfg.InsertJson5(zc.ConfigConnectKey, endpointsJSON); err != nil {
			return "", fmt.Errorf("zenoh: set connect endpoint: %w", err)
		}
	}

	session, err := zc.Open(cfg, nil)
	if err != nil {
		return "", fmt.Errorf("zenoh: open session: %w", err)
	}
	defer session.Drop()

	// Subscribe to the approval topic BEFORE publishing the beacon so we
	// cannot miss an instant response.
	approveKey, err := zc.NewKeyExpr(discovery.ApproveTopic(beacon.DeviceID))
	if err != nil {
		return "", fmt.Errorf("zenoh: approval key expr: %w", err)
	}

	approvalCh := make(chan string, 1) // buffers the approved server URL

	sub, err := session.DeclareSubscriber(approveKey, zc.Closure[zc.Sample]{
		Call: func(sample zc.Sample) {
			var payload discovery.ApprovalPayload
			if jsonErr := json.Unmarshal(sample.Payload().Bytes(), &payload); jsonErr != nil {
				a.logger().Error("zenoh: parse approval payload", "err", jsonErr)
				return
			}
			if payload.ServerURL == "" {
				a.logger().Warn("zenoh: approval payload has no server_url", "device", payload.DeviceID)
				return
			}
			select {
			case approvalCh <- payload.ServerURL:
				a.logger().Info("zenoh: approval received", "device", payload.DeviceID, "server_url", payload.ServerURL)
			default:
			}
		},
	}, nil)
	if err != nil {
		return "", fmt.Errorf("zenoh: declare subscriber: %w", err)
	}
	defer sub.Drop()

	beaconJSON, err := json.Marshal(beacon)
	if err != nil {
		return "", fmt.Errorf("zenoh: marshal beacon: %w", err)
	}

	reqKey, err := zc.NewKeyExpr(discovery.RequestTopic(beacon.DeviceID))
	if err != nil {
		return "", fmt.Errorf("zenoh: request key expr: %w", err)
	}

	publish := func() {
		if putErr := session.Put(reqKey, zc.NewZBytesFromString(string(beaconJSON)), nil); putErr != nil {
			a.logger().Warn("zenoh: publish beacon failed", "err", putErr)
		} else {
			a.logger().Debug("zenoh: beacon published", "topic", discovery.RequestTopic(beacon.DeviceID))
		}
	}

	// Publish immediately.
	publish()

	ticker := time.NewTicker(a.beaconInterval())
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case serverURL := <-approvalCh:
			return serverURL, nil
		case <-ticker.C:
			publish()
		}
	}
}
