//go:build zenoh

package zenoh

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	zc "github.com/eclipse-zenoh/zenoh-go/zenoh"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/discovery"
)

// ServerDiscoverer subscribes to device discovery beacons on a Zenoh router
// and publishes approval notifications once an operator has approved a device.
//
// The server can operate in two modes:
//
//   - Router mode (ListenAddr set): the ZTP server is the Zenoh router.
//     Agents connect directly to this address; no separate router process
//     is required.
//   - Client mode (RouterURL set or both empty): the server connects to an
//     external Zenoh router.  Empty means default peer-discovery scouting.
//
// Typical lifecycle:
//
//  1. Call [NewServerDiscoverer] and wire the onDiscovered callback to the
//     server's store (create a pending record + notify the SSE hub).
//  2. Call [Start] in a goroutine — it blocks until ctx is cancelled.
//  3. Call [Approve] from the HTTP approve handler after the store has been
//     updated.
type ServerDiscoverer struct {
	routerURL    string
	listenAddr   string
	logger       *slog.Logger
	onDiscovered func(discovery.BeaconPayload)

	mu      sync.Mutex
	session *zc.Session
}

// NewServerDiscoverer creates a ServerDiscoverer ready to be started.
//
//   - listenAddr, when non-empty, makes the ZTP server act as a Zenoh router
//     (mode=router) on that address, e.g. "tcp/0.0.0.0:7447".  Takes
//     precedence over routerURL.
//   - routerURL is the Zenoh router endpoint to connect to when an external
//     router is preferred.  Empty string uses Zenoh default scouting.
//   - logger is the structured logger; nil falls back to slog.Default().
//   - onDiscovered is called for every valid beacon that arrives on the
//     discovery topic.  It is invoked from the Zenoh callback goroutine, so
//     it must be safe for concurrent use.
func NewServerDiscoverer(
	listenAddr string,
	routerURL string,
	logger *slog.Logger,
	onDiscovered func(discovery.BeaconPayload),
) *ServerDiscoverer {
	if logger == nil {
		logger = slog.Default()
	}
	return &ServerDiscoverer{
		listenAddr:   listenAddr,
		routerURL:    routerURL,
		logger:       logger,
		onDiscovered: onDiscovered,
	}
}

// Start opens a Zenoh session, subscribes to the device discovery wildcard,
// and blocks until ctx is cancelled.  The returned error is ctx.Err() on clean
// shutdown or a Zenoh error on failure.
func (s *ServerDiscoverer) Start(ctx context.Context) error {
	cfg := zc.NewConfigDefault()

	switch {
	case s.listenAddr != "":
		// The ZTP server acts as the Zenoh router — no external router needed.
		if err := cfg.InsertJson5("mode", `"router"`); err != nil {
			return fmt.Errorf("zenoh server: set mode=router: %w", err)
		}
		listenJSON := fmt.Sprintf(`["%s"]`, s.listenAddr)
		if err := cfg.InsertJson5("listen/endpoints", listenJSON); err != nil {
			return fmt.Errorf("zenoh server: set listen endpoint: %w", err)
		}
		s.logger.Info("zenoh server: starting in router mode", "listen", s.listenAddr)
	case s.routerURL != "":
		endpointsJSON := fmt.Sprintf(`["%s"]`, s.routerURL)
		if err := cfg.InsertJson5(zc.ConfigConnectKey, endpointsJSON); err != nil {
			return fmt.Errorf("zenoh server: set connect endpoint: %w", err)
		}
	}

	session, err := zc.Open(cfg, nil)
	if err != nil {
		return fmt.Errorf("zenoh server: open session: %w", err)
	}
	defer session.Drop()

	s.mu.Lock()
	s.session = &session
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.session = nil
		s.mu.Unlock()
	}()

	keyexpr, err := zc.NewKeyExpr(discovery.RequestWildcard)
	if err != nil {
		return fmt.Errorf("zenoh server: request wildcard key expr: %w", err)
	}

	sub, err := session.DeclareSubscriber(keyexpr, zc.Closure[zc.Sample]{
		Call: func(sample zc.Sample) {
			var beacon discovery.BeaconPayload
			if jsonErr := json.Unmarshal(sample.Payload().Bytes(), &beacon); jsonErr != nil {
				s.logger.Error("zenoh server: parse beacon payload", "err", jsonErr)
				return
			}
			if beacon.DeviceID == "" || beacon.PublicKey == "" {
				s.logger.Warn("zenoh server: beacon missing required fields", "key", sample.KeyExpr().String())
				return
			}
			s.logger.Info("zenoh server: device beacon received",
				"device", beacon.DeviceID,
				"hostname", beacon.Facts.Hostname,
			)
			if s.onDiscovered != nil {
				s.onDiscovered(beacon)
			}
		},
	}, nil)
	if err != nil {
		return fmt.Errorf("zenoh server: declare subscriber: %w", err)
	}
	defer sub.Drop()

	s.logger.Info("zenoh server: discovery subscriber active",
		"listen", s.listenAddr,
		"router", s.routerURL,
		"topic", discovery.RequestWildcard,
	)
	<-ctx.Done()
	return ctx.Err()
}

// Approve publishes an [discovery.ApprovalPayload] to the device's approval
// topic.  The agent receives this message and proceeds with standard HTTPS
// enrollment at the supplied serverURL.
//
// Approve may be called from any goroutine.  It returns an error if the Zenoh
// session is not (yet) available or if the publish fails.
func (s *ServerDiscoverer) Approve(ctx context.Context, deviceID, serverURL string) error {
	s.mu.Lock()
	sess := s.session
	s.mu.Unlock()
	if sess == nil {
		return fmt.Errorf("zenoh server: not connected (session not started)")
	}

	payload := discovery.ApprovalPayload{
		DeviceID:  deviceID,
		ServerURL: serverURL,
		IssuedAt:  time.Now().UTC(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("zenoh server: marshal approval: %w", err)
	}

	approveKey, err := zc.NewKeyExpr(discovery.ApproveTopic(deviceID))
	if err != nil {
		return fmt.Errorf("zenoh server: approval key expr: %w", err)
	}

	if err := sess.Put(approveKey, zc.NewZBytesFromString(string(data)), nil); err != nil {
		return fmt.Errorf("zenoh server: publish approval: %w", err)
	}

	s.logger.Info("zenoh server: approval published", "device", deviceID, "server_url", serverURL)
	return nil
}
