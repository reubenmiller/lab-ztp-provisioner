//go:build !zenoh

package zenoh

import (
	"context"
	"log/slog"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/discovery"
)

// AgentDiscoverer is a no-op stub compiled when the zenoh build tag is absent.
type AgentDiscoverer struct {
	RouterURL      string
	BeaconInterval interface{} // unused in stub
	Logger         *slog.Logger
}

// Discover always returns ErrUnsupported.
func (AgentDiscoverer) Discover(_ context.Context, _ discovery.BeaconPayload) (string, error) {
	return "", ErrUnsupported
}

// ServerDiscoverer is a no-op stub compiled when the zenoh build tag is absent.
type ServerDiscoverer struct{}

// NewServerDiscoverer returns a no-op stub.
func NewServerDiscoverer(
	_ string, // listenAddr
	_ string, // routerURL
	_ *slog.Logger,
	_ func(discovery.BeaconPayload),
) *ServerDiscoverer {
	return &ServerDiscoverer{}
}

// Start always returns ErrUnsupported.
func (*ServerDiscoverer) Start(_ context.Context) error {
	return ErrUnsupported
}

// Approve always returns ErrUnsupported.
func (*ServerDiscoverer) Approve(_ context.Context, _, _ string) error {
	return ErrUnsupported
}
