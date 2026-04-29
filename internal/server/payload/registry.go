// Package payload contains composable PayloadProviders. Each provider emits
// zero or more typed Modules to be included in a device's ProvisioningBundle.
//
// Providers are independently toggleable (enabled/disabled in config) and may
// consult the per-device Overrides map for device-specific values. Operators
// add new providers without changing the engine: implement Provider, register
// it in main.go, and reference it from config.
package payload

import (
	"context"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Provider builds module(s) for a single device.
//
// Implementations must be deterministic given the same device + overrides so
// that retried bundle issuance is idempotent (apart from secrets like one-time
// passwords, which providers may rotate intentionally).
type Provider interface {
	Name() string
	Build(ctx context.Context, device *store.Device) ([]protocol.Module, error)
}

// Registry composes providers in declared order.
type Registry []Provider

// Build runs every provider and concatenates the modules. A failing provider
// short-circuits the whole bundle so the device sees a clean error rather than
// a half-applied configuration.
func (r Registry) Build(ctx context.Context, device *store.Device) ([]protocol.Module, error) {
	out := make([]protocol.Module, 0, len(r))
	for _, p := range r {
		mods, err := p.Build(ctx, device)
		if err != nil {
			return nil, err
		}
		out = append(out, mods...)
	}
	return out, nil
}
