package agent

import (
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/clock"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// adjustSystemClockFromBundle invokes clock.Adjust against the bundle's
// IssuedAt field. It is called from both the HTTP path (Run) and the BLE
// path (ApplyEnrollResponse) immediately after the bundle's signature has
// been verified, before any applier dispatches. Errors from clock.Adjust
// are intentionally non-fatal: a failure to set the clock (e.g. missing
// CAP_SYS_TIME) is logged by clock.Adjust itself, and the agent continues
// so a device with only a small drift can still finish provisioning.
func adjustSystemClockFromBundle(cfg Config, b *protocol.ProvisioningBundle) {
	if b == nil {
		return
	}
	_ = clock.Adjust(b.IssuedAt, cfg.SystemClockPolicy, cfg.SystemClockThreshold, cfg.Logger)
}
