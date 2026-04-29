package trust

import (
	"context"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Allowlist trusts requests whose DeviceID (or any reported MAC / serial) was
// pre-registered by an operator.
type Allowlist struct {
	Store store.Store
}

func (a *Allowlist) Name() string { return "allowlist" }

func (a *Allowlist) Verify(ctx context.Context, req *protocol.EnrollRequest) (Result, error) {
	// Direct device id match is the strongest hint.
	if e, err := a.Store.LookupAllowlist(ctx, req.DeviceID); err == nil && e != nil {
		return Result{Decision: Trust, Reason: "device id pre-registered", Profile: e.Profile}, nil
	}
	// MAC / serial fallbacks: scan the allowlist.
	entries, err := a.Store.ListAllowlist(ctx)
	if err != nil {
		return Result{Decision: Pending}, err
	}
	for _, e := range entries {
		if e.MAC != "" {
			for _, mac := range req.Facts.MACAddresses {
				if strings.EqualFold(mac, e.MAC) {
					return Result{Decision: Trust, Reason: "MAC pre-registered", Profile: e.Profile}, nil
				}
			}
		}
		if e.Serial != "" && req.Facts.Serial != "" && strings.EqualFold(req.Facts.Serial, e.Serial) {
			return Result{Decision: Trust, Reason: "serial pre-registered", Profile: e.Profile}, nil
		}
	}
	return Result{Decision: Pending}, nil
}
