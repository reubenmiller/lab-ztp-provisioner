//go:build !zenoh

package runtime

import (
	"context"
	"log/slog"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/api"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
)

// startZenohDiscovery is a no-op on non-zenoh builds.
func startZenohDiscovery(
	_ context.Context,
	_ config.ZenohConfig,
	_ string,
	_ store.Store,
	_ *api.Hub,
	_ *slog.Logger,
) (stop func(), onApproved func(context.Context, string)) {
	return nil, nil
}
