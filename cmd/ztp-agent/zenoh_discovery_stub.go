//go:build !zenoh

package main

import (
	"context"
	"log/slog"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
)

// zenohDiscoveryRunner is nil on non-zenoh builds.
var zenohDiscoveryRunner func(ctx context.Context, cfg agent.Config, routerURL string, logger *slog.Logger) error
