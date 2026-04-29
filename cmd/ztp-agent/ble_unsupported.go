//go:build ble && !(linux || windows)

package main

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
)

func init() {
	// Register a runner that surfaces a clear build error on platforms where
	// the tinygo.org/x/bluetooth library does not expose GATT server APIs.
	bleRunner = runBLEUnsupported
}

func runBLEUnsupported(_ context.Context, _ agent.Config, _ *slog.Logger) error {
	return fmt.Errorf(
		"BLE peripheral mode is not supported on %s/%s.\n\n"+
			"The device-side BLE agent must run on Linux (BlueZ) or Windows.\n"+
			"Cross-compile it for the target device:\n\n"+
			"  just cross-agent-ble arm64  # Raspberry Pi 4 (arm64)\n"+
			"  just cross-agent-ble        # Linux amd64 (default)\n\n"+
			"Then copy bin/ztp-agent-ble-linux-<arch> to the device and run it there.\n"+
			"Your browser can still act as the relay — open /onboard/ble in the admin UI.",
		runtime.GOOS, runtime.GOARCH,
	)
}
