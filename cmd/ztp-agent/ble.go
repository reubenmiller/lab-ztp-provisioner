//go:build ble && (linux || windows)

package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/transport/ble"
)

// bleAdvertisedName returns a name suitable for the BLE advertising payload.
// BlueZ will automatically overflow a long name into the scan-response PDU,
// so we pass the full id through rather than truncating it.
// prefix is prepended to id; when empty it defaults to "ztp-".
func bleAdvertisedName(id, prefix string) string {
	if prefix == "" {
		prefix = "ztp-"
	}
	if id == "" {
		return prefix + "device"
	}
	return prefix + id
}

func init() {
	// Register the BLE peripheral runner and mark the BLE stack as functional
	// on this platform. bleCapable drives auto transport selection in main().
	bleRunner = runBLEPeripheral
	bleCapable = true
}

// runBLEPeripheral starts a BLE GATT peripheral and handles enrollment
// requests from the relay. The dispatch is content-driven, not cycle-driven:
// an empty request buffer is a fresh trigger (build & send a new envelope
// with a new nonce), a non-empty buffer is a server response (verify and
// apply, then exit).
//
// Why content-driven: a relay that sees the server return "pending" simply
// disconnects without writing anything back to the device. After the
// operator approves, the relay reconnects and issues a fresh trigger.
// Treating that second trigger as another envelope build (rather than as
// "phase 2 of one connection") is what makes the post-approval reconnect
// path actually deliver the bundle.
//
// Clock synchronisation (Option 1 + Option 3):
//   - Option 3: before each trigger, the relay may write an RFC3339
//     timestamp to TimeSyncUUID. OnTimeSync stores the offset atomically;
//     the next envelope is built with the corrected timestamp.
//   - Option 1: if the server rejects due to clock skew, the response
//     carries ServerTime. The offset is extracted and applied to the next
//     envelope build.
func runBLEPeripheral(ctx context.Context, cfg agent.Config, logger *slog.Logger) error {
	// clockOffsetNs holds the current clock correction (nanoseconds) as an
	// atomic so it is safe for the BLE WriteEvent goroutine to update it while
	// the serve loop reads it.
	var clockOffsetNs atomic.Int64

	clkOffset := func() time.Duration {
		return time.Duration(clockOffsetNs.Load())
	}

	deviceName := cfg.DeviceID
	if deviceName == "" {
		// Try to derive a meaningful name from the same sources Run() would
		// use later (machine-id, /etc/device-id, tedge-identity). Falling back
		// to empty lets bleAdvertisedName produce the "<prefix>device" fallback,
		// which is unhelpful in workshops/demos but at least not misleading.
		if id, err := agent.ResolveDeviceID(""); err == nil && id != "" {
			deviceName = id
		}
	}
	deviceName = bleAdvertisedName(deviceName, cfg.BLENamePrefix)
	periph := ble.NewPeripheral(deviceName)
	// The "name" passed to NewPeripheral is the device's identity for
	// post-connect display only. The primary BLE advertisement uses
	// the short literal ble.AdvertisedLocalName so the 128-bit
	// service UUID always fits inside the 31-byte primary-PDU cap on
	// passive-scan WinRT centrals — long names like
	// "ztp-rpi4-d83add90fe56" would otherwise force BlueZ to push
	// either the name or the UUID into the scan response, where
	// Windows can't see them.
	logger.Info("BLE: peripheral ready",
		"device_name", deviceName,
		"advertised_name", ble.AdvertisedLocalName,
		"service_uuid", ble.ServiceUUID)

	// Option 3: relay writes current time to TimeSyncUUID before enrollment.
	periph.OnTimeSync = func(serverTime time.Time) {
		offset := serverTime.Sub(time.Now())
		clockOffsetNs.Store(int64(offset))
		logger.Info("BLE: time sync from relay", "server_time", serverTime, "offset", offset)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// ephPriv is the X25519 ephemeral private key whose public counterpart is
	// embedded in the most recent envelope. Apply needs to use the SAME key to
	// open any sealed modules in the bundle, so we keep them paired under a
	// single mutex and only swap when a fresh envelope is built.
	var (
		stateMu sync.Mutex
		ephPriv [32]byte
	)

	var applyErr error

	serveErr := periph.Serve(ctx, func(req []byte) ([]byte, error) {
		if len(req) == 0 {
			// Fresh trigger from the relay. Build a brand-new envelope
			// every time — the server has already consumed any prior
			// nonce, so we can't reuse the previous one.
			cfg.ClockOffset = clkOffset()
			logger.Info("BLE transport: building enroll envelope", "clock_offset", cfg.ClockOffset)
			envJSON, priv, buildErr := agent.BuildEnrollEnvelope(cfg)
			if buildErr != nil {
				applyErr = buildErr
				cancel()
				return nil, buildErr
			}
			stateMu.Lock()
			ephPriv = priv
			stateMu.Unlock()
			logger.Info("BLE: relay connected, sending enroll envelope")
			return envJSON, nil
		}

		// Non-empty payload: this is a server response the relay forwarded
		// after POSTing our envelope to /v1/enroll. Verify and apply.
		logger.Info("BLE: received server response, applying bundle")

		// Option 1: check for retryable response and extract ServerTime.
		retryable, status, reason, serverTime, parseErr := agent.IsRetryableEnrollResponse(req)
		if parseErr != nil {
			applyErr = parseErr
			cancel()
			return nil, parseErr
		}
		if retryable {
			if serverTime != nil {
				offset := serverTime.Sub(time.Now())
				clockOffsetNs.Store(int64(offset))
				logger.Info("BLE: auto-correcting clock from server response",
					"offset", time.Duration(clockOffsetNs.Load()))
			}
			logger.Warn("BLE: server response requires retry; awaiting next relay trigger",
				"status", status, "reason", reason)
			return nil, fmt.Errorf("%s: %s", status, reason)
		}

		stateMu.Lock()
		eph := ephPriv
		stateMu.Unlock()
		err := agent.ApplyEnrollResponse(ctx, cfg, eph, req)
		applyErr = err
		if err != nil {
			logger.Error("BLE: apply failed", "err", err)
		}
		// Cancel the serve loop — one enrollment cycle is complete.
		cancel()
		return nil, err
	})

	// Prefer the application-level error over the context-cancellation error
	// so the caller gets a meaningful message.
	if applyErr != nil {
		return applyErr
	}
	if serveErr != nil && ctx.Err() == nil {
		// Unexpected serve error (not our own cancel).
		return serveErr
	}
	return nil
}
