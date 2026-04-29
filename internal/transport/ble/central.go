//go:build ble && (linux || windows || darwin)

// BLE central (operator/relay-side) using tinygo.org/x/bluetooth.
// Compiles on Linux/BlueZ, Windows, AND macOS/CoreBluetooth — peripheral
// (GATT server) is still Linux/Windows-only and lives in ble.go.
//
// This file owns Relay (the historical low-level scan-write-listen API
// kept for backwards compatibility with existing agents) and Enroll —
// a high-level entry point matching the Web-Bluetooth onboarding flow
// the SPA already implements: trigger → receive envelope → forward →
// stream bundle back.

package ble

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tinygo.org/x/bluetooth"
)

// matchesZTPPeripheral reports whether a scan result looks like a ZTP
// device worth connecting to. The primary signal is the advertised
// 128-bit service UUID; the LocalName prefix is a fallback for stacks
// that don't surface ServiceUUIDs from the scan payload (Windows
// WinRT in particular — the UUID list often only populates after a
// connect-and-discover round-trip, which is too late for a passive
// scan filter).
//
// Tradeoff: any nearby device whose advertised name starts with "ztp-"
// will be picked up. We accept this — the prefix is specific enough
// that collisions with other vendor advertisements are unlikely, and
// the post-connect characteristic check still rejects non-ZTP
// peripherals before we forward anything to the server.
func matchesZTPPeripheral(sr bluetooth.ScanResult, target bluetooth.UUID) bool {
	if sr.AdvertisementPayload.HasServiceUUID(target) {
		return true
	}
	if name := sr.LocalName(); name != "" && strings.HasPrefix(name, LocalNamePrefix) {
		return true
	}
	return false
}

// adapterEnable runs bluetooth.DefaultAdapter.Enable() exactly once
// per process. tinygo's CoreBluetooth backend on macOS rejects a
// second concurrent call with "already calling Enable function" if
// the first one is still in flight, which is what happens when the
// user clicks Scan & relay a second time after a failed attempt:
// the underlying CBCentralManager is already up. Re-running Enable
// on subsequent attempts is therefore neither necessary nor safe.
var (
	adapterEnableOnce sync.Once
	adapterEnableErr  error
)

func enableAdapter(adapter *bluetooth.Adapter) error {
	adapterEnableOnce.Do(func() {
		adapterEnableErr = adapter.Enable()
	})
	return adapterEnableErr
}

// Relay is the gateway-side BLE central. Kept for callers of the
// original Run API; new callers should prefer Enroll which does the
// trigger-and-receive flow used by both the Web Bluetooth SPA and the
// desktop binding.
type Relay struct {
	adapter *bluetooth.Adapter
}

// NewRelay returns a Relay using the platform's default adapter.
func NewRelay() *Relay { return &Relay{adapter: bluetooth.DefaultAdapter} }

// Run is the legacy scan-write-listen flow. The caller passes a
// reqResp function invoked twice: once with nil to obtain the request
// bytes to write, then once with the response bytes after the device
// notifies them back. New callers should use Enroll instead.
func (r *Relay) Run(ctx context.Context, reqResp func(req []byte) (resp []byte, err error)) error {
	if err := enableAdapter(r.adapter); err != nil {
		return fmt.Errorf("enable adapter: %w", err)
	}

	target := parseUUID(ServiceUUID)
	devCh := make(chan bluetooth.ScanResult, 1)
	go func() {
		_ = r.adapter.Scan(func(_ *bluetooth.Adapter, sr bluetooth.ScanResult) {
			if matchesZTPPeripheral(sr, target) {
				select {
				case devCh <- sr:
				default:
				}
				_ = r.adapter.StopScan()
			}
		})
	}()

	var sr bluetooth.ScanResult
	select {
	case <-ctx.Done():
		_ = r.adapter.StopScan()
		return ctx.Err()
	case <-time.After(20 * time.Second):
		_ = r.adapter.StopScan()
		return errors.New("no ZTP peripheral found")
	case sr = <-devCh:
	}

	conn, err := r.adapter.Connect(sr.Address, bluetooth.ConnectionParams{})
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	defer conn.Disconnect()

	svcs, err := conn.DiscoverServices([]bluetooth.UUID{target})
	if err != nil || len(svcs) == 0 {
		return fmt.Errorf("discover service: %w", err)
	}
	chars, err := svcs[0].DiscoverCharacteristics([]bluetooth.UUID{
		parseUUID(RequestUUID), parseUUID(ResponseUUID), parseUUID(StatusUUID),
	})
	if err != nil || len(chars) < 3 {
		return fmt.Errorf("discover chars: %w", err)
	}
	reqCh, respCh, statCh := chars[0], chars[1], chars[2]

	requestBytes, err := reqResp(nil)
	if err != nil {
		return err
	}
	if err := writeFramed(reqCh, requestBytes); err != nil {
		return err
	}

	respBuf, err := readFramed(ctx, respCh, 60*time.Second)
	if err != nil {
		return err
	}

	if v, err := statCh.Read(make([]byte, 1)); err == nil && v == 1 {
		// no-op (legacy compat)
	}
	_, err = reqResp(respBuf)
	return err
}

// EnrollResult is what Enroll returns. Bytes the caller's submit
// function returned are echoed in Bundle so the caller can decide
// whether to forward something secondary back to the device or stop.
type EnrollResult struct {
	// EnvelopeBytes is the SignedEnvelope the device produced (the
	// bytes Enroll forwarded to submit).
	EnvelopeBytes []byte

	// BundleBytes is whatever submit returned and Enroll wrote back
	// to the device. Empty if submit returned nil bytes (e.g. a
	// pending result the caller declined to deliver).
	BundleBytes []byte
}

// Phase labels emitted via ProgressFn at major flow milestones. The
// labels are part of the contract with the SPA — adding new ones is
// fine, renaming existing ones requires updating the UI's switch.
const (
	PhaseScanning        = "scanning"
	PhaseConnected       = "connected"        // detail = device name (or address if name unavailable)
	PhaseTimeSync        = "time-sync"        // best-effort write succeeded
	PhaseTrigger         = "trigger"          // wrote the empty-EOM kick
	PhaseEnvelopeRead    = "envelope-read"    // detail = byte count
	PhaseSubmitting      = "submitting"       // handing envelope to the submit hook (typically POST /v1/enroll)
	PhaseWritingBundle   = "writing-bundle"   // detail = byte count
	PhaseDone            = "done"
)

// ProgressFn is invoked at each phase of the Enroll flow. detail is a
// short, free-form string suitable for display (a device name, byte
// count, etc.); empty when there's nothing useful to add. Callers
// pass nil to skip progress reporting.
//
// The function is invoked synchronously on the goroutine running
// Enroll, so it must not block. The desktop binding wraps Wails'
// EventsEmit (which is thread-safe and returns immediately).
type ProgressFn func(phase, detail string)

// Enroll performs the Web-Bluetooth-aligned onboarding flow with a
// single ZTP peripheral. Steps:
//
//  1. Scan for a peripheral advertising ServiceUUID; first match wins.
//  2. Connect, discover the four characteristics.
//  3. Best-effort write current wall-clock to TimeSyncUUID so devices
//     with no NTP can stamp their request inside the server's skew.
//  4. Subscribe to ResponseUUID notifications.
//  5. Write empty EOM to RequestUUID — that's the "kick" the device
//     waits for before publishing its signed envelope.
//  6. Reassemble the envelope from notification fragments.
//  7. Hand the envelope to submit (typically: POST /v1/enroll on the
//     in-process loopback). Receive bytes back.
//  8. Chunk-write those bytes via RequestUUID so the device can verify
//     and apply them.
//
// progress is fired at each labelled milestone; pass nil to skip.
// Empty submit bytes (return nil) skip the writeback. scanTimeout is
// the max time spent looking for a peripheral; ctx cancels everything.
func Enroll(ctx context.Context, scanTimeout time.Duration, progress ProgressFn, submit func(envelope []byte) (bundle []byte, err error)) (*EnrollResult, error) {
	emit := func(phase, detail string) {
		if progress != nil {
			progress(phase, detail)
		}
	}

	adapter := bluetooth.DefaultAdapter
	if err := enableAdapter(adapter); err != nil {
		return nil, fmt.Errorf("enable adapter: %w", err)
	}

	emit(PhaseScanning, "")
	target := parseUUID(ServiceUUID)
	devCh := make(chan bluetooth.ScanResult, 1)

	// Instrumentation that distinguishes the failure modes a bare
	// "scan timed out" can't tell apart:
	//
	//   advertCount == 0  → adapter is up but no advertisements
	//                       reached us. On Windows this is almost
	//                       always Settings > Privacy > Bluetooth
	//                       blocking unpackaged desktop apps; on Linux
	//                       it usually means the radio is rfkill'd or
	//                       the user lacks permissions.
	//   advertCount  > 0  → adverts came in but none matched. Either
	//                       the device isn't advertising, OR the BLE
	//                       stack only sees the primary advertisement
	//                       (passive scan, common on WinRT) and our
	//                       service UUID / local name was placed in
	//                       the scan-response payload by BlueZ
	//                       because the 31-byte primary was full.
	//   scanErr   != nil  → adapter.Scan returned an error — used to
	//                       be silently dropped, now surfaced.
	//
	// The match-callback runs on tinygo's scan goroutine so the
	// counters use atomic. The slog.Default() calls drop into the
	// app's verbose log when -v is set; the error path includes the
	// counts unconditionally so production logs always have enough
	// signal.
	var advertCount int64
	var scanErr error
	go func() {
		scanErr = adapter.Scan(func(_ *bluetooth.Adapter, sr bluetooth.ScanResult) {
			n := atomic.AddInt64(&advertCount, 1)
			slog.Debug("ble: advertisement",
				"i", n,
				"address", sr.Address.String(),
				"name", sr.LocalName(),
				"rssi", sr.RSSI,
				"has_service_uuid", sr.AdvertisementPayload.HasServiceUUID(target),
			)
			if matchesZTPPeripheral(sr, target) {
				select {
				case devCh <- sr:
				default:
				}
				_ = adapter.StopScan()
			}
		})
	}()

	if scanTimeout <= 0 {
		scanTimeout = 20 * time.Second
	}

	// Periodic liveness progress: refresh PhaseScanning every 2s with
	// the running advert count. Gives the SPA something to render so
	// the user can tell the difference between "scanning, just slow"
	// and "scanning, nothing on the air". Stops as soon as the select
	// below returns. Synchronous progress() emits are safe — the
	// desktop binding wraps Wails' EventsEmit which is non-blocking.
	tickCtx, tickCancel := context.WithCancel(ctx)
	defer tickCancel()
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-tickCtx.Done():
				return
			case <-t.C:
				emit(PhaseScanning, fmt.Sprintf("%d adverts seen", atomic.LoadInt64(&advertCount)))
			}
		}
	}()

	var sr bluetooth.ScanResult
	select {
	case <-ctx.Done():
		_ = adapter.StopScan()
		return nil, ctx.Err()
	case <-time.After(scanTimeout):
		_ = adapter.StopScan()
		return nil, scanTimeoutError(atomic.LoadInt64(&advertCount), scanErr, scanTimeout)
	case sr = <-devCh:
	}
	// Stop the periodic "scanning…" emitter as soon as we have a hit.
	// Otherwise it keeps firing through connect / service discovery
	// and the UI shows the misleading "scanning" status interleaved
	// with later phase events.
	tickCancel()

	conn, err := adapter.Connect(sr.Address, bluetooth.ConnectionParams{})
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Disconnect()
	emit(PhaseConnected, deviceLabel(sr))

	// Service discovery is retried because WinRT's
	// BluetoothLEDevice.GetGattServicesAsync returns "async operation
	// failed with status 2" when the GATT attribute cache hasn't
	// populated yet — common when a fresh connection's service
	// enumeration races the OS's caching. A 250ms delay between
	// attempts gives Windows time to fill the cache; three tries
	// covers the typical failure window without making genuinely
	// broken peripherals hang for long.
	var svcs []bluetooth.DeviceService
	for attempt := 1; attempt <= 3; attempt++ {
		svcs, err = conn.DiscoverServices([]bluetooth.UUID{target})
		if err == nil && len(svcs) > 0 {
			break
		}
		slog.Debug("ble: service discovery attempt failed",
			"attempt", attempt, "err", err, "services", len(svcs))
		if attempt < 3 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(250 * time.Millisecond):
			}
		}
	}
	if err != nil || len(svcs) == 0 {
		return nil, fmt.Errorf("discover service after retries: %w", err)
	}
	// Characteristic discovery is split into "required" and
	// "optional" passes because tinygo's filtered DiscoverCharacteristics
	// returns "did not find all requested" if ANY UUID in the list is
	// missing, even when the others are present. Doing one strict
	// call for the protocol-mandatory pair (request + response) and a
	// separate best-effort call for the optional TimeSync surfaces a
	// useful diagnostic on the few that matter and silently degrades
	// on the one that doesn't. The Status characteristic is exposed by
	// the peripheral but not consumed by Enroll's flow, so we don't
	// discover it here at all.
	reqUUID := parseUUID(RequestUUID)
	respUUID := parseUUID(ResponseUUID)
	tsUUID := parseUUID(TimeSyncUUID)
	chars, err := svcs[0].DiscoverCharacteristics([]bluetooth.UUID{reqUUID, respUUID})
	if err != nil {
		// Fallback: enumerate every characteristic on the service so
		// we can tell the operator exactly what was found. WinRT's
		// unfiltered GetCharacteristicsAsync can be flaky against
		// BlueZ peripherals, but when the filtered call has already
		// failed we have nothing to lose.
		slog.Debug("ble: filtered discovery failed; trying unfiltered fallback", "err", err)
		all, fallbackErr := svcs[0].DiscoverCharacteristics(nil)
		if fallbackErr != nil {
			return nil, fmt.Errorf("discover chars: %w (unfiltered fallback also failed: %v)", err, fallbackErr)
		}
		chars = all
	}
	var reqCh, respCh, timeSyncCh *bluetooth.DeviceCharacteristic
	seenUUIDs := make([]string, 0, len(chars))
	for i := range chars {
		u := chars[i].UUID()
		seenUUIDs = append(seenUUIDs, u.String())
		// Direct UUID equality (UUID is a [4]uint32 value type) is
		// safer than .String() comparison: tinygo's per-platform
		// stringification has historically returned different cases
		// between BlueZ and WinRT, which silently broke the previous
		// switch even when the underlying bytes matched.
		switch u {
		case reqUUID:
			c := chars[i]
			reqCh = &c
		case respUUID:
			c := chars[i]
			respCh = &c
		case tsUUID:
			c := chars[i]
			timeSyncCh = &c
		}
	}
	if reqCh == nil || respCh == nil {
		return nil, fmt.Errorf("device missing required ZTP characteristics (discovered %d: %v; need request=%s, response=%s)",
			len(chars), seenUUIDs, RequestUUID, ResponseUUID)
	}
	// TimeSync is a separate, best-effort discovery — older devices
	// don't expose it, and bundling it into the required-pass would
	// fail the whole enrollment for a feature that's only used to
	// nudge the device's clock before the envelope is signed.
	if timeSyncCh == nil {
		if tsChars, err := svcs[0].DiscoverCharacteristics([]bluetooth.UUID{tsUUID}); err == nil && len(tsChars) > 0 {
			c := tsChars[0]
			timeSyncCh = &c
		}
	}
	slog.Debug("ble: characteristics resolved",
		"discovered_in_first_pass", len(chars),
		"uuids", seenUUIDs,
		"request_found", reqCh != nil,
		"response_found", respCh != nil,
		"timesync_found", timeSyncCh != nil)

	// Best-effort time sync. Older devices may not advertise the
	// characteristic; silently skip.
	if timeSyncCh != nil {
		ts := []byte(time.Now().UTC().Format(time.RFC3339))
		if _, err := timeSyncCh.WriteWithoutResponse(ts); err == nil {
			emit(PhaseTimeSync, string(ts))
		}
	}

	// Subscribe to notifications BEFORE kicking the device — otherwise
	// fast peripherals can publish their response before the CCCD
	// descriptor write lands, which on CoreBluetooth surfaces as
	// "timeout on EnableNotifications" because the descriptor write
	// is queued behind the WriteWithoutResponse we sent on reqCh.
	envCh := make(chan []byte, 1)
	envErrCh := make(chan error, 1)
	subCtx, subCancel := context.WithCancel(ctx)
	defer subCancel()
	if err := startFramedReader(subCtx, *respCh, 60*time.Second, envCh, envErrCh); err != nil {
		return nil, fmt.Errorf("enable notifications: %w", err)
	}

	// Trigger the device's envelope publication with an empty EOM,
	// then collect notification fragments until EOM.
	emit(PhaseTrigger, "")
	if _, err := reqCh.WriteWithoutResponse([]byte{0, 0}); err != nil {
		return nil, fmt.Errorf("trigger: %w", err)
	}
	var envelope []byte
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-envErrCh:
		return nil, err
	case envelope = <-envCh:
	}
	emit(PhaseEnvelopeRead, fmt.Sprintf("%d bytes", len(envelope)))

	emit(PhaseSubmitting, "")
	bundle, err := submit(envelope)
	if err != nil {
		return &EnrollResult{EnvelopeBytes: envelope}, err
	}
	if len(bundle) > 0 {
		emit(PhaseWritingBundle, fmt.Sprintf("%d bytes", len(bundle)))
		if err := writeFramed(*reqCh, bundle); err != nil {
			return &EnrollResult{EnvelopeBytes: envelope}, fmt.Errorf("write bundle: %w", err)
		}
	}
	emit(PhaseDone, "")
	return &EnrollResult{EnvelopeBytes: envelope, BundleBytes: bundle}, nil
}

// scanTimeoutError builds a diagnostic error message that distinguishes
// "saw nothing at all" (most likely a permission/adapter issue) from
// "saw advertisements but none were ZTP" (most likely a peripheral or
// advertisement-payload-fit issue), and surfaces any error returned by
// adapter.Scan itself (used to be silently swallowed).
func scanTimeoutError(advertCount int64, scanErr error, scanTimeout time.Duration) error {
	if scanErr != nil {
		return fmt.Errorf("ble scan failed: %w (after %s, %d adverts seen)", scanErr, scanTimeout, advertCount)
	}
	if advertCount == 0 {
		return fmt.Errorf(
			"no BLE advertisements received during %s scan — the adapter is up but the OS isn't delivering any. "+
				"Common causes: Bluetooth radio off, Settings > Privacy > Bluetooth disallowing this app (Windows), "+
				"rfkill blocking the radio (Linux), or the binary lacks Bluetooth capability (sandboxed macOS).",
			scanTimeout)
	}
	return fmt.Errorf(
		"saw %d BLE advertisement(s) in %s but none matched ZTP service UUID %s or local name prefix %q. "+
			"Verify the device is advertising. On Windows centrals, the OS may only see the primary "+
			"advertisement payload — if both the service UUID and the device name are too large to fit, "+
			"the peripheral pushes one of them into the scan response which Windows passive-scanning ignores. "+
			"Run with -v to log every advertisement seen.",
		advertCount, scanTimeout, ServiceUUID, LocalNamePrefix)
}

// deviceLabel returns a human-readable identifier for a scan result —
// the advertised local name when available, falling back to the
// device's MAC address. The SPA shows this in the "connected to X"
// status line so operators know which device was picked.
func deviceLabel(sr bluetooth.ScanResult) string {
	if name := sr.LocalName(); name != "" {
		return name
	}
	return sr.Address.String()
}

// writeFramed chunks payload into [u16 BE length][bytes] fragments
// followed by a length-0 EOM. Mirrors the SPA's frame() helper byte
// for byte; the device's onWrite reassembles by tracking length.
//
// Each fragment is sent via Write (with-response) rather than
// WriteWithoutResponse. Reason: a 182-byte fragment exceeds the
// negotiated MTU on a fair fraction of BLE links (default ATT MTU
// is 23, often only negotiated up to 185 — and not always). On
// CoreBluetooth (the macOS central used by ztp-app), a
// WriteWithoutResponse that exceeds maximumWriteValueLengthForType:
// is silently truncated to fit, the call returns success, and the
// peripheral's onWrite either misses the fragment entirely or
// receives one whose length header overstates the bytes that
// arrived (then drops it on the `2+n > len(value)` check).
//
// Write with response triggers ATT Long Write under the hood
// (Prepare Write + Execute Write) for any payload >MTU-3, which
// BlueZ reassembles before invoking the peripheral's WriteValue
// callback. The cost is one extra round-trip per fragment, which
// for a 12-fragment bundle is well under a second on a typical
// BLE link.
func writeFramed(ch bluetooth.DeviceCharacteristic, payload []byte) error {
	for off := 0; off < len(payload); off += fragSize {
		end := off + fragSize
		if end > len(payload) {
			end = len(payload)
		}
		buf := make([]byte, 2+(end-off))
		binary.BigEndian.PutUint16(buf[:2], uint16(end-off))
		copy(buf[2:], payload[off:end])
		if _, err := ch.Write(buf); err != nil {
			return fmt.Errorf("write fragment: %w", err)
		}
	}
	if _, err := ch.Write([]byte{0, 0}); err != nil {
		return fmt.Errorf("write EOM: %w", err)
	}
	return nil
}

// startFramedReader enables notifications on ch immediately and
// streams the assembled payload (or error) onto outCh / errCh once
// an EOM fragment arrives. Unlike readFramed it returns as soon as
// the EnableNotifications descriptor write succeeds, so the caller
// can issue the trigger write without racing against subscription
// setup. ctx cancellation tears down the timeout goroutine.
func startFramedReader(ctx context.Context, ch bluetooth.DeviceCharacteristic, timeout time.Duration, outCh chan<- []byte, errCh chan<- error) error {
	buf := make([]byte, 0, 1024)
	done := make(chan struct{})
	var once sync.Once
	closeDone := func() { once.Do(func() { close(done) }) }
	if err := ch.EnableNotifications(func(value []byte) {
		if len(value) < 2 {
			return
		}
		n := int(binary.BigEndian.Uint16(value[:2]))
		if n == 0 {
			outCh <- append([]byte(nil), buf...)
			closeDone()
			return
		}
		if 2+n > len(value) {
			return
		}
		buf = append(buf, value[2:2+n]...)
	}); err != nil {
		return err
	}
	go func() {
		select {
		case <-ctx.Done():
			closeDone()
			errCh <- ctx.Err()
		case <-done:
		case <-time.After(timeout):
			closeDone()
			errCh <- errors.New("timeout waiting for response notifications")
		}
	}()
	return nil
}

// readFramed reads framed fragments off a notification characteristic
// until a length-0 fragment marks EOM. Returns the assembled payload
// or an error if ctx is cancelled / timeout elapses.
func readFramed(ctx context.Context, ch bluetooth.DeviceCharacteristic, timeout time.Duration) ([]byte, error) {
	buf := make([]byte, 0, 1024)
	done := make(chan struct{})
	if err := ch.EnableNotifications(func(value []byte) {
		if len(value) < 2 {
			return
		}
		n := int(binary.BigEndian.Uint16(value[:2]))
		if n == 0 {
			select {
			case <-done:
				// already closed
			default:
				close(done)
			}
			return
		}
		if 2+n > len(value) {
			return
		}
		buf = append(buf, value[2:2+n]...)
	}); err != nil {
		return nil, fmt.Errorf("enable notifications: %w", err)
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-done:
		return buf, nil
	case <-time.After(timeout):
		return nil, errors.New("timeout waiting for response notifications")
	}
}
