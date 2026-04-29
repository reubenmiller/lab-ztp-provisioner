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
	"strings"
	"sync"
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
	go func() {
		_ = adapter.Scan(func(_ *bluetooth.Adapter, sr bluetooth.ScanResult) {
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
	var sr bluetooth.ScanResult
	select {
	case <-ctx.Done():
		_ = adapter.StopScan()
		return nil, ctx.Err()
	case <-time.After(scanTimeout):
		_ = adapter.StopScan()
		return nil, errors.New("no ZTP peripheral found within scan timeout")
	case sr = <-devCh:
	}

	conn, err := adapter.Connect(sr.Address, bluetooth.ConnectionParams{})
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	defer conn.Disconnect()
	emit(PhaseConnected, deviceLabel(sr))

	svcs, err := conn.DiscoverServices([]bluetooth.UUID{target})
	if err != nil || len(svcs) == 0 {
		return nil, fmt.Errorf("discover service: %w", err)
	}
	chars, err := svcs[0].DiscoverCharacteristics(nil)
	if err != nil {
		return nil, fmt.Errorf("discover chars: %w", err)
	}
	var reqCh, respCh, timeSyncCh *bluetooth.DeviceCharacteristic
	for i := range chars {
		switch chars[i].UUID().String() {
		case parseUUID(RequestUUID).String():
			c := chars[i]
			reqCh = &c
		case parseUUID(ResponseUUID).String():
			c := chars[i]
			respCh = &c
		case parseUUID(TimeSyncUUID).String():
			c := chars[i]
			timeSyncCh = &c
		}
	}
	if reqCh == nil || respCh == nil {
		return nil, errors.New("device missing required ZTP characteristics")
	}

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
