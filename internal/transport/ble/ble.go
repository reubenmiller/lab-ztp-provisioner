//go:build ble && (linux || windows)

// BLE GATT peripheral implementation using tinygo.org/x/bluetooth.
// The library only exposes peripheral/server APIs on Linux (BlueZ) and
// Windows; on macOS this file is excluded by the build tag and the
// Peripheral type is stubbed in ble_peripheral_stub.go. Central-mode
// (relay) code lives in central.go and compiles on all three OSes.
//
// Peripheral (device) flow:
//   1. Advertise the ZTP service UUID + the local name.
//   2. Wait for a central to write a chunked EnrollRequest to RequestUUID.
//   3. Reassemble, hand off to the user-supplied handler (which talks to the
//      ZTP server over IP), then chunk the EnrollResponse back via notify on
//      ResponseUUID.
//
// Framing on both characteristics:
//   - Each fragment: 2-byte big-endian length prefix, then payload.
//   - A length-0 fragment marks "end of message".
//
// MTU defaults to 23 bytes (20 payload) on most stacks; we conservatively use
// 180-byte fragments (well within typical ATT MTU after negotiation) and let
// the stack split as needed.

package ble

import (
	"context"
	"encoding/binary"
	"fmt"
	"strings"
	"sync"
	"time"

	"tinygo.org/x/bluetooth"
)

// Peripheral is the device-side BLE GATT server.
type Peripheral struct {
	name    string
	adapter *bluetooth.Adapter
	// OnTimeSync, if non-nil, is called when the relay writes an RFC3339 UTC
	// timestamp to TimeSyncUUID before enrollment begins. Use it to correct the
	// device's clock offset so EnrollRequest timestamps pass the server's skew
	// check on devices that have not yet synced via NTP.
	OnTimeSync func(serverTime time.Time)
}

// NewPeripheral configures (but does not start) a BLE peripheral.
func NewPeripheral(name string) *Peripheral {
	if name == "" {
		name = "ztp-device"
	}
	return &Peripheral{name: name, adapter: bluetooth.DefaultAdapter}
}

// Serve advertises and serves until ctx is cancelled. handler is called with
// the bytes the central wrote and should return the bytes to send back.
func (p *Peripheral) Serve(ctx context.Context, handler func(req []byte) (resp []byte, err error)) error {
	if err := p.adapter.Enable(); err != nil {
		return fmt.Errorf("enable adapter: %w", err)
	}

	var (
		mu         sync.Mutex
		reqBuf     []byte
		respHandle bluetooth.Characteristic
		statHandle bluetooth.Characteristic
	)

	svcUUID := parseUUID(ServiceUUID)
	reqUUID := parseUUID(RequestUUID)
	respUUID := parseUUID(ResponseUUID)
	statUUID := parseUUID(StatusUUID)

	onWrite := func(_ bluetooth.Connection, _ int, value []byte) {
		mu.Lock()
		defer mu.Unlock()
		// Each write is one framed fragment.
		if len(value) < 2 {
			return
		}
		n := int(binary.BigEndian.Uint16(value[:2]))
		if n == 0 {
			// EOM — process the request and stream back the response.
			req := append([]byte(nil), reqBuf...)
			reqBuf = reqBuf[:0]
			go p.respond(req, handler, respHandle, statHandle)
			return
		}
		if 2+n > len(value) {
			return
		}
		reqBuf = append(reqBuf, value[2:2+n]...)
	}

	if err := p.adapter.AddService(&bluetooth.Service{
		UUID: svcUUID,
		Characteristics: []bluetooth.CharacteristicConfig{
			{
				UUID:       reqUUID,
				Flags:      bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicWriteWithoutResponsePermission,
				WriteEvent: onWrite,
			},
			{
				UUID:   respUUID,
				Handle: &respHandle,
				Flags:  bluetooth.CharacteristicReadPermission | bluetooth.CharacteristicNotifyPermission,
			},
			{
				UUID:   statUUID,
				Handle: &statHandle,
				Flags:  bluetooth.CharacteristicReadPermission | bluetooth.CharacteristicNotifyPermission,
				Value:  []byte{StatusIdle},
			},
			{
				UUID:  parseUUID(TimeSyncUUID),
				Flags: bluetooth.CharacteristicWritePermission | bluetooth.CharacteristicWriteWithoutResponsePermission,
				WriteEvent: func(_ bluetooth.Connection, _ int, value []byte) {
					if p.OnTimeSync == nil {
						return
					}
					t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(value)))
					if err == nil {
						p.OnTimeSync(t.UTC())
					}
				},
			},
		},
	}); err != nil {
		return fmt.Errorf("add service: %w", err)
	}

	// LocalName is intentionally omitted from the advertisement payload.
	// A 128-bit service UUID consumes 18 of the 31 bytes available in
	// a BLE 4.x primary advertisement (after the 3-byte Flags AD type),
	// leaving only ~8 bytes for any LocalName before the host stack is
	// forced to push one of name/UUID into the scan-response packet.
	// WinRT centrals default to passive scanning, which discards scan-
	// response data — the symptom an operator sees is "0 of 600+
	// scanned advertisements matched ZTP", followed by sporadic
	// successes whenever Windows happens to deliver the right slice.
	//
	// Dropping LocalName here keeps the advertisement deterministic at
	// 21 bytes (3 flags + 18 UUID), well under the 31-byte cap, so
	// every passive-scan central reliably sees the service UUID. The
	// peripheral's name is still readable post-connect via the GAP
	// Device Name characteristic; identification before connect uses
	// the MAC address (deviceLabel falls back to that automatically).
	adv := p.adapter.DefaultAdvertisement()
	if err := adv.Configure(bluetooth.AdvertisementOptions{
		ServiceUUIDs: []bluetooth.UUID{svcUUID},
	}); err != nil {
		return fmt.Errorf("configure adv: %w", err)
	}
	if err := adv.Start(); err != nil {
		return fmt.Errorf("start adv: %w", err)
	}
	defer adv.Stop()

	<-ctx.Done()
	return ctx.Err()
}

func (*Peripheral) respond(req []byte, handler func([]byte) ([]byte, error),
	respCh, statCh bluetooth.Characteristic) {

	_, _ = statCh.Write([]byte{StatusRelaying})
	resp, err := handler(req)
	if err != nil {
		_, _ = statCh.Write([]byte{StatusError})
		return
	}
	for off := 0; off < len(resp); off += fragSize {
		end := off + fragSize
		if end > len(resp) {
			end = len(resp)
		}
		chunk := resp[off:end]
		buf := make([]byte, 2+len(chunk))
		binary.BigEndian.PutUint16(buf[:2], uint16(len(chunk)))
		copy(buf[2:], chunk)
		_, _ = respCh.Write(buf)
	}
	// EOM
	_, _ = respCh.Write([]byte{0, 0})
	_, _ = statCh.Write([]byte{StatusDone})
}
