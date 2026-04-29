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

	// Advertisement payload sizing for BLE 4.x: 31-byte cap on the
	// primary PDU. A 128-bit service UUID consumes 18 bytes
	// (1 length + 1 AD type + 16 bytes value), leaving only 13 bytes
	// for everything else after the 3-byte Flags AD type — and BlueZ
	// frequently auto-adds a 3-byte TX-Power AD entry on top, leaving
	// just ~10 bytes for a LocalName AD entry (which itself costs 2
	// bytes of header), i.e. up to 8 chars of name.
	//
	// The previous default ("ztp-rpi4-d83add90fe56", 23 chars) blew
	// past that limit, so BlueZ pushed either the UUID or the name
	// into the scan response. WinRT centrals default to PASSIVE scan
	// mode, which discards scan-response data, so the device became
	// effectively invisible to Windows ("0 of 600+ scanned
	// advertisements matched ZTP", with intermittent successes
	// whenever Windows happened to dedupe down to the right slice).
	//
	// Setting LocalName to the short literal AdvertisedLocalName
	// (rather than leaving it empty) is the robust fix: it overrides
	// BlueZ's default of falling back to the adapter alias when
	// "local-name" is in `Includes`, which tinygo doesn't expose. The
	// peripheral's full identity is still exposed via the enrollment
	// envelope (device_id field) and any GAP Device Name read after
	// connect.
	adv := p.adapter.DefaultAdvertisement()
	if err := adv.Configure(bluetooth.AdvertisementOptions{
		LocalName:    AdvertisedLocalName,
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
