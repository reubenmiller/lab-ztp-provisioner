// Package ble defines the BLE GATT transport used between an unconnected
// device and a "relay" (a phone or LAN gateway) which forwards the encrypted
// enrollment exchange to the ZTP server.
//
// The transport is tag-gated:
//
//	go build              → uses the no-op stub in this file (returns ErrUnsupported)
//	go build -tags ble    → uses the tinygo.org/x/bluetooth implementation
//
// This keeps the default build CGO-free and platform-portable while allowing
// device images to opt in to BLE on systems that have BlueZ / CoreBluetooth /
// Windows Bluetooth available.
//
// Wire layout (chunked over notify because GATT MTU is small):
//
//	Service UUID:                  6e400001-b5a3-f393-e0a9-e50e24dcca9e
//	   - "request"  characteristic (write/no-resp): EnrollRequest envelope (JSON)
//	   - "response" characteristic (notify):        EnrollResponse JSON
//	   - "status"   characteristic (notify):        u8 — 0=idle 1=relaying 2=done 3=error
//
// Both ends frame messages as: 2-byte big-endian length, payload bytes,
// repeated until length == 0 (end of message).
package ble

import "errors"

// ErrUnsupported is returned by the stub when the binary was built without
// the "ble" build tag.
var ErrUnsupported = errors.New("BLE transport not built in (rebuild with -tags ble)")

// Service / characteristic UUIDs (Nordic UART-derived for compatibility with
// generic BLE tooling).
const (
	ServiceUUID  = "6e400001-b5a3-f393-e0a9-e50e24dcca9e"
	RequestUUID  = "6e400002-b5a3-f393-e0a9-e50e24dcca9e"
	ResponseUUID = "6e400003-b5a3-f393-e0a9-e50e24dcca9e"
	StatusUUID   = "6e400004-b5a3-f393-e0a9-e50e24dcca9e"
	// TimeSyncUUID is a write-only characteristic the relay (central) writes
	// an RFC3339 UTC timestamp to before enrollment. The peripheral reads it
	// to correct its local clock offset so the EnrollRequest timestamp passes
	// the server's skew check — needed on devices that haven't run NTP yet.
	TimeSyncUUID = "6e400005-b5a3-f393-e0a9-e50e24dcca9e"

	StatusIdle     byte = 0
	StatusRelaying byte = 1
	StatusDone     byte = 2
	StatusError    byte = 3

	// AdvertisedLocalName is the short literal peripherals put in the
	// LocalName AD entry of their primary BLE advertisement. It is
	// deliberately tiny (3 chars + 2-byte AD header = 5 bytes) so the
	// 128-bit service UUID (18 bytes) plus Flags (3 bytes) plus an
	// auto-added TX-Power entry (3 bytes) all fit inside the 31-byte
	// primary-PDU cap on every BlueZ build, regardless of the
	// adapter's alias / hostname. The peripheral's *real* identity
	// (machine-id, hostname, tedge-identity) is shipped inside the
	// enrollment envelope, so this short advertised label only has to
	// be unique-ish among ZTP devices on the same airwave — a prefix
	// match is enough for the central scan filter.
	AdvertisedLocalName = "ztp"

	// LocalNamePrefix is what centrals match when filtering scan
	// results by name. It must be a prefix of AdvertisedLocalName so
	// the peripheral's own advertisement triggers the match, but
	// short enough to also catch legacy peripherals whose advertised
	// LocalName is the longer device id (e.g. "ztp-rpi4-…") that
	// earlier builds emitted before the 31-byte sizing was tightened.
	LocalNamePrefix = "ztp"
)
