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

	// LocalNamePrefix is the advertised LocalName prefix peripherals
	// use (NewPeripheral defaults to "ztp-device" but operators may
	// pass any name starting with "ztp-"). Centrals use this as a
	// secondary scan filter when the platform's BLE stack doesn't
	// surface ServiceUUIDs reliably from the advertisement payload —
	// notably WinRT, which sometimes only exposes service UUIDs via a
	// post-connect GATT discovery rather than the scan-result list.
	LocalNamePrefix = "ztp-"
)
