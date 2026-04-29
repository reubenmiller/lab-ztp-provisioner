//go:build ble && !(linux || windows)

// Peripheral is not supported on this platform: the tinygo.org/x/bluetooth
// library only exposes GATT server (peripheral) APIs on Linux (BlueZ) and
// Windows. Central-mode (Relay, Enroll) DOES work on macOS via CoreBluetooth
// and lives in central.go.

package ble

import "context"

// Peripheral is a no-op stub on platforms other than Linux / Windows.
type Peripheral struct{}

// NewPeripheral returns a stub peripheral.
func NewPeripheral(_ string) *Peripheral { return &Peripheral{} }

// Serve always returns ErrUnsupported on this platform. Use Linux or Windows
// to run a BLE peripheral device agent.
func (*Peripheral) Serve(_ context.Context, _ func([]byte) ([]byte, error)) error {
	return ErrUnsupported
}
