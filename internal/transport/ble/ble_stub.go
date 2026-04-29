//go:build !ble

package ble

import "context"

// Peripheral is the device-side BLE GATT server. The default build provides
// only a no-op stub; rebuild with `-tags ble` to enable the real tinygo
// bluetooth implementation.
type Peripheral struct{}

// NewPeripheral returns a stub peripheral.
func NewPeripheral(_ string) *Peripheral { return &Peripheral{} }

// Serve always returns ErrUnsupported in the default build.
func (*Peripheral) Serve(_ context.Context, _ func([]byte) ([]byte, error)) error {
	return ErrUnsupported
}

// Relay is the gateway-side BLE central. Stubbed out in the default build.
type Relay struct{}

// NewRelay returns a stub relay.
func NewRelay() *Relay { return &Relay{} }

// Run always returns ErrUnsupported in the default build.
func (*Relay) Run(_ context.Context, _ func(req []byte) (resp []byte, err error)) error {
	return ErrUnsupported
}
