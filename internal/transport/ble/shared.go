//go:build ble && (linux || windows || darwin)

// Helpers shared by ble.go (peripheral; linux+windows) and central.go
// (central; linux+windows+darwin). The narrowest common build tag is
// just `ble && (linux || windows || darwin)`, matching central.go.

package ble

import (
	"fmt"

	"tinygo.org/x/bluetooth"
)

// fragSize is the BLE write fragment size used by both ends of the
// chunked-message framing. 180 bytes leaves room under most ATT MTUs
// (which negotiate up from the 23-byte default) without forcing the
// transport to fragment further.
const fragSize = 180

// parseUUID is a thin wrapper around bluetooth.ParseUUID that panics
// on failure. Used only with our hard-coded service/characteristic
// UUIDs in doc.go — those are constants and a parse error is a code
// bug, not a runtime input problem.
func parseUUID(s string) bluetooth.UUID {
	u, err := bluetooth.ParseUUID(s)
	if err != nil {
		panic(fmt.Sprintf("invalid uuid %q: %v", s, err))
	}
	return u
}
