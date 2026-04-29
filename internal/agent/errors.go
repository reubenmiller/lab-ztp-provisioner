package agent

import (
	"errors"
	"fmt"
)

// ErrServerUnreachable is returned by Run when MaxNetworkFailures consecutive
// network-level errors occur. The outer transport dispatcher treats this as a
// signal to try the next transport (e.g. BLE) rather than aborting entirely.
var ErrServerUnreachable = errors.New("server unreachable")

// ErrEnrollRejected is returned when the server definitively rejects a device's
// enrollment request. It is terminal — the caller must NOT fall back to another
// transport; the device needs operator intervention.
type ErrEnrollRejected struct {
	Reason string
}

func (e ErrEnrollRejected) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("server rejected enrollment: %s", e.Reason)
	}
	return "server rejected enrollment"
}

// Is enables errors.Is matching on the type alone (reason is ignored).
func (e ErrEnrollRejected) Is(target error) bool {
	_, ok := target.(ErrEnrollRejected)
	return ok
}
