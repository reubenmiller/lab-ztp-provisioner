//go:build unix

package clock

import (
	"time"

	"golang.org/x/sys/unix"
)

// setSystemClock writes t to CLOCK_REALTIME via settimeofday(2). Requires
// CAP_SYS_TIME on Linux (or root). On failure it returns the underlying
// errno wrapped by the unix package — typically EPERM when the agent is
// running unprivileged.
func setSystemClock(t time.Time) error {
	tv := unix.NsecToTimeval(t.UnixNano())
	return unix.Settimeofday(&tv)
}
