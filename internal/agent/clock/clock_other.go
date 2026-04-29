//go:build !unix

package clock

import "time"

func setSystemClock(_ time.Time) error {
	return ErrUnsupported
}
