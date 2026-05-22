// Package zenoh implements ZTP device discovery over a Zenoh router.
//
// Build with -tags zenoh to include the real implementation; without the tag
// only no-op stubs are compiled and all operations return [ErrUnsupported].
//
// Requirements for the real build:
//
//   - zenoh-c installed on the build host (https://github.com/eclipse-zenoh/zenoh-c),
//     compiled with -DZENOHC_BUILD_WITH_UNSTABLE_API=ON.
//   - CGO_ENABLED=1.
//   - The zenoh-go module:
//     GOFLAGS="-tags=zenoh" go get github.com/eclipse-zenoh/zenoh-go@v1.9.0
//
// Key expression topology:
//
//	ztp/discovery/request/<device_uuid>  — agent → server (beacon)
//	ztp/discovery/approve/<device_uuid>  — server → agent (approval + server URL)
package zenoh

import "errors"

// ErrUnsupported is returned when any operation is called on a build that was
// compiled without the zenoh build tag.
var ErrUnsupported = errors.New(
	"zenoh discovery not built in (rebuild with -tags zenoh and zenoh-c installed)",
)
