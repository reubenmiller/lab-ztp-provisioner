//go:build !darwin

package mdns

// bonjourProc is a no-op on non-Darwin platforms. mDNSResponder is macOS-only;
// on Linux, hashicorp/mdns answering direct multicast queries is sufficient.
type bonjourProc struct{}

func registerWithBonjour(_, _ string, _ int, _ []string) bonjourProc { return bonjourProc{} }
func (b bonjourProc) stop()                                          {}
