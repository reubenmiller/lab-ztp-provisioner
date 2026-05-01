// Package facts collects identity-relevant information about the device for
// inclusion in EnrollRequest.Facts. Each function is best-effort: a missing
// field on an unusual platform is fine, the operator will still see something
// in the pending-approvals UI thanks to other facts.
package facts

import (
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// Collect returns a populated DeviceFacts for the current host.
func Collect(agentVersion string) protocol.DeviceFacts {
	f := protocol.DeviceFacts{
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		AgentVersion: agentVersion,
	}
	if h, err := os.Hostname(); err == nil {
		f.Hostname = h
	}
	if mid, err := os.ReadFile("/etc/machine-id"); err == nil {
		f.MachineID = strings.TrimSpace(string(mid))
	}
	if serial, err := os.ReadFile("/sys/firmware/devicetree/base/serial-number"); err == nil {
		f.Serial = strings.Trim(strings.TrimSpace(string(serial)), "\x00")
	}
	if model, err := os.ReadFile("/sys/firmware/devicetree/base/model"); err == nil {
		f.Model = strings.Trim(strings.TrimSpace(string(model)), "\x00")
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifc := range ifaces {
			if ifc.Flags&net.FlagLoopback != 0 {
				continue
			}
			if ifc.HardwareAddr == nil {
				continue
			}
			mac := ifc.HardwareAddr.String()
			if mac != "" {
				f.MACAddresses = append(f.MACAddresses, mac)
			}
		}
	}
	f.OSPrettyName = osReleasePrettyName()
	return f
}

// osReleasePrettyName parses /etc/os-release to extract the PRETTY_NAME value.
// Returns empty string on any error (file absent, field missing, non-Linux).
func osReleasePrettyName() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "PRETTY_NAME=") {
			continue
		}
		val := strings.TrimPrefix(line, "PRETTY_NAME=")
		// Strip surrounding double-quotes if present.
		val = strings.Trim(strings.TrimSpace(val), `"`)
		return val
	}
	return ""
}
