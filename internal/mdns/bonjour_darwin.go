//go:build darwin

package mdns

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// bonjourProc wraps a dns-sd subprocess that keeps a service registered
// with mDNSResponder for the lifetime of the Publisher.
type bonjourProc struct {
	cmd *exec.Cmd
}

// registerWithBonjour spawns `dns-sd -R <instance> <type> local <port> [txt...]`
// so that the service appears in dns-sd -B and is visible to the system
// resolver on macOS. The hashicorp/mdns server handles direct multicast
// queries from Go agents; this call handles everything that goes through
// mDNSResponder (Bonjour, dns-sd, Finder, iOS, etc.).
//
// Failure is non-fatal and logged at WARN: the Publisher still works for
// direct mDNS queriers even without mDNSResponder registration.
func registerWithBonjour(service string, port int, host string, info []string) bonjourProc {
	if _, err := exec.LookPath("dns-sd"); err != nil {
		slog.Warn("bonjour: dns-sd not found; skipping mDNSResponder registration", "err", err)
		return bonjourProc{}
	}

	// Strip .local suffix from host for the instance name.
	instance := strings.TrimSuffix(host, ".local")
	instance = strings.TrimSuffix(instance, ".")
	if instance == "" {
		instance = "ZTP Server"
	}

	// dns-sd -R <Name> <Type> <Domain> <Port> [<TXT>...]
	args := []string{"-R", instance, service, "local", fmt.Sprint(port)}
	args = append(args, info...)

	cmd := exec.Command("dns-sd", args...)
	if err := cmd.Start(); err != nil {
		slog.Warn("bonjour: failed to start dns-sd registration", "err", err)
		return bonjourProc{}
	}
	slog.Info("bonjour: registered with mDNSResponder via dns-sd",
		"instance", instance, "service", service, "port", port)
	return bonjourProc{cmd: cmd}
}

func (b bonjourProc) stop() {
	if b.cmd == nil || b.cmd.Process == nil {
		return
	}
	_ = b.cmd.Process.Kill()
	_ = b.cmd.Wait()
}
