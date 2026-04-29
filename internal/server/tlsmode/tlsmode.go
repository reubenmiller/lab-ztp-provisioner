// Package tlsmode chooses how the server's HTTPS listener is set up.
// It exists so cmd/ztp-server (a long-running daemon, often behind a
// reverse proxy) and cmd/ztp-app (a desktop binary on a laptop) can
// share TLS-listener semantics while plugging the choice in via
// config.
//
// Modes:
//
//	off        — plain HTTP. Used by the docker-compose stack with
//	             Caddy in front, and by the desktop app on loopback.
//	cert       — operator-supplied PEM cert + key on disk (the
//	             pre-existing tls.cert / tls.key behaviour).
//	selfsigned — generate a self-signed cert on first run, cache it
//	             under paths.TLSCacheDir(); regenerate when expired.
//	             Useful for local-LAN deployments without Caddy /
//	             ACME / mkcert.
//
// ACME (autocert) is intentionally not in this package yet — it
// belongs in a follow-up PR alongside autocert.Manager wiring and a
// dedicated tls.acme.host config field.
package tlsmode

import (
	"errors"
	"strings"
)

// Mode is the chosen TLS-listener strategy.
type Mode string

const (
	// Off serves plain HTTP. The bearer-token check on /v1/admin is
	// the auth boundary; transport security is the deployer's
	// responsibility (typically a reverse proxy or loopback).
	Off Mode = "off"

	// Cert uses an operator-supplied PEM cert + key on disk.
	Cert Mode = "cert"

	// SelfSigned generates and caches a self-signed cert.
	SelfSigned Mode = "selfsigned"
)

// Parse normalises a YAML / CLI string into a Mode. Empty, "none",
// "plain", and "http" are all treated as Off so config files can use
// the spelling that reads best in context. Returns an error for an
// unknown spelling so misconfiguration fails fast at startup.
func Parse(s string) (Mode, error) {
	switch strings.TrimSpace(strings.ToLower(s)) {
	case "", "off", "none", "plain", "http":
		return Off, nil
	case "cert", "file", "manual":
		return Cert, nil
	case "selfsigned", "self-signed", "self_signed":
		return SelfSigned, nil
	}
	return "", errors.New("unknown tls.mode: " + s)
}
