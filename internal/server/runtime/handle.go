package runtime

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net/http"

	"filippo.io/age"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/mdns"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/api"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/profiles"
)

// Handle is what Start returns. It owns the HTTP server, mDNS
// publisher, profile loader/resolver, and the keys the engine signs
// with. The cmd-level entrypoint wires OS signals to Reload (SIGHUP)
// and Shutdown (SIGINT/SIGTERM); the desktop app calls Shutdown on
// window close.
type Handle struct {
	// Config is the resolved configuration after defaults and overrides.
	Config *config.Config

	// SigningKey is the Ed25519 private key the engine signs bundles with.
	SigningKey ed25519.PrivateKey

	// SigningKeyB64 is the base64-encoded public key, suitable for
	// printing or embedding in agent trust roots.
	SigningKeyB64 string

	// AgeIdentity is the X25519 identity used to decrypt SOPS-age
	// sealed profile files at rest.
	AgeIdentity *age.X25519Identity

	// AdminToken is the resolved bearer token for /v1/admin/*. Echoed
	// here so the desktop app can hand it to its embedded SPA without
	// re-deriving it from config.
	AdminToken string

	// BaseURL is the scheme://host:port the server is listening on,
	// captured after the listener has bound (so it reflects the real
	// port even when ListenOverride was ":0").
	BaseURL string

	// MDNSActive is true when a live _ztp._tcp mDNS publisher was
	// started successfully. Mirrors api.Server.MDNSActive so callers
	// such as the desktop binding can read it without going through HTTP.
	MDNSActive bool

	logger     *slog.Logger
	server     *http.Server
	publisher  *mdns.Publisher
	fileLoader *profiles.FileLoader
	resolver   *profiles.Resolver
	hub        *api.Hub
	serveErr   chan error
}

// Reload re-reads the profile directory and re-resolves every
// profile's c8y issuer. Mirrors the SIGHUP behaviour the cmd binary
// previously implemented inline. On read error the previously loaded
// profile set stays in place — the FileLoader swaps atomically only
// on a clean read.
func (h *Handle) Reload(ctx context.Context) error {
	if h == nil || h.fileLoader == nil {
		return errors.New("runtime: Reload called on a Handle without a profile loader")
	}
	n, err := h.fileLoader.Load(ctx)
	if err != nil {
		h.logger.Error("profile reload failed; keeping previous set", "err", err)
		return err
	}
	h.logger.Info("profiles reloaded", "count", n)
	if err := resolveAllIssuers(ctx, h.resolver, h.logger); err != nil {
		h.logger.Error("issuer resolve after reload", "err", err)
		return err
	}
	return nil
}

// Shutdown stops the HTTP server (with the supplied context as the
// graceful-shutdown deadline) and closes the mDNS publisher if one
// was started. Safe to call on a nil Handle.
//
// The SSE pending stream is signalled to exit before http.Server.Shutdown
// is called: otherwise its long-lived connection blocks the graceful
// drain until the per-request context fires (whenever the browser
// happens to close it), which makes the Wails desktop app appear to
// hang for several seconds when the user clicks the window close button.
func (h *Handle) Shutdown(ctx context.Context) error {
	if h == nil {
		return nil
	}
	if h.publisher != nil {
		_ = h.publisher.Close()
	}
	if h.hub != nil {
		h.hub.Shutdown()
	}
	if h.server != nil {
		return h.server.Shutdown(ctx)
	}
	return nil
}

// ServeErr returns a channel that receives the error from the
// background Serve goroutine when the listener exits. It receives
// http.ErrServerClosed on a clean Shutdown — callers that care about
// only fatal errors should filter it out.
func (h *Handle) ServeErr() <-chan error {
	return h.serveErr
}
