package runtime

import (
	"io/fs"
	"log/slog"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
)

// Options control how Start brings the engine, store, profile loader,
// HTTP API, and (optionally) mDNS publisher up. Both the cmd/ztp-server
// process and the cmd/ztp-app Wails desktop binary call Start with
// different option shapes; the package itself stays process-agnostic.
//
// Either ConfigPath or Config must be set. Config wins if both are
// present, which lets the desktop app build a *config.Config in-memory
// without ever touching disk.
type Options struct {
	// ConfigPath is the path to a YAML config file. Read with config.Load.
	ConfigPath string

	// Config is a pre-loaded configuration. When non-nil, ConfigPath is ignored.
	Config *config.Config

	// Logger replaces the default slog logger. When nil, slog.Default() is used.
	Logger *slog.Logger

	// ListenOverride, when non-empty, replaces cfg.Listen. The desktop
	// app sets this to "127.0.0.1:0" so the kernel picks an ephemeral
	// port and the resulting Handle.BaseURL points at it.
	ListenOverride string

	// AdminTokenOverride, when non-empty, replaces both the config's
	// admin_token field and the ZTP_ADMIN_TOKEN env var. The desktop
	// app generates a random token at startup and passes it here.
	AdminTokenOverride string

	// AgentScript is the optional POSIX shell agent script served at
	// GET /v1/agent.sh. Empty means the route returns 404. cmd/ztp-server
	// reads it from a flag-supplied path; other entry points may pass
	// embedded bytes or leave it nil.
	AgentScript []byte

	// EmbeddedSPA is the in-binary SPA assets used when web.dir is
	// empty in config. cmd/ztp-server passes web.EmbeddedFS(); the
	// desktop binary will pass its own. nil leaves the SPA disabled
	// unless web.dir picks up an external directory.
	EmbeddedSPA fs.FS

	// RuntimeMode populates GET /v1/runtime-config. Empty defaults to
	// "browser" at handler time. cmd/ztp-app sets this to "desktop"
	// so the SPA can skip its login modal and prefer native bindings.
	RuntimeMode string

	// RuntimeCapabilities is the optional capability list the SPA
	// uses to feature-detect, e.g. "ble.central.native" for the
	// desktop app's Wails-bound BLE relay.
	RuntimeCapabilities []string
}
