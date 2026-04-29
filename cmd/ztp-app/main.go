// ztp-app is the Wails desktop binary. It wraps the same SvelteKit
// admin SPA shipped by ztp-server in a native window, runs the engine
// in-process on a loopback ephemeral port, and (once PR 4 lands) adds
// a native BLE central binding so device onboarding works without a
// Chromium-based Web Bluetooth host.
//
// Layout: main.go is intentionally thin. All long-lived logic lives
// in internal/server/runtime (engine wire-up) and internal/desktop
// (Wails bindings). Keeping the main file boring lets the desktop
// app share 100% of its server logic with cmd/ztp-server.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/mac"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/desktop"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/initdir"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/runtime"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/web"
)

func main() {
	// Subcommand sniff: `ztp-app init [dir]` scaffolds a data
	// directory and exits BEFORE any flag parsing or Wails
	// initialisation, mirroring `ztp-server init`. Done by raw
	// os.Args inspection so the Windows windowsgui build (where
	// flag.Parse failures would be invisible) can never accidentally
	// fall through to launching the GUI when the operator typed
	// "init". attachParentConsole reattaches stdio to the calling
	// shell's console on Windows so the printed output is actually
	// visible — it's a no-op on Linux/macOS.
	if len(os.Args) > 1 && os.Args[1] == "init" {
		attachParentConsole()
		if err := runInit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			os.Exit(1)
		}
		return
	}

	// Flags must be defined BEFORE the help check, otherwise
	// flag.PrintDefaults inside printAppUsage has nothing to
	// enumerate and the "Flags:" section comes back empty.
	flag.Usage = func() { printAppUsage(flag.CommandLine.Output()) }
	configPath := flag.String("config", "",
		"path to a YAML config (e.g. deploy/config/ztp-app.yaml) "+
			"to reuse the docker-compose stack's persistent state. "+
			"When empty, the app looks for ./ztp-server.yaml in the "+
			"working directory; if that's also missing, the app runs "+
			"with a fresh in-memory store and ephemeral keys.")
	listenFlag := flag.String("listen", "",
		"TCP listen address. Default 127.0.0.1:0 (loopback only, ephemeral port). "+
			"Pass e.g. ':8080' to make the engine reachable from the LAN — needed "+
			"for -mdns to be useful. Loopback default keeps an unattended desktop "+
			"app off the network.")
	mdnsFlag := flag.Bool("mdns", false,
		"advertise the engine on the LAN via mDNS-SD (_ztp._tcp). Implies "+
			"-listen :8080 unless -listen is set explicitly. Devices running "+
			"ztp-agent with no -server flag will discover and enroll automatically.")
	verbose := flag.Bool("v", false, "verbose logging")

	if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help") {
		attachParentConsole()
		printAppUsage(os.Stdout)
		return
	}
	flag.Parse()

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	listenAddr := resolveListenAddr(*listenFlag, *mdnsFlag)

	cfg, err := loadConfig(*configPath, *mdnsFlag, listenAddr, logger)
	if err != nil {
		logger.Error("load config", "err", err)
		os.Exit(1)
	}

	token, err := generateAdminToken()
	if err != nil {
		logger.Error("token generation failed", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ListenOverride trumps any YAML 'listen:' so an operator who
	// copy-pastes a production server YAML can't accidentally make
	// the desktop app bind on a different address than they asked
	// for via the CLI flags.
	h, err := runtime.Start(ctx, runtime.Options{
		Config:              cfg,
		Logger:              logger,
		ListenOverride:      listenAddr,
		AdminTokenOverride:  token,
		EmbeddedSPA:         web.EmbeddedFS(),
		RuntimeMode:         "desktop",
		RuntimeCapabilities: desktop.Capabilities(),
	})
	if err != nil {
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}

	// Watch the listener — if it dies the engine is unusable. Tear
	// the window down to avoid showing a zombie UI talking to nothing.
	go func() {
		if err := <-h.ServeErr(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("engine listener died", "err", err)
			cancel()
		}
	}()

	// Wails' webview origin is wails://wails.localhost (or similar
	// per-platform); fetch('/v1/...') lands on AssetsHandler. Proxy
	// every asset request to the in-process engine via 127.0.0.1 —
	// not via h.BaseURL directly, since when -listen is ":8080" the
	// listener binds on all interfaces and BaseURL becomes "[::]:8080"
	// which httputil refuses to dial. Loopback always works.
	//
	// FlushInterval bounds buffering so SSE streams (admin pending
	// stream) feel live — net/http's ReverseProxy is otherwise free
	// to coalesce small chunks.
	loopbackURL, err := loopbackProxyTarget(h.BaseURL)
	if err != nil {
		logger.Error("parse base url", "url", h.BaseURL, "err", err)
		os.Exit(1)
	}
	proxy := httputil.NewSingleHostReverseProxy(loopbackURL)
	proxy.FlushInterval = 100 * time.Millisecond

	app := desktop.New(h)

	// SIGINT/SIGTERM handler runs alongside Wails' own window-close
	// hook so the engine shuts down cleanly whether the user clicks
	// the close button or kills the process from a terminal.
	//
	// Shutdown signals the SSE hub before draining HTTP, so the
	// long-lived /v1/admin/pending/stream connection doesn't pin the
	// drain phase open. 2s is plenty for the remaining short-lived
	// admin requests; a hung backend should not delay window close.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		<-sigCh
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = h.Shutdown(shutdownCtx)
		os.Exit(0)
	}()

	if err := wails.Run(&options.App{
		Title:  "ZTP",
		Width:  1280,
		Height: 800,
		AssetServer: &assetserver.Options{
			Handler: proxy,
		},
		Mac: &mac.Options{
			About: &mac.AboutInfo{
				Title:   "ZTP — Zero-Touch Provisioning",
				Message: "Onboard devices automatically via mDNS or BLE.",
				Icon:    appIcon,
			},
		},
		OnStartup: func(wctx context.Context) {
			// Stash the Wails-supplied context so binding methods
			// can call wruntime.EventsEmit. Without this the BLE
			// progress events would silently drop.
			app.SetContext(wctx)
		},
		OnShutdown: func(_ context.Context) {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = h.Shutdown(shutdownCtx)
		},
		Bind: []any{app},
	}); err != nil {
		logger.Error("wails run", "err", err)
		os.Exit(1)
	}
}

// runInit scaffolds a ZTP data directory and exits. Shares the
// underlying scaffold with `ztp-server init <dir>` so the desktop app
// and the CLI produce identical layouts. The printed launch line
// points back at this same binary, which is the preferred desktop
// workflow (persistent SQLite + persistent keys).
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.Usage = func() {
		fmt.Fprintln(os.Stdout, "Usage: ztp-app init [dir]")
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "Scaffold a ZTP data directory at <dir> (default '.').")
		fmt.Fprintln(os.Stdout, "Existing files are preserved; safe to re-run on a partial tree.")
		fmt.Fprintln(os.Stdout, "")
		fmt.Fprintln(os.Stdout, "After init, launch the app from the same directory with:")
		fmt.Fprintln(os.Stdout, "  ztp-app")
	}
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir := "."
	if fs.NArg() > 0 {
		dir = fs.Arg(0)
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	res, err := initdir.Scaffold(initdir.Options{Dir: dir, Logger: logger})
	if err != nil {
		return err
	}
	fmt.Println()
	fmt.Println("ZTP data directory initialised at", res.Dir)
	fmt.Println()
	fmt.Println("  config         ", res.ConfigPath)
	fmt.Println("  admin token    ", res.AdminToken)
	fmt.Println("  signing pubkey ", res.SigningPubB64)
	fmt.Println("  age recipient  ", res.AgeRecipient)
	fmt.Println()
	fmt.Println("Launch the desktop app against this data with:")
	fmt.Println()
	fmt.Println("  cd", res.Dir)
	fmt.Println("  ztp-app")
	fmt.Println()
	if len(res.Skipped) > 0 {
		fmt.Println("Note: the following files already existed and were left untouched:")
		for _, s := range res.Skipped {
			fmt.Println("  -", s)
		}
		fmt.Println()
	}
	return nil
}

// printAppUsage writes the top-level help banner for `ztp-app`. Goes
// to stdout (not stderr) when the user explicitly asked for help so
// piping into `less` / clipboard works the way operators expect.
func printAppUsage(out io.Writer) {
	fmt.Fprintln(out, "ZTP desktop — bundles the SPA, the engine, and a native BLE relay.")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  ztp-app                       launch the GUI (uses ./ztp-server.yaml if present)")
	fmt.Fprintln(out, "  ztp-app -config <path>        launch with the given config")
	fmt.Fprintln(out, "  ztp-app init [dir]            scaffold a data directory and exit")
	fmt.Fprintln(out, "  ztp-app -h | --help           show this help")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Flags:")
	flag.PrintDefaults()
}

// generateAdminToken mints a 32-byte random token rendered as
// URL-safe base64. Length matches the >=16 char minimum the runtime
// enforces; the kind of token an operator would otherwise hand-write
// into config.
func generateAdminToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// resolveListenAddr applies the flag-resolution rules:
//   - explicit -listen wins
//   - -mdns alone implies ":8080" so the advertised SRV record
//     points at something LAN-reachable
//   - neither: loopback ephemeral, the safe default
func resolveListenAddr(listenFlag string, mdns bool) string {
	if listenFlag != "" {
		return listenFlag
	}
	if mdns {
		return ":8080"
	}
	return "127.0.0.1:0"
}

// loadConfig either loads a YAML file (when configPath is set, e.g.
// pointed at deploy/config/ztp-app.yaml so the desktop app reuses
// the docker stack's signing key, age key, SQLite DB, and profiles)
// or returns a minimal in-memory config (when empty, every launch is
// a fresh session).
//
// TLS is always stripped: the desktop app's listener is plain HTTP
// regardless of YAML, since the Wails webview proxies via AssetsHandler
// and self-signed certs on localhost trigger browser warnings inside
// the embedded webview. The bearer token is the auth boundary.
//
// mDNS is stripped UNLESS the operator explicitly opts in via -mdns
// (or sets mdns.enabled in YAML). When -mdns is set we force-enable
// regardless of YAML so the flag is sufficient on its own. The
// advertised port comes from listenAddr so the SRV record matches
// what we actually bind.
func loadConfig(configPath string, mdnsFlag bool, listenAddr string, logger *slog.Logger) (*config.Config, error) {
	// Implicit default: when -config is not set, look for an
	// init-scaffolded ztp-server.yaml in the working directory. If
	// found, use it; otherwise fall back to ephemeral in-memory.
	// This makes `cd <dir> && ztp-app` Just Work after `ztp-app init <dir>`.
	if configPath == "" {
		if _, err := os.Stat("ztp-server.yaml"); err == nil {
			configPath = "ztp-server.yaml"
			logger.Info("auto-detected local config", "path", configPath)
		}
	}
	var cfg *config.Config
	if configPath == "" {
		cfg = &config.Config{
			Listen: "127.0.0.1:0",
			Store:  config.StoreConfig{Driver: "memory"},
		}
	} else {
		c, err := config.Load(configPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", configPath, err)
		}
		cfg = c
		logger.Info("loaded config — reusing persistent state",
			"signing_key_file", cfg.SigningKeyFile,
			"age_key_file", cfg.AgeKeyFile,
			"store", cfg.Store.Driver,
			"profiles_dir", cfg.ProfilesDir)
	}
	// TLS always stripped (see doc above).
	cfg.TLS = config.TLSConfig{}

	// mDNS: respect YAML if set, override-on with -mdns flag, else
	// disable. The mdns advertised port must match the actual TCP
	// port we'll bind, so re-derive it from listenAddr (which already
	// reflects flag + YAML resolution upstream).
	if mdnsFlag {
		cfg.MDNS.Enabled = true
	}
	if cfg.MDNS.Enabled {
		if cfg.MDNS.Service == "" {
			cfg.MDNS.Service = "_ztp._tcp"
		}
		if port := portFromAddr(listenAddr); port != 0 {
			cfg.MDNS.Port = port
		}
		logger.Info("mDNS-SD enabled", "service", cfg.MDNS.Service, "advertised_port", cfg.MDNS.Port)
	} else {
		cfg.MDNS = config.MDNSConfig{}
	}
	return cfg, nil
}

// portFromAddr extracts a TCP port number from an address like ":8080"
// or "127.0.0.1:8080". Returns 0 for ":0" (kernel-assigned, unknown at
// startup) — runtime.Start's parsePort fallback (8080) takes over in
// that case for mDNS purposes; loopback ephemeral mode shouldn't be
// advertising anyway.
func portFromAddr(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(p)
	if err != nil || n == 0 {
		return 0
	}
	return n
}

// loopbackProxyTarget rewrites the engine's BaseURL to use 127.0.0.1
// regardless of what interface the listener bound. When -listen is
// ":8080" the kernel binds on all interfaces and Addr().String() is
// "[::]:8080"; httputil.ReverseProxy can't dial that as a host. The
// port survives — the URL we synthesize keeps everything else.
func loopbackProxyTarget(baseURL string) (*url.URL, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	port := u.Port()
	if port == "" {
		return nil, fmt.Errorf("missing port in base url %q", baseURL)
	}
	u.Host = net.JoinHostPort("127.0.0.1", port)
	return u, nil
}
