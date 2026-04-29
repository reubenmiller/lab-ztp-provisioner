// ztp-server is the Zero-Touch Provisioning server.
//
// It accepts EnrollRequests from devices, runs them through a configurable
// trust chain (allowlist, bootstrap token, known keypair, TPM stub), and
// either issues a signed ProvisioningBundle, queues the request for manual
// approval, or rejects it. Operators interact via the /v1/admin/* REST API
// (and a separate Svelte SPA in web/).
//
// Almost all of the bring-up logic lives in internal/server/runtime so it
// can be reused unchanged by the cmd/ztp-app Wails desktop binary. This
// main is intentionally thin: parse flags, call runtime.Start, wire OS
// signals to the returned Handle, exit cleanly.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/initdir"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/runtime"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/web"
)

func main() {
	// Subcommand sniff: `ztp-server init [dir]` scaffolds a fresh data
	// directory and exits before any normal-server flag handling. Done
	// here rather than via a real flag so the existing CLI surface
	// (`-config …`, `-print-pubkey`, etc.) is unchanged.
	if len(os.Args) > 1 && os.Args[1] == "init" {
		if err := runInit(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "init:", err)
			os.Exit(1)
		}
		return
	}

	configPath := flag.String("config", "ztp-server.yaml", "path to config file")
	verbose := flag.Bool("v", false, "verbose logging")
	printPubkey := flag.Bool("print-pubkey", false, "print the server's signing public key (base64) and exit")
	agentScriptPath := flag.String("agent-script", "/usr/local/share/ztp/ztp-agent.sh",
		"optional path to a POSIX shell agent script to host at GET /v1/agent.sh; "+
			"missing file is logged and the route returns 404")
	flag.Parse()

	logLevel := slog.LevelInfo
	if *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	// -print-pubkey is a fast path: load just enough config to mint or
	// read the signing key, print it, exit. We deliberately do not call
	// runtime.Start for this since it would require admin_token and
	// open the store / bind the listener.
	if *printPubkey {
		if err := printSigningPubkey(*configPath); err != nil {
			logger.Error("print-pubkey", "err", err)
			os.Exit(1)
		}
		return
	}

	agentScript := loadAgentScript(*agentScriptPath, logger)

	ctx := context.Background()
	h, err := runtime.Start(ctx, runtime.Options{
		ConfigPath:  *configPath,
		Logger:      logger,
		AgentScript: agentScript,
		EmbeddedSPA: web.EmbeddedFS(),
	})
	if err != nil {
		// admin-token problems should exit 2 to match the previous CLI
		// contract; everything else is a generic 1.
		if errors.Is(err, runtime.ErrAdminTokenRequired) || errors.Is(err, runtime.ErrAdminTokenTooShort) {
			logger.Error(err.Error())
			os.Exit(2)
		}
		logger.Error("startup failed", "err", err)
		os.Exit(1)
	}

	// Surface a fatal Serve error: if the listener dies for any reason
	// other than a clean Shutdown, exit 1 so an init system restarts us.
	go func() {
		if err := <-h.ServeErr(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server", "err", err)
			os.Exit(1)
		}
	}()

	// Graceful shutdown + SIGHUP-driven profile reload. SIGHUP rereads
	// the profile directory and re-resolves c8y issuers; on error the
	// previously loaded profile set stays in place (FileLoader.Load
	// swaps atomically only on a clean read).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	for {
		s := <-sigCh
		if s == syscall.SIGHUP {
			logger.Info("SIGHUP: reloading profiles")
			_ = h.Reload(context.Background())
			continue
		}
		break
	}
	logger.Info("shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = h.Shutdown(ctx)
}

// printSigningPubkey loads the signing key from the configured location
// (or generates an ephemeral one) and prints its public part as base64.
// Mirrors the old `-print-pubkey` flag exactly.
func printSigningPubkey(configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	key, err := cfg.LoadOrCreateSigningKey()
	if err != nil {
		return fmt.Errorf("signing key: %w", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)))
	return nil
}

// runInit handles the `ztp-server init [dir]` subcommand. It scaffolds
// a directory tree containing ztp-server.yaml, signing/age keys, a
// minimal default profile, and an .env file with a freshly minted
// admin token. Idempotent — re-running fills missing pieces and
// preserves existing keys/configs/tokens.
func runInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "Usage: ztp-server init [dir]")
		fmt.Fprintln(fs.Output(), "")
		fmt.Fprintln(fs.Output(), "Scaffold a ZTP server data directory at <dir> (default '.').")
		fmt.Fprintln(fs.Output(), "Existing files are preserved; safe to re-run on a partial tree.")
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
	fmt.Println("ZTP server initialised at", res.Dir)
	fmt.Println()
	fmt.Println("  config        ", res.ConfigPath)
	fmt.Println("  admin token   ", res.AdminToken, "(also in", relPath(res.Dir, res.EnvPath)+")")
	fmt.Println("  signing pubkey", res.SigningPubB64)
	fmt.Println("  age recipient ", res.AgeRecipient)
	fmt.Println("  default profile", relPath(res.Dir, res.ProfilePath))
	fmt.Println()
	fmt.Println("Run the server with:")
	fmt.Println()
	fmt.Println("  cd", res.Dir)
	fmt.Println("  ZTP_ADMIN_TOKEN=$(grep '^ZTP_ADMIN_TOKEN=' .env | cut -d= -f2-) ztp-server -config ztp-server.yaml")
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

func relPath(base, target string) string {
	if r, err := filepath.Rel(base, target); err == nil {
		return r
	}
	return target
}

// loadAgentScript best-effort loads the POSIX shell agent so
// /v1/agent.sh can serve it. Missing or unreadable scripts are logged
// but not fatal — operators who don't want the bootstrap-pipe workflow
// can leave the flag empty or point at a non-existent path.
func loadAgentScript(path string, logger *slog.Logger) []byte {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		logger.Warn("agent script not loaded; /v1/agent.sh will return 404",
			"path", path, "err", err)
		return nil
	}
	logger.Info("agent script loaded for /v1/agent.sh", "path", path, "bytes", len(data))
	return data
}
