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
	"syscall"
	"time"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/runtime"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/web"
)

func main() {
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
