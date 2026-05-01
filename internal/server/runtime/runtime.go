// Package runtime is the process-agnostic seam that brings the ZTP
// server's engine, store, profile loader, HTTP API, and (optionally)
// mDNS publisher up. Both the cmd/ztp-server CLI and the cmd/ztp-app
// Wails desktop binary call Start; they share 100% of the wire-up
// logic and differ only in how they hand options in and tear the
// returned Handle down.
//
// Start used to live inline in cmd/ztp-server/main.go; extracting it
// is what makes the desktop app possible without forking the engine
// initialisation. Behaviour is intentionally identical to the
// previous main.go bring-up.
package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/mdns"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/api"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/config"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/payload"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/profiles"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/store/sqlitestore"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/tlsmode"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/trust"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/server/web"
	"github.com/thin-edge/tedge-zerotouch-provisioning/pkg/protocol"
)

// errAdminTokenRequired and errAdminTokenTooShort are exposed so
// callers can distinguish "missing admin token" (a config problem)
// from generic startup failures. The cmd binary maps both to exit
// code 2; tests can match on the value directly.
var (
	ErrAdminTokenRequired = errors.New("admin_token is required (set admin_token: in config or ZTP_ADMIN_TOKEN env)")
	ErrAdminTokenTooShort = errors.New("admin_token is too short (need at least 16 chars; generate with `openssl rand -hex 32`)")
)

// Start brings the server up: loads/generates keys, opens the store,
// builds the verifier chain, loads profiles, constructs the engine
// and HTTP API, optionally publishes mDNS, binds the listener, and
// starts serving in a background goroutine. The returned Handle owns
// the lifecycle; callers must Shutdown it.
//
// Start does not install signal handlers or block. The cmd binary
// wires SIGINT/SIGTERM/SIGHUP to Handle.Shutdown and Handle.Reload at
// process scope.
func Start(ctx context.Context, opts Options) (*Handle, error) {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	cfg, err := loadConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if opts.ListenOverride != "" {
		cfg.Listen = opts.ListenOverride
	}
	payload.SetCredentialLookup(buildC8YCredentialLookup(cfg, opts.C8YCredentialLookup))

	signingKey, err := cfg.LoadOrCreateSigningKey()
	if err != nil {
		return nil, fmt.Errorf("signing key: %w", err)
	}
	pubB64 := base64.StdEncoding.EncodeToString(signingKey.Public().(ed25519.PublicKey))
	if cfg.SigningKey == "" && cfg.SigningKeyFile == "" {
		logger.Warn("no persistent signing key configured; using ephemeral key (devices will reject the next bundle after restart)",
			"public_key", pubB64)
	} else {
		logger.Info("signing key loaded", "public_key", pubB64)
	}
	if err := cfg.WritePublicKey(pubB64); err != nil {
		logger.Warn("could not write public key file", "err", err)
	}

	// Bootstrap (or load) the age identity used for SOPS-age decryption
	// of profile files. Mirrors the signing-key flow: zero-config UX
	// for the demo stack, opt-in operator-managed key for production.
	ageIdentity, err := cfg.LoadOrCreateAgeKey()
	if err != nil {
		return nil, fmt.Errorf("age key: %w", err)
	}
	if cfg.AgeKey == "" && cfg.AgeKeyFile == "" {
		logger.Warn("no persistent age key configured; using ephemeral key (encrypted profiles will be unreadable after restart)",
			"recipient", ageIdentity.Recipient().String())
	} else {
		logger.Info("age key loaded", "recipient", ageIdentity.Recipient().String())
	}

	st, err := openStore(cfg.Store, logger)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}

	verifiers, err := buildVerifiers(cfg.Verifiers, st)
	if err != nil {
		return nil, fmt.Errorf("verifiers: %w", err)
	}

	fileLoader := profiles.NewFileLoader(cfg.ProfilesDir, logger)
	fileLoader.AgeIdentity = ageIdentity
	if n, err := fileLoader.Load(ctx); err != nil {
		return nil, fmt.Errorf("profiles load: %w", err)
	} else if cfg.ProfilesDir != "" {
		logger.Info("profiles loaded from disk", "dir", cfg.ProfilesDir, "count", n)
	}
	resolver := profiles.NewResolver(fileLoader, cfg.DefaultProfile, logger)
	if err := resolveAllIssuers(ctx, resolver, logger); err != nil {
		return nil, fmt.Errorf("profile cumulocity issuer: %w", err)
	}

	hub := api.NewHub()
	engine, err := server.NewEngine(server.EngineConfig{
		Store:        st,
		Verifiers:    verifiers,
		Resolver:     resolver,
		SigningKey:   signingKey,
		SigningKeyID: cfg.SigningKeyID,
		ClockSkew:    cfg.ClockSkew,
		Logger:       logger,
		OnPending:    hub.Notify,
	})
	if err != nil {
		return nil, fmt.Errorf("engine: %w", err)
	}

	adminToken, err := resolveAdminToken(cfg, opts)
	if err != nil {
		return nil, err
	}

	apiSrv := &api.Server{
		Engine:               engine,
		Store:                st,
		AdminToken:           adminToken,
		Logger:               logger,
		Hub:                  hub,
		Resolver:             resolver,
		ProfileLoader:        fileLoader,
		EncryptionRecipients: buildEncryptionRecipients(ageIdentity, cfg.AgeRecipients),
		ProfilesDir:          cfg.ProfilesDir,
		AgeIdentity:          ageIdentity,
	}
	if len(opts.AgentScript) > 0 {
		apiSrv.AgentScript = opts.AgentScript
	}
	apiSrv.RuntimeMode = opts.RuntimeMode
	apiSrv.RuntimeCapabilities = opts.RuntimeCapabilities
	if spa, err := buildSPAHandler(cfg.Web, opts.EmbeddedSPA, logger); err != nil {
		return nil, err
	} else if spa != nil {
		apiSrv.SPA = spa
	}

	srv := &http.Server{
		Handler:           apiSrv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Bind first, serve second. Binding first lets us read the actual
	// addr (important when the caller passed ":0" / "127.0.0.1:0") and
	// surface BaseURL through the Handle before any request races in.
	listener, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", cfg.Listen, err)
	}
	mode, err := resolveTLSMode(cfg.TLS)
	if err != nil {
		_ = listener.Close()
		return nil, err
	}
	scheme := "http"
	if mode != tlsmode.Off {
		scheme = "https"
	}
	baseURL := scheme + "://" + listener.Addr().String()

	publisher := startMDNS(cfg, pubB64, listener.Addr(), logger)
	mdnsActive := publisher != nil
	apiSrv.MDNSActive = mdnsActive

	tlsOpts := tlsmode.Options{
		CertFile:  cfg.TLS.Cert,
		KeyFile:   cfg.TLS.Key,
		Hostnames: cfg.TLS.Hostnames,
		Logger:    logger,
	}
	serveErr := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", listener.Addr().String(), "tls", mode)
		serveErr <- tlsmode.Serve(srv, listener, mode, tlsOpts)
	}()

	return &Handle{
		Config:        cfg,
		SigningKey:    signingKey,
		SigningKeyB64: pubB64,
		AgeIdentity:   ageIdentity,
		AdminToken:    adminToken,
		BaseURL:       baseURL,
		MDNSActive:    mdnsActive,
		logger:        logger,
		server:        srv,
		publisher:     publisher,
		fileLoader:    fileLoader,
		resolver:      resolver,
		hub:           hub,
		serveErr:      serveErr,
	}, nil
}

func buildC8YCredentialLookup(cfg *config.Config, overlay payload.CredentialLookup) payload.CredentialLookup {
	if (cfg == nil || len(cfg.C8YCredentials) == 0) && overlay == nil {
		return nil
	}
	return func(ref string) (payload.CredentialMaterial, bool) {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			return payload.CredentialMaterial{}, false
		}
		if overlay != nil {
			if mat, ok := overlay(ref); ok {
				return mat, true
			}
		}
		if cfg == nil {
			return payload.CredentialMaterial{}, false
		}
		cred, ok := cfg.C8YCredentials[ref]
		if !ok {
			return payload.CredentialMaterial{}, false
		}
		return payload.CredentialMaterial{
			URL:             cred.URL,
			Tenant:          cred.Tenant,
			Username:        cred.Username,
			Password:        cred.Password,
			CredentialsFile: cred.CredentialsFile,
		}, true
	}
}

// loadConfig honours the Options precedence: an inline *config.Config
// wins; otherwise read from ConfigPath.
func loadConfig(opts Options) (*config.Config, error) {
	if opts.Config != nil {
		return opts.Config, nil
	}
	if opts.ConfigPath == "" {
		return nil, errors.New("runtime: Options.ConfigPath or Options.Config must be set")
	}
	return config.Load(opts.ConfigPath)
}

// resolveAdminToken applies the override → inline → file → env
// precedence and validates length. Same rules main.go used to enforce
// inline, plus admin_token_file support so the token can come from a
// Docker secret, an init-scaffolded file, or any other on-disk source
// without ever surfacing on a process command line or in process env.
func resolveAdminToken(cfg *config.Config, opts Options) (string, error) {
	tok := opts.AdminTokenOverride
	if tok == "" {
		tok = cfg.AdminToken
	}
	if tok == "" && cfg.AdminTokenFile != "" {
		t, err := readAdminTokenFile(cfg.AdminTokenFile)
		if err != nil {
			return "", fmt.Errorf("admin_token_file: %w", err)
		}
		tok = t
	}
	if tok == "" {
		tok = os.Getenv("ZTP_ADMIN_TOKEN")
	}
	if tok == "" {
		return "", ErrAdminTokenRequired
	}
	if len(tok) < 16 {
		return "", ErrAdminTokenTooShort
	}
	return tok, nil
}

// readAdminTokenFile returns the first non-empty, non-comment line of
// the file. Comment lines start with '#'. This makes the format
// tolerant of `.env`-style files (`KEY=value` is treated as the
// literal value once we strip a leading `ZTP_ADMIN_TOKEN=`) without
// requiring a separate parser. Most operators will just write the
// raw token, which works trivially.
func readAdminTokenFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Allow `ZTP_ADMIN_TOKEN=value` so a single .env-style file
		// works for both `source .env && ztp-server` and
		// `admin_token_file: .env`.
		if eq := strings.IndexByte(line, '='); eq > 0 && line[:eq] == "ZTP_ADMIN_TOKEN" {
			line = line[eq+1:]
		}
		return strings.TrimSpace(line), nil
	}
	return "", errors.New("file is empty")
}

// startMDNS publishes the _ztp._tcp record when enabled in config.
// Failure is logged but never fatal — multicast often doesn't work in
// containers without host networking, and the server should keep
// running anyway.
func startMDNS(cfg *config.Config, pubB64 string, boundAddr net.Addr, logger *slog.Logger) *mdns.Publisher {
	if !cfg.MDNS.Enabled {
		return nil
	}
	port := cfg.MDNS.Port
	if port == 0 {
		if tc, ok := boundAddr.(*net.TCPAddr); ok && tc.Port != 0 {
			port = tc.Port
		} else {
			port = parsePort(cfg.Listen, 8080)
		}
	}
	info := []string{
		"version=" + protocol.Version,
		"pubkey=" + pubB64,
	}
	scheme := "http"
	if cfg.TLS.Cert != "" {
		scheme = "https"
	}
	if cfg.MDNS.PublicScheme != "" {
		scheme = cfg.MDNS.PublicScheme
	}
	info = append(info, "scheme="+scheme)
	mdnsHost := cfg.MDNS.PublicHost
	if cfg.MDNS.PublicPort != 0 {
		port = cfg.MDNS.PublicPort
	}
	p, err := mdns.Publish(cfg.MDNS.Service, port, mdnsHost, info)
	if err != nil {
		logger.Warn("mdns publish failed", "err", err)
		return nil
	}
	logger.Info("mdns advertised", "service", cfg.MDNS.Service, "host", mdnsHost, "port", port, "scheme", scheme)
	return p
}

// openStore opens the persistence layer selected in config. Memory is
// the zero-config default; sqlite is the persistent option.
func openStore(c config.StoreConfig, logger *slog.Logger) (store.Store, error) {
	switch c.Driver {
	case "", "memory":
		logger.Info("store: in-memory (data does not persist across restarts)")
		return store.NewMemory(), nil
	case "sqlite":
		dsn := c.DSN
		if dsn == "" {
			dsn = "ztp.db"
		}
		logger.Info("store: sqlite", "dsn", dsn)
		return sqlitestore.Open(dsn)
	default:
		return nil, fmt.Errorf("unknown store driver %q", c.Driver)
	}
}

// buildVerifiers turns a list of verifier names from YAML into a Chain.
func buildVerifiers(names []string, st store.Store) (trust.Chain, error) {
	if len(names) == 0 {
		// Sensible default: pre-registered devices auto-trusted, anyone with a
		// valid bootstrap token auto-trusted, repeat customers auto-trusted,
		// everyone else queued for manual approval.
		names = []string{"allowlist", "bootstrap_token", "known_keypair"}
	}
	chain := make(trust.Chain, 0, len(names))
	for _, n := range names {
		switch n {
		case "allowlist":
			chain = append(chain, &trust.Allowlist{Store: st})
		case "bootstrap_token":
			chain = append(chain, &trust.BootstrapToken{Store: st})
		case "known_keypair":
			chain = append(chain, &trust.KnownKeypair{Store: st})
		case "tpm_attestation":
			chain = append(chain, trust.TPMAttestation{})
		default:
			return nil, fmt.Errorf("unknown verifier %q", n)
		}
	}
	return chain, nil
}

// resolveAllIssuers walks every loaded profile and runs
// Cumulocity.ResolveIssuer on the ones that have a c8y payload.
// Keeps the c8y bootstrap-token issuer fully wired before any device
// tries to enroll.
func resolveAllIssuers(ctx context.Context, resolver *profiles.Resolver, logger *slog.Logger) error {
	all, err := resolver.List(ctx)
	if err != nil {
		return err
	}
	for i := range all {
		if all[i].Payload == nil || all[i].Payload.Cumulocity == nil {
			continue
		}
		if err := all[i].Payload.Cumulocity.ResolveIssuer(logger); err != nil {
			return fmt.Errorf("profile %q: %w", all[i].Name, err)
		}
	}
	return nil
}

func parsePort(addr string, fallback int) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return fallback
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		return fallback
	}
	return n
}

// buildSPAHandler chooses where the SPA assets come from: an
// operator-supplied directory wins (web.dir), then the in-binary
// embed. Returns nil to skip SPA registration entirely (web.disabled,
// or no source at all on a binary built before pnpm build was run).
func buildSPAHandler(cfg config.WebConfig, embedded fs.FS, logger *slog.Logger) (http.Handler, error) {
	if cfg.Disabled {
		logger.Info("web: SPA disabled in config; / will return 404")
		return nil, nil
	}
	if cfg.Dir != "" {
		f, err := web.DirFS(cfg.Dir)
		if err != nil {
			return nil, fmt.Errorf("web.dir: %w", err)
		}
		logger.Info("web: serving SPA from external directory", "dir", cfg.Dir)
		return web.NewSPAHandler(f), nil
	}
	if embedded != nil {
		logger.Info("web: serving SPA from embedded assets")
		return web.NewSPAHandler(embedded), nil
	}
	logger.Info("web: no SPA assets available; / will serve a placeholder page")
	return web.NewSPAHandler(nil), nil
}

// resolveTLSMode honours backwards compatibility: an empty mode with
// a Cert path set is treated as Mode=cert, matching the pre-Mode
// behaviour where setting tls.cert was the only way to enable TLS.
func resolveTLSMode(c config.TLSConfig) (tlsmode.Mode, error) {
	if strings.TrimSpace(c.Mode) == "" && c.Cert != "" {
		return tlsmode.Cert, nil
	}
	return tlsmode.Parse(c.Mode)
}

// buildEncryptionRecipients composes the recipient set the API
// exposes via /v1/admin/profiles/encryption-key. The server's own
// pubkey is always first so a "naive" ztpctl secrets seal — which
// uses the first recipient — still produces a server-readable file.
// Operator-managed recipients from age_recipients in the config
// follow.
func buildEncryptionRecipients(id *age.X25519Identity, configured []string) []string {
	out := make([]string, 0, 1+len(configured))
	out = append(out, id.Recipient().String())
	for _, s := range configured {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}
