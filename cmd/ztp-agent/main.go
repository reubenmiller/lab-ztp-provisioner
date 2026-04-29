// ztp-agent is the Zero-Touch Provisioning device agent.
//
// It loads (or creates) a long-lived Ed25519 identity key, enrolls with the
// configured ZTP server, applies the resulting provisioning bundle, and
// exits. Module appliers come from two sources: drop-in POSIX scripts in
// /etc/ztp/appliers.d/<type>.sh (preferred — operator-overridable) and a
// minimal set of built-in handlers compiled into the binary.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/appliers"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/clock"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/identity"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/agent/logging"
	"github.com/thin-edge/tedge-zerotouch-provisioning/internal/mdns"
)

// Version is overridden at build time via -ldflags '-X main.Version=...'.
var Version = "dev"

// bleRunner is set by cmd/ztp-agent/ble.go (only compiled with -tags ble).
// When non-nil, main routes to the BLE peripheral path instead of HTTP.
var bleRunner func(ctx context.Context, cfg agent.Config, logger *slog.Logger) error

// bleCapable is true only in ble.go (linux/windows + ble build tag), where
// the real GATT peripheral is available. ble_unsupported.go leaves it false.
var bleCapable bool

// defaultConfigPath is the well-known location for the agent TOML config file.
const defaultConfigPath = "/etc/ztp/agent.toml"

// newRootCmd builds the root cobra command, registers all flags, and binds
// them to viper so CLI > env var > config file > compiled default precedence
// is handled automatically.
//
// Viper keys use underscore separators to match the TOML config file format.
// Env vars are derived as ZTP_<UPPERCASE_KEY> (e.g. ZTP_SERVER_LIST).
// The --config flag is intentionally not bound to viper (its value cannot
// come from the config file itself).
func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ztp-agent",
		Short: "Zero-Touch Provisioning device agent",
		Long: `Enrolls this device with a ZTP server, applies the returned provisioning
bundle (WiFi, SSH keys, Cumulocity credentials, arbitrary files, hooks),
and exits. On success the device is fully provisioned; on failure it exits
non-zero and can be retried by the calling service (e.g. systemd).

The agent generates (or reuses) a long-lived Ed25519 identity key and signs
every enroll request. The server's signing public key is used to verify the
returned bundle before any applier runs.`,
		Example: `  # Minimal: server URL only — pubkey fetched automatically from /v1/server-info
  ztp-agent --server https://ztp.example.com

  # Recommended for production: pin the server's CA cert
  ztp-agent --server https://ztp.example.com --ca /etc/ztp/ca.pem

  # Provide the pubkey explicitly (baked into the image)
  ztp-agent --server https://ztp.example.com \
            --server-pubkey iF47gcxyz...==

  # Use a bootstrap token for first-contact allowlisting
  ztp-agent --server https://ztp.example.com --token-file /etc/ztp/bootstrap.token

  # LAN / zero-config: discover the server via mDNS (no URL needed)
  ztp-agent --mdns

  # Try HTTP first, automatically fall back to BLE if the server is unreachable
  ztp-agent --server-list https://ztp.local:8443,https://172.17.0.1:8443 --transport http,ble

  # BLE-only provisioning on a device without network access
  ztp-agent --transport ble

  # Force end-to-end bundle encryption (useful over untrusted transports)
  ztp-agent --server https://ztp.example.com --encrypt

  # Debug: verbose logging
  ztp-agent --server https://ztp.example.com --verbose`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE:          runAgent,
	}

	f := cmd.Flags()
	f.String("config", defaultConfigPath, "`path` to a TOML config file.\n\tAll flags can be set in the file; CLI flags and env vars take precedence.\n\tDefault: "+defaultConfigPath)
	f.String("server", "", "ZTP server `URL` (e.g. https://ztp.example.com).\n\tIf omitted, mDNS discovery is attempted when --mdns is set.\n\tThe server signing pubkey is fetched automatically from /v1/server-info\n\twhen --server-pubkey is not provided.")
	f.String("server-list", "", "Comma-separated list of fallback server `URL`s to try when --server is\n\tnot reachable and mDNS discovery fails. The first reachable URL wins.\n\tAlso configurable via ZTP_SERVER_LIST env var.\n\tExample: --server-list https://localhost:8443,https://192.168.1.10:8443")
	f.String("server-pubkey", "", "Base64-encoded Ed25519 `public key` used to verify the provisioning bundle.\n\tIf omitted, fetched automatically from the server's /v1/server-info endpoint.\n\tAlso populated from the mDNS TXT record `pubkey=` when using --mdns.")
	f.String("server-pubkey-file", "/etc/ztp/server.pub", "`path` to a file containing the base64-encoded Ed25519 server public key.\n\tUsed when --server-pubkey is not set. The file is silently ignored when absent.\n\tAlso configurable via ZTP_SERVER_PUBKEY_FILE env var.")
	f.String("ca", "", "`path` to a PEM-encoded CA certificate that signed the server's TLS cert.\n\tWhen set, TLS verification is anchored to this CA instead of system roots.\n\tOmitting this flag means the pubkey is fetched via TOFU on first contact.")
	f.String("identity", "/var/lib/ztp/identity.key", "`path` to the device's long-lived Ed25519 identity key.\n\tCreated automatically on first run.")
	f.String("sentinel", "/var/lib/ztp/provisioned", "`path` to the sentinel file written on successful enrollment.\n\tWhen this file exists the agent exits 0 immediately — device is already provisioned.\n\tSet to empty string to disable both the check and the creation.")
	f.Bool("force", false, "Ignore the sentinel file and re-run enrollment even if the device is already provisioned.\n\tUseful for local testing or forced re-provisioning without deleting the sentinel manually.")
	f.String("device-id", "", "Override the device `ID` sent in the enroll request.\n\tResolved from: /etc/device-id, /var/lib/ztp/device-id, then `tedge-identity` command.\n\tReturns an error if none of the sources yield a value.")
	f.String("token", "", "Bootstrap `token` for first-contact allowlisting (optional).\n\tSingle- or limited-use; stored only as a hash on the server.")
	f.String("token-file", "", "`path` to a file containing the bootstrap token (alternative to --token).")
	f.String("profile", "", "Advisory provisioning `profile` name to request from the server.\n\tThe server treats this as a hint only — any operator-side binding\n\t(allowlist/token assignment, sticky persisted name, device override,\n\tor a fact-based selector) wins over it. Useful when the device\n\timage already knows what role it has (e.g. \"lab\", \"production\").\n\tAlso configurable via ZTP_PROFILE env var.")
	f.String("appliers", "/etc/ztp/appliers.d", "`directory` of drop-in POSIX applier scripts (one per module type).\n\tA script at <dir>/wifi.v2.sh overrides the built-in wifi handler.\n\tScripts receive the module's INI payload on stdin.")
	f.String("applier-log", "", "`path` for an append-only applier run log.\n\tEach applier invocation appends its combined stdout/stderr with a header\n\tso the full history survives across agent restarts.\n\tAlso configurable via ZTP_APPLIER_LOG env var.")
	f.String("log-file", "", "`path` for an append-only file that mirrors all agent log output.\n\tThe agent normally logs to stderr (captured by journald). When journald\n\tis volatile (tmpfs-backed) this flag persists logs across reboots so\n\tprovisioning history is recoverable. Independent of --applier-log,\n\twhich captures raw applier stdout/stderr.\n\tAlso configurable via ZTP_LOG_FILE env var.")
	f.Int64("log-file-max-bytes", 1024*1024, "Maximum `bytes` per log file before --log-file rotates.\n\tThe current file is renamed to <path>.1 (cascading older backups one\n\tslot down) and a fresh file is opened. 0 disables rotation entirely.\n\tDefault: 1 MiB. Also configurable via ZTP_LOG_FILE_MAX_BYTES env var.")
	f.Int("log-file-max-backups", 3, "Maximum `count` of rotated log files to keep on disk\n\t(<path>.1 through <path>.<N>). Older backups are deleted on rotation.\n\t0 means \"do not keep any rotated copies\" — the current file is\n\ttruncated in place once full, bounding disk use to log-file-max-bytes\n\tflat. Default: 3. Also configurable via ZTP_LOG_FILE_MAX_BACKUPS env var.")
	f.String("applier-debug", "", "Applier debug verbosity.\n\t  1 / verbose — log stdout/stderr of every applier, not only failures.\n\t  trace       — pass -x to the shell interpreter (prints every command).\n\tAlso configurable via ZTP_APPLIER_DEBUG env var.")
	f.Bool("mdns", true, "Discover the ZTP server on the local network via mDNS/DNS-SD.\n\tThe server advertises itself as _ztp._tcp; its pubkey is included in\n\tthe TXT record so no --server-pubkey flag is needed on LAN deployments.\n\tEnabled by default for zero-config LAN deployments.")
	f.String("mdns-service", "_ztp._tcp", "mDNS `service type` to query for server discovery.\n\tChange only when the server is configured with a custom service name.")
	f.String("transport", "auto", "Ordered comma-separated list of enrollment `transport`s to attempt.\n\tEach transport is tried in order; the first successful enrollment wins.\n\tValid tokens: http, ble, auto\n\t  auto     — expands to 'http,ble' on BLE-capable builds, 'http' otherwise.\n\t  http     — HTTPS enrollment directly to --server / --server-list candidates.\n\t  ble      — BLE peripheral mode (Linux only, requires -tags ble build).\n\tExamples: auto, http, ble, http,ble, ble,http")
	f.Duration("scan-interval", 30*time.Second, "Interval between background HTTP/mDNS rescans after the initial probe.\n\tWhen >0 and the first HTTP attempt fails, the agent keeps re-running\n\tmDNS discovery and TCP-probing static --server-list URLs at this cadence,\n\tracing the resulting attempts against any BLE peripheral session. As\n\tsoon as a server becomes reachable (e.g. when a network cable is\n\tplugged in mid-boot), HTTP enrollment proceeds and BLE is cancelled.\n\tSet to 0 to disable rescanning (legacy one-shot behaviour).\n\tAlso configurable via ZTP_SCAN_INTERVAL env var (e.g. \"45s\", \"2m\").")
	f.Bool("encrypt", false, "Request a fully end-to-end encrypted bundle (X25519+ChaCha20-Poly1305).\n\tSensitive per-module payloads (e.g. Cumulocity tokens) are always sealed\n\tregardless of this flag. Use --encrypt when the transport is untrusted\n\t(e.g. BLE relay).")
	f.Bool("insecure", false, "Skip TLS certificate verification entirely.\n\tFor development/testing only — never use in production.")
	f.BoolP("verbose", "v", false, "Enable verbose (debug) logging.")
	f.String("debug", "", "Dump the provisioning bundle to stderr before applying.\n\t  (no value) / 1 / true / yes / on — dump, then run appliers\n\t  only / dump / inspect — dump, then exit 0 without applying\n\tAlso configurable via ZTP_DEBUG env var; the flag takes precedence.")
	f.String("ble-name-prefix", "ztp-", "Prefix prepended to the device id in the BLE advertising name.\n\tDefault \"ztp-\" gives names like \"ztp-<device-id>\" in BLE scanners.\n\tSet to an empty string to advertise the bare device id.\n\tAlso configurable via ZTP_BLE_NAME_PREFIX env var.")
	f.String("system-clock", "auto", "Policy for adjusting the device's system real-time clock from the\n\tverified bundle's issued_at timestamp before appliers run.\n\t  auto    — advance the clock when it is more than 60s behind (default).\n\t  off     — never touch the system clock (use when chronyd / NTP manages it).\n\t  always  — adjust unconditionally, forwards or backwards.\n\tFixes downstream TLS NotBefore failures (e.g. tedge cert download c8y)\n\ton devices that boot before any time-sync mechanism is available.\n\tRequires CAP_SYS_TIME (root); a missing capability is logged as a warning\n\tand provisioning continues. Also configurable via ZTP_SYSTEM_CLOCK env var.")

	// Bind flags to viper keys. Underscore keys match the TOML config file
	// and map to env vars as ZTP_<UPPERCASE_KEY> via AutomaticEnv.
	v := viper.GetViper()
	_ = v.BindPFlag("server", f.Lookup("server"))
	_ = v.BindPFlag("server_list", f.Lookup("server-list"))
	_ = v.BindPFlag("server_pubkey", f.Lookup("server-pubkey"))
	_ = v.BindPFlag("server_pubkey_file", f.Lookup("server-pubkey-file"))
	_ = v.BindPFlag("ca", f.Lookup("ca"))
	_ = v.BindPFlag("sentinel", f.Lookup("sentinel"))
	_ = v.BindPFlag("force", f.Lookup("force"))
	_ = v.BindPFlag("identity", f.Lookup("identity"))
	_ = v.BindPFlag("device_id", f.Lookup("device-id"))
	_ = v.BindPFlag("token", f.Lookup("token"))
	_ = v.BindPFlag("token_file", f.Lookup("token-file"))
	_ = v.BindPFlag("profile", f.Lookup("profile"))
	_ = v.BindPFlag("appliers", f.Lookup("appliers"))
	_ = v.BindPFlag("applier_log", f.Lookup("applier-log"))
	_ = v.BindPFlag("log_file", f.Lookup("log-file"))
	_ = v.BindPFlag("log_file_max_bytes", f.Lookup("log-file-max-bytes"))
	_ = v.BindPFlag("log_file_max_backups", f.Lookup("log-file-max-backups"))
	_ = v.BindPFlag("applier_debug", f.Lookup("applier-debug"))
	_ = v.BindPFlag("mdns", f.Lookup("mdns"))
	_ = v.BindPFlag("mdns_service", f.Lookup("mdns-service"))
	_ = v.BindPFlag("transport", f.Lookup("transport"))
	_ = v.BindPFlag("scan_interval", f.Lookup("scan-interval"))
	_ = v.BindPFlag("encrypt", f.Lookup("encrypt"))
	_ = v.BindPFlag("insecure", f.Lookup("insecure"))
	_ = v.BindPFlag("verbose", f.Lookup("verbose"))
	_ = v.BindPFlag("debug", f.Lookup("debug"))
	_ = v.BindPFlag("ble_name_prefix", f.Lookup("ble-name-prefix"))
	_ = v.BindPFlag("system_clock", f.Lookup("system-clock"))

	v.SetEnvPrefix("ZTP")
	v.AutomaticEnv()

	return cmd
}

func runAgent(cmd *cobra.Command, args []string) error {
	v := viper.GetViper()

	// Load config file. Missing file or parse errors are silently ignored so
	// the agent works without any config file present.
	cfgPath, _ := cmd.Flags().GetString("config")
	v.SetConfigFile(cfgPath)
	v.SetConfigType("toml")
	_ = v.ReadInConfig()

	logLevel := slog.LevelDebug
	logHandler, logCloser, err := buildLogHandler(
		v.GetString("log_file"),
		v.GetInt64("log_file_max_bytes"),
		v.GetInt("log_file_max_backups"),
		logLevel,
	)
	if err != nil {
		return fmt.Errorf("log file: %w", err)
	}
	if logCloser != nil {
		defer logCloser()
	}
	logger := slog.New(logHandler)

	serverURL := v.GetString("server")
	serverListStr := v.GetString("server_list")
	serverPubKeyStr := v.GetString("server_pubkey")
	serverPubKeyFile := v.GetString("server_pubkey_file")
	caFile := v.GetString("ca")
	identityPath := v.GetString("identity")
	deviceID := v.GetString("device_id")
	tokenVal := v.GetString("token")
	tokenFile := v.GetString("token_file")
	profileVal := v.GetString("profile")
	scriptsDir := v.GetString("appliers")
	applierLogVal := v.GetString("applier_log")
	applierDebugVal := v.GetString("applier_debug")
	useMDNS := v.GetBool("mdns")
	mdnsService := v.GetString("mdns_service")
	sentinelPath := v.GetString("sentinel")
	force := v.GetBool("force")
	transportStr := v.GetString("transport")
	scanInterval := v.GetDuration("scan_interval")
	encrypt := v.GetBool("encrypt")
	insecure := v.GetBool("insecure")
	debugVal := v.GetString("debug")
	bleNamePrefix := v.GetString("ble_name_prefix")
	systemClockStr := v.GetString("system_clock")

	systemClockPolicy, err := clock.ParsePolicy(systemClockStr)
	if err != nil {
		return fmt.Errorf("invalid --system-clock: %w", err)
	}

	// Guard: exit 0 immediately if this device is already provisioned.
	if !force && sentinelPath != "" {
		if _, err := os.Stat(sentinelPath); err == nil {
			logger.Info("device already provisioned — skipping enrollment", "sentinel", sentinelPath)
			return nil
		}
	}

	var serverFallbacks []string
	for _, u := range splitCSV(serverListStr) {
		if u != "" {
			serverFallbacks = append(serverFallbacks, u)
		}
	}

	transports, err := parseTransportList(transportStr)
	if err != nil {
		return fmt.Errorf("invalid --transport: %w", err)
	}

	// Resolve pubkey from file when not set directly.
	if serverPubKeyStr == "" && serverPubKeyFile != "" {
		if b, err := os.ReadFile(serverPubKeyFile); err == nil {
			serverPubKeyStr = strings.TrimSpace(string(b))
		}
	}

	// Collect live HTTP candidates: TCP-probe pre-filter + optional mDNS discovery.
	// serverPubKeyStr may be updated if mDNS TXT advertises a pubkey= record.
	candidates := buildHTTPCandidates(serverURL, serverFallbacks, useMDNS, mdnsService, &serverPubKeyStr, logger)

	// Decode the explicitly-supplied server pubkey. This is used directly for
	// BLE transport (TOFU if empty). HTTP candidates resolve their own pubkey
	// per-candidate inside runHTTPCandidates.
	var pubBytes ed25519.PublicKey
	if serverPubKeyStr != "" {
		decoded, err := base64.StdEncoding.DecodeString(serverPubKeyStr)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return errors.New("--server-pubkey must be a base64-encoded Ed25519 public key")
		}
		pubBytes = decoded
	}

	idp, err := identity.LoadOrCreateFile(identityPath)
	if err != nil {
		return fmt.Errorf("identity: %w", err)
	}

	token := tokenVal
	if token == "" && tokenFile != "" {
		b, err := os.ReadFile(tokenFile)
		if err != nil {
			return fmt.Errorf("read token file: %w", err)
		}
		token = string(b)
	}

	disp := appliers.New(nil) // built-in handlers can be added here
	disp.ScriptsDir = scriptsDir
	disp.Logger = logger
	disp.LogFile = applierLogVal
	switch applierDebugVal {
	case "trace":
		disp.ShellTrace = true
		disp.Verbose = true
	case "1", "verbose", "true", "yes", "on":
		disp.Verbose = true
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Base config. ServerURL, DialAddr and ServerPubKey are filled per-candidate
	// inside runHTTPCandidates. For BLE, pubBytes is used directly (empty = TOFU).
	baseCfg := agent.Config{
		DeviceID:          deviceID,
		BootstrapToken:    token,
		Profile:           profileVal,
		ServerPubKey:      pubBytes,
		CACertFile:        caFile,
		Insecure:          insecure,
		Identity:          idp,
		Dispatcher:        disp,
		Logger:            logger,
		AgentVersion:      Version,
		Encrypt:           encrypt,
		Debug:             debugVal,
		BLENamePrefix:     bleNamePrefix,
		SystemClockPolicy: systemClockPolicy,
	}

	scanCfg := scanConfig{
		serverURL:    serverURL,
		fallbacks:    serverFallbacks,
		useMDNS:      useMDNS,
		mdnsService:  mdnsService,
		serverPubKey: serverPubKeyStr,
	}
	if err := runMultiTransport(ctx, transports, candidates, baseCfg, scanCfg, scanInterval, caFile, insecure, logger); err != nil {
		return fmt.Errorf("provisioning failed: %w", err)
	}

	// Mark the device as provisioned so subsequent boots skip enrollment.
	if sentinelPath != "" {
		if err := os.MkdirAll(filepath.Dir(sentinelPath), 0o700); err != nil {
			logger.Warn("could not create sentinel directory", "path", sentinelPath, "err", err)
		} else if err := os.WriteFile(sentinelPath, nil, 0o600); err != nil {
			logger.Warn("could not write sentinel file", "path", sentinelPath, "err", err)
		} else {
			logger.Info("enrollment complete", "sentinel", sentinelPath)
		}
	}
	return nil
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// buildLogHandler returns a slog.Handler writing to stderr and, if
// logFilePath is non-empty, also appending to a size-rotated file at that
// path. The returned closer (when non-nil) should be invoked on agent
// shutdown to release the file handle.
//
// maxBytes <= 0 disables rotation (file grows unbounded). maxBackups <= 0
// truncates the file in place once full instead of keeping rotated copies.
//
// Failure to create the parent directory or open the file is fatal: an
// operator who explicitly requested a log file would rather see the agent
// fail loudly than silently lose logs.
func buildLogHandler(logFilePath string, maxBytes int64, maxBackups int, level slog.Level) (slog.Handler, func(), error) {
	stderrHandler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	if logFilePath == "" {
		return stderrHandler, nil, nil
	}
	rf, err := logging.OpenRotating(logFilePath, maxBytes, maxBackups)
	if err != nil {
		return nil, nil, err
	}
	fileHandler := slog.NewTextHandler(rf, &slog.HandlerOptions{Level: level})
	return logging.NewMulti(stderrHandler, fileHandler), func() { _ = rf.Close() }, nil
}

// httpCandidate is a server endpoint that passed the TCP pre-probe.
type httpCandidate struct {
	url        string
	dialAddr   string // non-empty when resolved via mDNS multicast (ip:port)
	pubkeyHint string // non-empty when advertised in mDNS TXT record
}

// parseTransportList splits and validates the --transport flag value into an
// ordered list of transport tokens. "auto" expands to ["http","ble"] on
// BLE-capable builds and ["http"] on others. Duplicate tokens are silently
// deduplicated, preserving first-occurrence order.
func parseTransportList(s string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, tok := range splitCSV(s) {
		var expanded []string
		switch tok {
		case "http", "ble":
			expanded = []string{tok}
		case "auto":
			expanded = []string{"http"}
			if bleCapable {
				expanded = append(expanded, "ble")
			}
		default:
			return nil, fmt.Errorf("unknown transport %q; valid values: http, ble, auto (or comma-separated list e.g. http,ble)", tok)
		}
		for _, t := range expanded {
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	if len(out) == 0 {
		return nil, errors.New("--transport must not be empty")
	}
	return out, nil
}

// buildHTTPCandidates probes configured server URLs (from --server and
// --server-list) plus any mDNS-discovered server using lightweight TCP probes.
// It returns only the endpoints that are currently reachable, in priority
// order: mDNS-discovered first, then configured URLs. The serverPubKey pointer
// may be updated if the mDNS TXT record advertises a pubkey= entry.
func buildHTTPCandidates(
	serverURL string,
	fallbacks []string,
	useMDNS bool,
	mdnsService string,
	serverPubKey *string,
	logger *slog.Logger,
) []httpCandidate {
	// Unified URL list: --server is syntactic sugar for the head of the list.
	var allURLs []string
	if serverURL != "" {
		allURLs = append(allURLs, serverURL)
	}
	allURLs = append(allURLs, fallbacks...)

	var candidates []httpCandidate

	// mDNS discovery: prepend if live, capture pubkey hint from TXT.
	if useMDNS {
		mctx, mcancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer mcancel()
		if entry, err := mdns.Discover(mctx, mdnsService, 4*time.Second); err == nil {
			discoveredURL := entry.URL()
			discoveredDial := entry.DialAddr()
			if ok, _ := probeWithMDNS(discoveredURL, logger); ok {
				hint := ""
				if *serverPubKey == "" {
					for _, t := range entry.Info {
						if len(t) > 7 && t[:7] == "pubkey=" {
							hint = t[7:]
							*serverPubKey = hint // propagate so callers see it
						}
					}
				}
				candidates = append(candidates, httpCandidate{
					url:        discoveredURL,
					dialAddr:   discoveredDial,
					pubkeyHint: hint,
				})
				logger.Info("candidates: mDNS discovered server reachable", "url", discoveredURL)
			} else {
				logger.Info("candidates: mDNS discovered server not reachable", "url", discoveredURL)
			}
		} else {
			logger.Info("candidates: mDNS discovery failed", "err", err)
		}
	}

	// Probe each configured URL (skip any already added via mDNS).
	for _, u := range allURLs {
		already := false
		for _, c := range candidates {
			if c.url == u {
				already = true
				break
			}
		}
		if already {
			continue
		}
		if ok, dial := probeWithMDNS(u, logger); ok {
			candidates = append(candidates, httpCandidate{url: u, dialAddr: dial})
			logger.Info("candidates: server reachable", "url", u)
		} else {
			logger.Debug("candidates: server not reachable over TCP", "url", u)
		}
	}

	if len(allURLs) > 0 && len(candidates) == 0 {
		logger.Info("candidates: no configured server reachable over TCP", "tried", len(allURLs))
	}
	return candidates
}

// resolveServerPubKey returns the decoded Ed25519 public key for candidate.
// Priority: explicit global key > candidate's mDNS hint > fetch from /v1/server-info.
func resolveServerPubKey(
	ctx context.Context,
	cand httpCandidate,
	globalPubKeyStr string,
	caFile string,
	insecure bool,
	logger *slog.Logger,
) (ed25519.PublicKey, error) {
	keyStr := globalPubKeyStr
	if keyStr == "" {
		keyStr = cand.pubkeyHint
	}
	if keyStr == "" {
		if caFile == "" {
			logger.Warn("fetching server pubkey without a CA cert — TOFU trust (use --ca to pin the certificate)", "url", cand.url)
		}
		var err error
		keyStr, err = fetchServerPubKey(ctx, cand.url, cand.dialAddr, caFile, insecure)
		if err != nil {
			return nil, fmt.Errorf("fetch server pubkey from %s: %w", cand.url, err)
		}
		logger.Info("fetched server pubkey from /v1/server-info", "url", cand.url)
	}
	decoded, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid server pubkey for %s: must be base64-encoded Ed25519 public key", cand.url)
	}
	return ed25519.PublicKey(decoded), nil
}

// runHTTPCandidates tries each live HTTP candidate in order. For each, it
// resolves the server pubkey then calls agent.Run with MaxNetworkFailures=3.
// On ErrServerUnreachable it advances to the next candidate; on
// ErrEnrollRejected or any other terminal error it returns immediately.
// Returns agent.ErrServerUnreachable if all candidates are exhausted.
func runHTTPCandidates(
	ctx context.Context,
	candidates []httpCandidate,
	baseCfg agent.Config,
	globalPubKeyStr string,
	caFile string,
	insecure bool,
	logger *slog.Logger,
) error {
	if len(candidates) == 0 {
		return fmt.Errorf("no reachable HTTP server candidates: %w", agent.ErrServerUnreachable)
	}
	for _, cand := range candidates {
		pub, err := resolveServerPubKey(ctx, cand, globalPubKeyStr, caFile, insecure, logger)
		if err != nil {
			logger.Warn("skipping HTTP candidate: could not resolve server pubkey", "url", cand.url, "err", err)
			continue
		}
		cfg := baseCfg
		cfg.ServerURL = cand.url
		cfg.DialAddr = cand.dialAddr
		cfg.ServerPubKey = pub
		cfg.MaxNetworkFailures = 3

		logger.Info("trying HTTP candidate", "url", cand.url)
		err = agent.Run(ctx, cfg)
		if err == nil {
			return nil
		}
		if errors.Is(err, agent.ErrServerUnreachable) {
			logger.Info("HTTP candidate unreachable after retries, trying next", "url", cand.url)
			continue
		}
		// Rejection, applier failures, and other terminal errors must not
		// cause a fallback to another transport.
		return err
	}
	return fmt.Errorf("all HTTP candidates exhausted: %w", agent.ErrServerUnreachable)
}

// scanConfig captures the inputs needed to rebuild the HTTP candidate list on
// every scanner tick. Mirrors the parameters of buildHTTPCandidates.
type scanConfig struct {
	serverURL    string
	fallbacks    []string
	useMDNS      bool
	mdnsService  string
	serverPubKey string
}

// scanAndEnroll periodically rebuilds the HTTP candidate list (re-running mDNS
// discovery and TCP-probing static URLs) and attempts enrollment as soon as
// any candidate becomes reachable. It returns:
//   - nil on a successful enrollment;
//   - a terminal error (rejection, applier failure, …) — surfaced immediately;
//   - context.Canceled / context.DeadlineExceeded if ctx is cancelled.
//
// ErrServerUnreachable from a single attempt is *not* terminal — the loop
// keeps scanning until ctx is cancelled or something else succeeds.
func scanAndEnroll(
	ctx context.Context,
	interval time.Duration,
	scanCfg scanConfig,
	baseCfg agent.Config,
	caFile string,
	insecure bool,
	logger *slog.Logger,
) error {
	logger.Info("scan-and-enroll: starting periodic HTTP rescan", "interval", interval)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
		// Per-tick local copy: buildHTTPCandidates may set the pubkey hint
		// from a freshly-discovered mDNS TXT record, but we don't want one
		// tick's hint to leak into the next.
		keyStr := scanCfg.serverPubKey
		candidates := buildHTTPCandidates(scanCfg.serverURL, scanCfg.fallbacks, scanCfg.useMDNS, scanCfg.mdnsService, &keyStr, logger)
		if len(candidates) == 0 {
			logger.Debug("scan-and-enroll: no reachable HTTP server this tick")
			continue
		}
		logger.Info("scan-and-enroll: HTTP server reachable, attempting enrollment", "candidates", len(candidates))
		err := runHTTPCandidates(ctx, candidates, baseCfg, keyStr, caFile, insecure, logger)
		if err == nil {
			return nil
		}
		if errors.Is(err, agent.ErrServerUnreachable) {
			logger.Info("scan-and-enroll: enrollment attempt failed, will retry", "err", err)
			continue
		}
		// Terminal error (rejection, applier failure, etc.) — propagate.
		return err
	}
}

// runMultiTransport orchestrates enrollment across the configured transports.
//
// Phase 1 (fast path): if HTTP is in the transport list, try the candidates
// already probed at startup. Success → return; non-network error → return.
//
// Phase 2 (concurrent fallback): if Phase 1 exhausted HTTP candidates without
// success, run BLE (if requested + capable) and a periodic HTTP rescanner
// (if scan_interval > 0) concurrently under a shared cancellation context.
// The first to succeed wins; the loser is cancelled. If a worker returns a
// terminal error, the other is cancelled and the error is propagated.
//
// When scan_interval == 0 the rescanner is disabled, restoring the legacy
// one-shot HTTP-then-BLE behaviour.
func runMultiTransport(
	ctx context.Context,
	transports []string,
	candidates []httpCandidate,
	baseCfg agent.Config,
	scanCfg scanConfig,
	scanInterval time.Duration,
	caFile string,
	insecure bool,
	logger *slog.Logger,
) error {
	var httpReq, bleReq bool
	for _, t := range transports {
		switch t {
		case "http":
			httpReq = true
		case "ble":
			bleReq = true
		}
	}

	// Phase 1: initial HTTP attempt with pre-probed candidates.
	if httpReq {
		err := runHTTPCandidates(ctx, candidates, baseCfg, scanCfg.serverPubKey, caFile, insecure, logger)
		if err == nil {
			return nil
		}
		if !errors.Is(err, agent.ErrServerUnreachable) {
			return err // terminal
		}
		logger.Info("HTTP exhausted on initial probe; entering concurrent scan/BLE phase")
	}

	// Phase 2: race the BLE peripheral against a periodic HTTP rescanner.
	runScanner := httpReq && scanInterval > 0
	runBLE := bleReq && bleCapable && bleRunner != nil
	if bleReq && (!bleCapable || bleRunner == nil) {
		logger.Warn("BLE transport requested but not available on this platform; rebuild for Linux with -tags ble")
	}

	if !runScanner && !runBLE {
		return fmt.Errorf("all transports exhausted: %w", agent.ErrServerUnreachable)
	}

	raceCtx, raceCancel := context.WithCancel(ctx)
	defer raceCancel()

	type workerResult struct {
		source string
		err    error
	}
	resCh := make(chan workerResult, 2)
	workers := 0

	if runScanner {
		workers++
		go func() {
			err := scanAndEnroll(raceCtx, scanInterval, scanCfg, baseCfg, caFile, insecure, logger)
			resCh <- workerResult{"http-scan", err}
		}()
	}
	if runBLE {
		workers++
		go func() {
			logger.Info("trying BLE transport (concurrent with HTTP rescanner)")
			err := bleRunner(raceCtx, baseCfg, logger)
			resCh <- workerResult{"ble", err}
		}()
	}

	var success bool
	var terminalErr, lastUnreachableErr error
	for i := 0; i < workers; i++ {
		r := <-resCh
		switch {
		case r.err == nil:
			logger.Info("transport succeeded; cancelling other workers", "source", r.source)
			success = true
			raceCancel()
		case errors.Is(r.err, context.Canceled), errors.Is(r.err, context.DeadlineExceeded):
			// The losing worker was cancelled by us — expected, ignore.
		case !errors.Is(r.err, agent.ErrServerUnreachable):
			// Terminal error from this worker. Cancel the other and remember
			// the first such error to surface.
			if terminalErr == nil {
				terminalErr = r.err
				logger.Info("transport returned terminal error; cancelling other workers", "source", r.source, "err", r.err)
				raceCancel()
			}
		default:
			lastUnreachableErr = r.err
			logger.Info("transport unreachable", "source", r.source, "err", r.err)
		}
	}

	switch {
	case success:
		return nil
	case terminalErr != nil:
		return terminalErr
	case lastUnreachableErr != nil:
		return lastUnreachableErr
	default:
		return fmt.Errorf("all transports exhausted: %w", agent.ErrServerUnreachable)
	}
}

// splitCSV splits a comma-separated string into trimmed, non-empty tokens.
func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// probeServer returns true if the host TCP endpoint of rawURL accepts a
// connection within 3 seconds. A failed probe is not fatal — it just means
// auto mode moves on to the next candidate transport.
func probeServer(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		switch u.Scheme {
		case "https":
			port = "443"
		default:
			port = "80"
		}
	}
	// Use a 3 s timeout for the probe; .local hostnames that fail here
	// are retried via direct mDNS multicast resolution by the caller.
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// probeWithMDNS probes rawURL for TCP reachability. For .local hostnames that
// fail the initial probe (Go's pure resolver may not resolve them through
// systemd-resolved's stub), it falls back to a direct mDNS multicast A query.
// Returns (reachable, dialAddr) where dialAddr is "ip:port" when the server
// was reached via mDNS resolution (empty string when normal DNS worked fine).
func probeWithMDNS(rawURL string, logger *slog.Logger) (bool, string) {
	if probeServer(rawURL) {
		return true, ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || !strings.HasSuffix(strings.ToLower(u.Hostname()), ".local") {
		return false, ""
	}
	logger.Debug("probe: normal DNS failed for .local host, trying mDNS multicast", "host", u.Hostname())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	ip, err := mdns.ResolveHost(ctx, u.Hostname(), 3*time.Second)
	cancel()
	if err != nil {
		logger.Debug("probe: mDNS resolution failed", "host", u.Hostname(), "err", err)
		return false, ""
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	dial := net.JoinHostPort(ip.String(), port)
	conn, err := net.DialTimeout("tcp", dial, 5*time.Second)
	if err != nil {
		logger.Debug("probe: mDNS resolved but TCP connect failed", "host", u.Hostname(), "ip", ip, "err", err)
		return false, ""
	}
	conn.Close()
	return true, dial
}

// fetchServerPubKey retrieves the server's Ed25519 signing public key from
// the unauthenticated GET /v1/server-info endpoint. When caFile is set the
// TLS certificate is validated against that root; otherwise the system roots
// are used (TOFU — caller should warn the user). Returns the base64-encoded
// public key string ready for use as --server-pubkey.
func fetchServerPubKey(ctx context.Context, serverURL, dialAddr, caFile string, insecure bool) (string, error) {
	// In TOFU mode (no CA cert pinned), skip TLS verification — the caller has
	// already warned the user. Security relies on bundle signature verification.
	tofu := !insecure && caFile == ""
	tlsCfg := &tls.Config{InsecureSkipVerify: insecure || tofu} //nolint:gosec
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return "", fmt.Errorf("read CA cert: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return "", errors.New("CA cert: no PEM blocks found")
		}
		tlsCfg.RootCAs = pool
	}
	transport := &http.Transport{TLSClientConfig: tlsCfg}
	if dialAddr != "" {
		target := dialAddr
		baseDialer := &net.Dialer{Timeout: 10 * time.Second}
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return baseDialer.DialContext(ctx, network, target)
		}
	}
	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, serverURL+"/v1/server-info", nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("GET /v1/server-info: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("/v1/server-info returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read /v1/server-info response: %w", err)
	}
	var info struct {
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("decode /v1/server-info: %w", err)
	}
	if info.PublicKey == "" {
		return "", errors.New("/v1/server-info: empty public_key field")
	}
	return info.PublicKey, nil
}
