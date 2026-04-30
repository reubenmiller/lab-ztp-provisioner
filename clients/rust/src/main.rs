//! ztp-agent — Zero-Touch Provisioning device agent (Rust implementation).
//!
//! Wire-compatible with the Go agent at cmd/ztp-agent. All CLI flags, exit
//! codes, and wire-protocol behaviour match the Go implementation exactly.

use std::path::PathBuf;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{CommandFactory, FromArgMatches, Parser};
use clap::parser::ValueSource;

use ztp_agent::{appliers, ble, enroll, identity, transport};
use ztp_agent::Result;
#[cfg(feature = "mdns")]
use ztp_agent::mdns;

// ---- CLI --------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(
    name = "ztp-agent",
    about = "Zero-Touch Provisioning device agent (Rust)\n\n\
             Enrolls this device with a ZTP server, applies the returned \
             provisioning bundle, and exits."
)]
struct Cli {
    /// ZTP server URL (e.g. https://ztp.example.com).
    /// If omitted, mDNS discovery is attempted when --mdns is set.
    #[arg(long, default_value = "")]
    server: String,

    /// Comma-separated list of fallback server URLs to try when --server is
    /// not reachable and mDNS discovery fails. The first reachable URL wins.
    /// Can also be set via the ZTP_SERVER_LIST environment variable.
    /// Example: --server-list https://localhost:8443,https://192.168.1.10:8443
    #[arg(long, value_delimiter = ',')]
    server_list: Vec<String>,

    /// Path to the device's long-lived Ed25519 identity key.
    /// Created automatically on first run (permissions 0600).
    #[arg(long, default_value = "/var/lib/ztp/identity.key")]
    identity: PathBuf,

    /// Bootstrap token for first-contact allowlisting (optional).
    #[arg(long, default_value = "")]
    token: String,

    /// Path to a file containing the bootstrap token (alternative to --token).
    #[arg(long)]
    token_file: Option<PathBuf>,

    /// Advisory provisioning profile name to request from the server.
    /// The server treats this as a hint only — any operator-side binding
    /// (allowlist/token assignment, sticky persisted name, device override,
    /// or a fact-based selector) wins over it. Useful when the device image
    /// already knows what role it has (e.g. "lab", "production").
    /// Also settable via ZTP_PROFILE env var.
    #[arg(long, default_value = "")]
    profile: String,

    /// Override the device ID sent in the enroll request.
    /// Resolved from: /etc/device-id, /var/lib/ztp/device-id, then `tedge-identity` command.
    /// Returns an error if none of the sources yield a value.
    #[arg(long, default_value = "")]
    device_id: String,

    /// Base64-encoded Ed25519 public key used to verify the provisioning bundle.
    /// If omitted, fetched automatically from /v1/server-info.
    /// Also populated from the mDNS TXT record `pubkey=` when using --mdns.
    #[arg(long, default_value = "")]
    server_pubkey: String,

    /// Path to a file containing the base64-encoded Ed25519 server public key.
    /// Used when --server-pubkey is not set. Silently ignored when absent.
    #[arg(long, default_value = "/etc/ztp/server.pub")]
    server_pubkey_file: PathBuf,

    /// Path to a PEM-encoded CA certificate that signed the server's TLS cert.
    /// When set, TLS is anchored to this CA instead of TOFU.
    #[arg(long)]
    ca: Option<PathBuf>,

    /// Skip TLS certificate verification entirely. Dev/testing only.
    #[arg(long)]
    insecure: bool,

    /// Directory of drop-in POSIX applier scripts.
    #[arg(long, default_value = "/etc/ztp/appliers.d")]
    appliers: PathBuf,

    /// Discover the ZTP server on the local network via mDNS/DNS-SD.
    /// Enabled by default for zero-config LAN deployments.
    #[arg(long, default_value_t = true)]
    mdns: bool,

    /// mDNS service type to query for server discovery.
    #[arg(long, default_value = "_ztp._tcp")]
    mdns_service: String,

    /// Request fully end-to-end encrypted bundle (X25519+ChaCha20-Poly1305).
    #[arg(long)]
    encrypt: bool,

    /// Ordered comma-separated list of enrollment transports to attempt.
    /// Each transport is tried in order; the first successful enrollment wins.
    /// Tokens: http, ble, auto
    ///   auto  — expands to 'http,ble' on BLE-capable builds, 'http' otherwise.
    ///   http  — HTTPS enrollment directly to --server / --server-list candidates.
    ///   ble   — BLE peripheral mode (Linux only, requires --features ble build).
    /// Examples: auto, http, ble, http,ble, ble,http
    #[arg(long, default_value = "auto")]
    transport: String,

    /// Interval between background HTTP/mDNS rescans after the initial probe.
    /// When >0 and the first HTTP attempt fails, the agent keeps re-running
    /// mDNS discovery and TCP-probing static --server-list URLs at this cadence,
    /// racing the resulting attempts against any BLE peripheral session. As
    /// soon as a server becomes reachable (e.g. when a network cable is plugged
    /// in mid-boot), HTTP enrollment proceeds and BLE is cancelled. Set to "0s"
    /// to disable rescanning (legacy one-shot behaviour). Accepts values like
    /// "30s", "2m", "1h". Also settable via ZTP_SCAN_INTERVAL env var.
    #[arg(long, default_value = "30s")]
    scan_interval: String,

    /// Enable verbose (debug) logging.
    #[arg(short = 'v', long = "v")]
    verbose: bool,

    /// Dump the provisioning bundle before applying.
    ///   "" / 1 / true / yes / on — dump then apply.
    ///   only / dump / inspect    — dump then exit without applying.
    /// Also settable via ZTP_DEBUG env var; flag takes precedence.
    #[arg(long, default_value = "")]
    debug: String,

    /// Applier debug verbosity.
    ///   1 / verbose — log stdout/stderr of every applier, not only failures.
    ///   trace       — pass -x to the shell interpreter (prints every command).
    /// Also settable via ZTP_APPLIER_DEBUG env var.
    #[arg(long, default_value = "")]
    applier_debug: String,

    /// Append-only log file for all applier output.
    /// Each applier invocation appends combined stdout/stderr with a header.
    /// Also settable via ZTP_APPLIER_LOG env var.
    #[arg(long)]
    applier_log: Option<PathBuf>,

    /// Append-only file that mirrors all agent log output (the same lines
    /// the agent prints to stderr / journald). Useful on devices whose
    /// journald is volatile (tmpfs-backed) so provisioning history survives
    /// reboots. Independent of --applier-log, which captures raw applier
    /// stdout/stderr. Also settable via ZTP_LOG_FILE env var.
    #[arg(long)]
    log_file: Option<PathBuf>,

    /// Maximum bytes per log file before --log-file rotates. The current
    /// file is renamed to <path>.1 (cascading older backups one slot down)
    /// and a fresh file is opened. 0 disables rotation entirely.
    /// Default: 1 MiB. Also settable via ZTP_LOG_FILE_MAX_BYTES env var.
    #[arg(long, default_value_t = ztp_agent::logging::DEFAULT_MAX_BYTES)]
    log_file_max_bytes: u64,

    /// Maximum number of rotated log files to keep on disk (<path>.1
    /// through <path>.<N>). Older backups are deleted on rotation. 0 means
    /// "do not keep any rotated copies" — the current file is truncated in
    /// place once full, bounding disk use to log_file_max_bytes flat.
    /// Default: 3. Also settable via ZTP_LOG_FILE_MAX_BACKUPS env var.
    #[arg(long, default_value_t = ztp_agent::logging::DEFAULT_MAX_BACKUPS)]
    log_file_max_backups: u32,

    /// Path to the sentinel file written on successful enrollment.
    /// When this file exists the agent exits 0 immediately — device is already provisioned.
    /// Set to empty string to disable both the check and the creation.
    #[arg(long, default_value = "/var/lib/ztp/provisioned")]
    sentinel: String,

    /// Ignore the sentinel file and re-run enrollment even if the device is already provisioned.
    /// Useful for local testing or forced re-provisioning without deleting the sentinel manually.
    #[arg(long)]
    force: bool,

    /// Path to a TOML config file. All flags can be set in the file;
    /// CLI flags and env vars take precedence.
    #[arg(long, default_value = "/etc/ztp/agent.toml")]
    config: PathBuf,

    /// Prefix prepended to the device id in the BLE advertising name.
    /// Default "ztp-" gives names like "ztp-<device-id>" in BLE scanners.
    /// Set to an empty string to advertise the bare device id.
    #[arg(long, default_value = "ztp-")]
    ble_name_prefix: String,

    /// Policy for adjusting the device's system real-time clock from the
    /// verified bundle's issued_at timestamp before appliers run.
    ///   auto    — advance the clock when it is more than 60 s behind (default).
    ///   off     — never touch the system clock (use when chronyd / NTP manages it).
    ///   always  — adjust unconditionally, forwards or backwards.
    /// Fixes downstream TLS NotBefore failures (e.g. `tedge cert download c8y`)
    /// on devices that boot before any time-sync mechanism is available.
    /// Requires CAP_SYS_TIME (root); a missing capability is logged as a warning
    /// and provisioning continues. Also settable via ZTP_SYSTEM_CLOCK env var.
    #[arg(long, default_value = "auto")]
    system_clock: String,
}

// ---- Config file ------------------------------------------------------------

/// All fields are optional; unset fields fall through to env vars or compiled
/// defaults. Precedence: CLI flag > env var > config file > compiled default.
#[derive(serde::Deserialize, Default)]
struct FileConfig {
    server:             Option<String>,
    /// Comma-separated list of server URLs.
    server_list:        Option<String>,
    server_pubkey:      Option<String>,
    server_pubkey_file: Option<PathBuf>,
    ca:                 Option<PathBuf>,
    identity:           Option<PathBuf>,
    device_id:          Option<String>,
    token:              Option<String>,
    token_file:         Option<PathBuf>,
    profile:            Option<String>,
    appliers:           Option<PathBuf>,
    applier_log:        Option<PathBuf>,
    applier_debug:      Option<String>,
    mdns:               Option<bool>,
    mdns_service:       Option<String>,
    transport:          Option<String>,
    encrypt:            Option<bool>,
    insecure:           Option<bool>,
    verbose:            Option<bool>,
    debug:              Option<String>,
    sentinel:           Option<String>,
    force:              Option<bool>,
    ble_name_prefix:    Option<String>,
    system_clock:       Option<String>,
    log_file:           Option<PathBuf>,
    log_file_max_bytes:    Option<u64>,
    log_file_max_backups:  Option<u32>,
    scan_interval:      Option<String>,
}

fn load_file_config(path: &std::path::Path) -> FileConfig {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

fn main() {
    // Use raw ArgMatches so we can detect which flags were explicitly set on
    // the command line (vs being at their compiled default). This lets the
    // config file act as a lower-priority layer than env vars.
    let matches = Cli::command().get_matches();
    let mut cli = Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit());

    // ── Load TOML config file ─────────────────────────────────────────────
    let file_cfg = load_file_config(&cli.config);

    // ── Merge: config file fills in fields NOT explicitly set on the CLI ──
    // Helper: was this arg explicitly passed on the command line?
    let cli_set = |id: &str| matches.value_source(id) == Some(ValueSource::CommandLine);

    if !cli_set("server")             { if let Some(v) = file_cfg.server             { cli.server = v; } }
    if !cli_set("server_pubkey")      { if let Some(v) = file_cfg.server_pubkey      { cli.server_pubkey = v; } }
    if !cli_set("server_pubkey_file") { if file_cfg.server_pubkey_file.is_some()     { cli.server_pubkey_file = file_cfg.server_pubkey_file.unwrap(); } }
    if !cli_set("sentinel")           { if let Some(v) = file_cfg.sentinel           { cli.sentinel = v; } }
    if !cli_set("force")              { if let Some(v) = file_cfg.force              { cli.force = v; } }
    if !cli_set("device_id")     { if let Some(v) = file_cfg.device_id     { cli.device_id = v; } }
    if !cli_set("token")         { if let Some(v) = file_cfg.token         { cli.token = v; } }
    if !cli_set("profile")       { if let Some(v) = file_cfg.profile       { cli.profile = v; } }
    if !cli_set("transport")     { if let Some(v) = file_cfg.transport     { cli.transport = v; } }
    if !cli_set("scan_interval") { if let Some(v) = file_cfg.scan_interval { cli.scan_interval = v; } }
    if !cli_set("mdns_service")  { if let Some(v) = file_cfg.mdns_service  { cli.mdns_service = v; } }
    if !cli_set("applier_debug") { if let Some(v) = file_cfg.applier_debug { cli.applier_debug = v; } }
    if !cli_set("debug")         { if let Some(v) = file_cfg.debug         { cli.debug = v; } }
    if !cli_set("identity")      { if let Some(v) = file_cfg.identity      { cli.identity = v; } }
    if !cli_set("appliers")      { if let Some(v) = file_cfg.appliers      { cli.appliers = v; } }
    if !cli_set("ca")            { if file_cfg.ca.is_some()        { cli.ca = file_cfg.ca; } }
    if !cli_set("token_file")    { if file_cfg.token_file.is_some(){ cli.token_file = file_cfg.token_file; } }
    if !cli_set("applier_log")   { if file_cfg.applier_log.is_some(){ cli.applier_log = file_cfg.applier_log; } }
    if !cli_set("log_file")      { if file_cfg.log_file.is_some()   { cli.log_file = file_cfg.log_file; } }
    if !cli_set("log_file_max_bytes")   { if let Some(v) = file_cfg.log_file_max_bytes   { cli.log_file_max_bytes = v; } }
    if !cli_set("log_file_max_backups") { if let Some(v) = file_cfg.log_file_max_backups { cli.log_file_max_backups = v; } }
    if !cli_set("insecure")      { if let Some(v) = file_cfg.insecure { cli.insecure = v; } }
    if !cli_set("mdns")          { if let Some(v) = file_cfg.mdns    { cli.mdns = v; } }
    if !cli_set("encrypt")       { if let Some(v) = file_cfg.encrypt { cli.encrypt = v; } }
    if !cli_set("v")             { if let Some(v) = file_cfg.verbose { cli.verbose = v; } }
    if !cli_set("ble_name_prefix") { if let Some(v) = file_cfg.ble_name_prefix { cli.ble_name_prefix = v; } }
    if !cli_set("system_clock")    { if let Some(v) = file_cfg.system_clock    { cli.system_clock = v; } }
    // server_list: config uses a comma-string; CLI uses Vec<String>
    if !cli_set("server_list") {
        if let Some(s) = file_cfg.server_list {
            cli.server_list = s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
        }
    }

    // ── Env vars (win over config file, lose to explicit CLI flags) ───────
    // debug: CLI > ZTP_DEBUG env > config file > ""
    let debug_val = if cli_set("debug") {
        cli.debug.clone()
    } else if let Ok(v) = std::env::var("ZTP_DEBUG") {
        if !v.is_empty() { v } else { cli.debug.clone() }
    } else {
        cli.debug.clone()
    };

    // server_list: CLI > ZTP_SERVER_LIST env > config file > []
    let server_list = if cli_set("server_list") {
        cli.server_list.clone()
    } else if let Ok(env_list) = std::env::var("ZTP_SERVER_LIST") {
        let from_env: Vec<String> = env_list
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !from_env.is_empty() { from_env } else { cli.server_list.clone() }
    } else {
        cli.server_list.clone()
    };

    // log_file: CLI > ZTP_LOG_FILE env > config file > None
    let log_file: Option<PathBuf> = if cli_set("log_file") {
        cli.log_file.clone()
    } else if let Ok(v) = std::env::var("ZTP_LOG_FILE") {
        if !v.is_empty() { Some(PathBuf::from(v)) } else { cli.log_file.clone() }
    } else {
        cli.log_file.clone()
    };

    // Rotation knobs follow the same precedence as log_file. Env-var values
    // that fail to parse silently fall through to the config/default — the
    // typo case is much commoner than a deliberate corruption attempt and a
    // hard exit at this point would be over-eager.
    let log_file_max_bytes: u64 = if cli_set("log_file_max_bytes") {
        cli.log_file_max_bytes
    } else if let Ok(v) = std::env::var("ZTP_LOG_FILE_MAX_BYTES") {
        v.parse().unwrap_or(cli.log_file_max_bytes)
    } else {
        cli.log_file_max_bytes
    };
    let log_file_max_backups: u32 = if cli_set("log_file_max_backups") {
        cli.log_file_max_backups
    } else if let Ok(v) = std::env::var("ZTP_LOG_FILE_MAX_BACKUPS") {
        v.parse().unwrap_or(cli.log_file_max_backups)
    } else {
        cli.log_file_max_backups
    };

    // Logging — env_logger to stderr, optionally teed into log_file (with
    // size-based rotation) so the history persists across reboots even when
    // journald is volatile.
    let log_level_str = if cli.verbose { "debug" } else { "info" };
    std::env::set_var("RUST_LOG", format!("{log_level_str},ureq=warn,rustls=warn"));
    if let Some(path) = log_file.as_ref() {
        let inner = env_logger::Builder::from_default_env().build();
        let level = inner.filter();
        match ztp_agent::logging::TeeLogger::open(
            Box::new(inner),
            path,
            log_file_max_bytes,
            log_file_max_backups,
            level,
        ) {
            Ok(tee) => {
                log::set_max_level(level);
                if let Err(e) = log::set_boxed_logger(Box::new(tee)) {
                    eprintln!("ztp-agent: install tee logger: {e}");
                    std::process::exit(1);
                }
            }
            Err(e) => {
                eprintln!("ztp-agent: {e}");
                std::process::exit(1);
            }
        }
    } else {
        env_logger::init();
    }

    // applier_debug: CLI > ZTP_APPLIER_DEBUG env > config file > ""
    let applier_debug = if cli_set("applier_debug") {
        cli.applier_debug.clone()
    } else if let Ok(v) = std::env::var("ZTP_APPLIER_DEBUG") {
        if !v.is_empty() { v } else { cli.applier_debug.clone() }
    } else {
        cli.applier_debug.clone()
    };

    // applier_log: CLI > ZTP_APPLIER_LOG env > config file > None
    let applier_log: Option<PathBuf> = if cli_set("applier_log") {
        cli.applier_log.clone()
    } else if let Ok(v) = std::env::var("ZTP_APPLIER_LOG") {
        if !v.is_empty() { Some(PathBuf::from(v)) } else { cli.applier_log.clone() }
    } else {
        cli.applier_log.clone()
    };

    // profile: CLI > ZTP_PROFILE env > config file > ""
    if !cli_set("profile") {
        if let Ok(v) = std::env::var("ZTP_PROFILE") {
            if !v.is_empty() { cli.profile = v; }
        }
    }

    // system_clock: CLI > ZTP_SYSTEM_CLOCK env > config file > "auto"
    if !cli_set("system_clock") {
        if let Ok(v) = std::env::var("ZTP_SYSTEM_CLOCK") {
            if !v.is_empty() { cli.system_clock = v; }
        }
    }

    // scan_interval: CLI > ZTP_SCAN_INTERVAL env > config file > "30s"
    if !cli_set("scan_interval") {
        if let Ok(v) = std::env::var("ZTP_SCAN_INTERVAL") {
            if !v.is_empty() { cli.scan_interval = v; }
        }
    }

    // Resolve pubkey from file when not set directly.
    if cli.server_pubkey.is_empty() {
        if let Ok(raw) = std::fs::read_to_string(&cli.server_pubkey_file) {
            let trimmed = raw.trim().to_string();
            if !trimmed.is_empty() {
                cli.server_pubkey = trimmed;
            }
        }
    }

    let sentinel = cli.sentinel.clone();

    // Guard: exit 0 immediately if this device is already provisioned.
    if !cli.force && !sentinel.is_empty() && std::path::Path::new(&sentinel).exists() {
        log::info!("device already provisioned — skipping enrollment sentinel={sentinel}");
        return;
    }

    let scan_interval = match parse_scan_interval(&cli.scan_interval) {
        Ok(d) => d,
        Err(e) => {
            log::error!("invalid --scan-interval {:?}: {e}", cli.scan_interval);
            std::process::exit(2);
        }
    };

    if let Err(e) = run(cli, debug_val, server_list, applier_debug, applier_log, scan_interval) {
        log::error!("{e}");
        std::process::exit(1);
    }

    // Mark the device as provisioned so subsequent boots skip enrollment.
    if !sentinel.is_empty() {
        let sentinel_path = std::path::Path::new(&sentinel);
        if let Some(parent) = sentinel_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(sentinel_path, b"") {
            log::warn!("could not write sentinel file path={sentinel} err={e}");
        } else {
            log::info!("enrollment complete sentinel={sentinel}");
        }
    }
}

fn run(
    cli: Cli,
    debug_val: String,
    server_list: Vec<String>,
    applier_debug: String,
    applier_log: Option<PathBuf>,
    scan_interval: Duration,
) -> Result<()> {
    // --- system clock policy ----------------------------------------------
    let system_clock_policy = ztp_agent::clock::parse_policy(&cli.system_clock)
        .map_err(|e| format!("invalid --system-clock: {e}"))?;

    // --- transport list and HTTP candidate collection ----------------------
    let mut server_pubkey = cli.server_pubkey.clone();
    let transports = build_transport_list(&cli.transport)?;
    let http_candidates = build_http_candidates(
        &cli.server,
        &server_list,
        cli.mdns,
        &cli.mdns_service,
        &mut server_pubkey,
    );
    let scan_cfg = ScanConfig {
        server_url: cli.server.clone(),
        fallbacks: server_list.clone(),
        use_mdns: cli.mdns,
        mdns_service: cli.mdns_service.clone(),
        server_pubkey: server_pubkey.clone(),
    };

    // --- identity ----------------------------------------------------------
    let identity = identity::Identity::load_or_create(&cli.identity)?;

    // --- bootstrap token ---------------------------------------------------
    let bootstrap_token = resolve_token(&cli.token, cli.token_file.as_deref())?;

    // --- applier dispatcher ------------------------------------------------
    let mut dispatcher = appliers::Dispatcher::new(cli.appliers.clone());
    dispatcher.log_file = applier_log;
    match applier_debug.as_str() {
        "trace" => {
            dispatcher.shell_trace = true;
            dispatcher.verbose = true;
        }
        "1" | "verbose" | "true" | "yes" | "on" => {
            dispatcher.verbose = true;
        }
        _ => {}
    }

    // Decode explicitly-supplied server pubkey. Used directly for BLE (TOFU if
    // empty). HTTP candidates resolve their own pubkey per-candidate.
    let base_server_pub_key: Option<[u8; 32]> = if server_pubkey.is_empty() {
        None
    } else {
        let pub_bytes = STANDARD.decode(&server_pubkey).map_err(|_| {
            "--server-pubkey must be a valid base64 string"
        })?;
        if pub_bytes.len() != 32 {
            log::error!("--server-pubkey must be a base64-encoded Ed25519 public key (32 bytes)");
            std::process::exit(2);
        }
        Some(pub_bytes.try_into().unwrap())
    };

    // Base config — server-specific fields (server_url, dial_addr, server_pub_key)
    // are overridden per-candidate inside run_multi_transport.
    let base_cfg = enroll::Config {
        server_url: String::new(),
        device_id: cli.device_id.clone(),
        bootstrap_token,
        profile: if cli.profile.is_empty() { None } else { Some(cli.profile.clone()) },
        server_pub_key: base_server_pub_key,
        ca_file: cli.ca.clone(),
        insecure: cli.insecure,
        identity,
        dispatcher,
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        encrypt: cli.encrypt,
        pending_poll: Duration::from_secs(10),
        max_attempts: 0,
        max_network_failures: 3,
        debug: debug_val,
        dial_addr: None,
        clock_offset: chrono::Duration::zero(),
        ble_name_prefix: cli.ble_name_prefix.clone(),
        system_clock_policy,
        system_clock_threshold: chrono::Duration::zero(),
    };

    run_multi_transport(
        &transports,
        &http_candidates,
        base_cfg,
        &scan_cfg,
        scan_interval,
        cli.ca.as_deref(),
        cli.insecure,
    )
}

// ── Transport-selection types and helpers ────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum TransportKind {
    Http,
    Ble,
}

/// Split and validate the --transport flag. "auto" expands to Http + optionally
/// Ble depending on compile-time feature flags. Duplicates are deduplicated.
fn build_transport_list(s: &str) -> Result<Vec<TransportKind>> {
    let mut out: Vec<TransportKind> = Vec::new();
    let mut seen_http = false;
    let mut seen_ble = false;

    for tok in s.split(',').map(|t| t.trim()) {
        match tok {
            "http" => {
                if !seen_http {
                    out.push(TransportKind::Http);
                    seen_http = true;
                }
            }
            "ble" => {
                if !seen_ble {
                    out.push(TransportKind::Ble);
                    seen_ble = true;
                }
            }
            "auto" => {
                if !seen_http {
                    out.push(TransportKind::Http);
                    seen_http = true;
                }
                // BLE only available when compiled with --features ble on Linux.
                #[cfg(all(feature = "ble", target_os = "linux"))]
                if !seen_ble {
                    out.push(TransportKind::Ble);
                    seen_ble = true;
                }
            }
            unknown => {
                return Err(format!(
                    "unknown --transport {unknown:?}; valid values: http, ble, auto \
                     (or comma-separated list e.g. http,ble)"
                )
                .into());
            }
        }
    }

    if out.is_empty() {
        return Err("--transport must not be empty".into());
    }
    Ok(out)
}

struct HttpCandidate {
    url: String,
    dial_addr: Option<String>,
    pubkey_hint: Option<String>,
}

/// Probe configured server URLs (--server + --server-list) and optionally run
/// mDNS discovery. Returns only reachable candidates in priority order
/// (mDNS-discovered first, then configured URLs). May update server_pubkey if
/// the mDNS TXT record advertises a pubkey= entry.
fn build_http_candidates(
    server_url: &str,
    fallbacks: &[String],
    use_mdns: bool,
    _mdns_service: &str,
    _server_pubkey: &mut String,
) -> Vec<HttpCandidate> {
    let mut all_urls: Vec<String> = Vec::new();
    if !server_url.is_empty() {
        all_urls.push(server_url.to_string());
    }
    all_urls.extend_from_slice(fallbacks);

    let mut candidates: Vec<HttpCandidate> = Vec::new();

    // mDNS discovery — prepend if live, capture pubkey hint from TXT.
    if use_mdns {
        #[cfg(feature = "mdns")]
        {
            match mdns::discover(_mdns_service, Duration::from_secs(5)) {
                Ok(entry) => {
                    let discovered_url = entry.url().to_string();
                    if let Some(dial_str) = transport::probe_with_mdns(&discovered_url) {
                        let hint = if _server_pubkey.is_empty() {
                            entry.pubkey().map(|pk| {
                                *_server_pubkey = pk.clone();
                                pk
                            })
                        } else {
                            None
                        };
                        log::info!("candidates: mDNS discovered server reachable url={discovered_url}");
                        candidates.push(HttpCandidate {
                            url: discovered_url,
                            dial_addr: if dial_str.is_empty() { None } else { Some(dial_str) },
                            pubkey_hint: hint,
                        });
                    } else {
                        log::info!("candidates: mDNS discovered server not reachable url={discovered_url}");
                    }
                }
                Err(e) => log::info!("candidates: mDNS discovery failed: {e}"),
            }
        }
        #[cfg(not(feature = "mdns"))]
        {
            log::warn!("--mdns requested but mDNS support not compiled in; rebuild with --features mdns");
        }
    }

    // Probe each configured URL (skip any already added via mDNS).
    for url in &all_urls {
        if candidates.iter().any(|c| &c.url == url) {
            continue;
        }
        if let Some(dial_str) = transport::probe_with_mdns(url) {
            let dial_addr = if dial_str.is_empty() { None } else { Some(dial_str) };
            log::info!("candidates: server reachable url={url}");
            candidates.push(HttpCandidate {
                url: url.clone(),
                dial_addr,
                pubkey_hint: None,
            });
        } else {
            log::debug!("candidates: server not reachable over TCP url={url}");
        }
    }

    if !all_urls.is_empty() && candidates.is_empty() {
        log::info!("candidates: no configured server reachable over TCP tried={}", all_urls.len());
    }
    candidates
}

fn resolve_server_pubkey_for_candidate(
    candidate: &HttpCandidate,
    global_pubkey_str: &str,
    ca_file: Option<&std::path::Path>,
    insecure: bool,
) -> Result<[u8; 32]> {
    let key_str: String = if !global_pubkey_str.is_empty() {
        global_pubkey_str.to_string()
    } else if let Some(hint) = &candidate.pubkey_hint {
        hint.clone()
    } else {
        if ca_file.is_none() && !insecure {
            log::warn!(
                "fetching server pubkey without a CA cert — TOFU trust \
                 (use --ca to pin the certificate) url={}",
                candidate.url
            );
        }
        let agent = transport::build_agent(
            ca_file,
            insecure || ca_file.is_none(),
            candidate.dial_addr.as_deref(),
        )?;
        let fetched = transport::fetch_server_pubkey(&agent, &candidate.url).map_err(|e| {
            format!("fetch server pubkey from {}: {e}", candidate.url)
        })?;
        log::info!("fetched server pubkey from /v1/server-info url={}", candidate.url);
        fetched
    };

    let pub_bytes = STANDARD.decode(&key_str).map_err(|_| {
        format!("invalid server pubkey for {}: not valid base64", candidate.url)
    })?;
    if pub_bytes.len() != 32 {
        return Err(format!(
            "invalid server pubkey for {}: expected 32 bytes, got {}",
            candidate.url,
            pub_bytes.len()
        )
        .into());
    }
    Ok(pub_bytes.try_into().unwrap())
}

fn run_http_candidates(
    candidates: &[HttpCandidate],
    base_cfg: enroll::Config,
    global_pubkey_str: &str,
    ca_file: Option<&std::path::Path>,
    insecure: bool,
) -> Result<()> {
    if candidates.is_empty() {
        return Err(Box::new(enroll::ServerUnreachableError {
            attempts: 0,
            message: "no reachable HTTP server candidates".to_string(),
        }));
    }
    for candidate in candidates {
        let pub_key = match resolve_server_pubkey_for_candidate(
            candidate,
            global_pubkey_str,
            ca_file,
            insecure,
        ) {
            Ok(k) => k,
            Err(e) => {
                log::warn!(
                    "skipping HTTP candidate: could not resolve server pubkey url={} err={e}",
                    candidate.url
                );
                continue;
            }
        };

        let mut cfg = base_cfg.clone();
        cfg.server_url = candidate.url.clone();
        cfg.dial_addr = candidate.dial_addr.clone();
        cfg.server_pub_key = Some(pub_key);
        cfg.max_network_failures = 3;

        log::info!("trying HTTP candidate url={}", candidate.url);
        match enroll::run(cfg) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if e.downcast_ref::<enroll::ServerUnreachableError>().is_some() {
                    log::info!(
                        "HTTP candidate unreachable after retries, trying next url={}",
                        candidate.url
                    );
                    continue;
                }
                return Err(e); // terminal (rejection, applier failure, etc.)
            }
        }
    }
    Err(Box::new(enroll::ServerUnreachableError {
        attempts: 0,
        message: "all HTTP candidates exhausted".to_string(),
    }))
}

/// Inputs needed to rebuild the HTTP candidate list on each scanner tick.
/// Mirrors the parameters of `build_http_candidates`.
#[derive(Clone)]
struct ScanConfig {
    server_url:    String,
    fallbacks:     Vec<String>,
    use_mdns:      bool,
    mdns_service:  String,
    server_pubkey: String,
}

/// Parse the --scan-interval value. Accepts plain integer seconds ("30") or
/// suffixed values ("30s", "2m", "1h"). Returns Duration::ZERO for "0" / "0s"
/// so the caller can disable rescanning entirely.
fn parse_scan_interval(s: &str) -> std::result::Result<Duration, String> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("empty value".into());
    }
    // Permit suffixes s/m/h; default to seconds when absent.
    let (num_str, mult): (&str, u64) = if let Some(rest) = trimmed.strip_suffix("ms") {
        // milliseconds — useful for tests; not advertised in --help.
        return rest
            .parse::<u64>()
            .map(Duration::from_millis)
            .map_err(|e| format!("parse milliseconds: {e}"));
    } else if let Some(rest) = trimmed.strip_suffix('s') {
        (rest, 1)
    } else if let Some(rest) = trimmed.strip_suffix('m') {
        (rest, 60)
    } else if let Some(rest) = trimmed.strip_suffix('h') {
        (rest, 3600)
    } else {
        (trimmed, 1)
    };
    let n: u64 = num_str.parse().map_err(|e| format!("parse number: {e}"))?;
    Ok(Duration::from_secs(n * mult))
}

/// Periodically rebuild the HTTP candidate list (re-running mDNS discovery
/// and TCP-probing static URLs) and attempt enrollment as soon as any
/// candidate becomes reachable. Returns:
///   - `Ok(())` on a successful enrollment;
///   - a terminal error (rejection, applier failure) — surfaced immediately;
///   - `Err(BleCancelledError)` if `cancel` is observed `true`.
///
/// `ServerUnreachableError` from a single attempt is *not* terminal — the
/// loop keeps scanning until cancelled or something else succeeds.
fn scan_and_enroll(
    interval: Duration,
    scan_cfg: &ScanConfig,
    base_cfg: &enroll::Config,
    ca_file: Option<&std::path::Path>,
    insecure: bool,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<()> {
    log::info!("scan-and-enroll: starting periodic HTTP rescan interval={interval:?}");
    // Sleep in small increments so cancel is observed promptly.
    let tick = std::cmp::min(interval, Duration::from_millis(500));
    let mut elapsed = Duration::ZERO;
    loop {
        // Wait for `interval`, polling cancel every `tick`.
        while elapsed < interval {
            if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                return Err(Box::new(ble::BleCancelledError));
            }
            std::thread::sleep(tick);
            elapsed += tick;
        }
        elapsed = Duration::ZERO;
        if cancel.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Box::new(ble::BleCancelledError));
        }
        // Per-tick local copy: build_http_candidates may set a freshly-
        // discovered mDNS pubkey hint, but we don't want one tick's hint to
        // leak into the next.
        let mut key_str = scan_cfg.server_pubkey.clone();
        let candidates = build_http_candidates(
            &scan_cfg.server_url,
            &scan_cfg.fallbacks,
            scan_cfg.use_mdns,
            &scan_cfg.mdns_service,
            &mut key_str,
        );
        if candidates.is_empty() {
            log::debug!("scan-and-enroll: no reachable HTTP server this tick");
            continue;
        }
        log::info!(
            "scan-and-enroll: HTTP server reachable, attempting enrollment candidates={}",
            candidates.len()
        );
        match run_http_candidates(&candidates, base_cfg.clone(), &key_str, ca_file, insecure) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if e.downcast_ref::<enroll::ServerUnreachableError>().is_some() {
                    log::info!("scan-and-enroll: enrollment attempt failed, will retry: {e}");
                    continue;
                }
                // Terminal — propagate.
                return Err(e);
            }
        }
    }
}

/// Orchestrate enrollment across the configured transports.
///
/// **Phase 1 (fast path):** if HTTP is in the transport list, try the
/// candidates already probed at startup. Success → return; non-network error
/// → return.
///
/// **Phase 2 (concurrent fallback):** if Phase 1 exhausted HTTP candidates
/// without success, run BLE (if requested + capable) and a periodic HTTP
/// rescanner (if `scan_interval > 0`) on background threads. The first to
/// succeed wins; the loser is signalled to abort via the shared `cancel`
/// flag. A terminal error from either side is propagated and cancels the
/// other.
///
/// When `scan_interval == 0` the rescanner is disabled, restoring the legacy
/// one-shot HTTP-then-BLE behaviour.
fn run_multi_transport(
    transports: &[TransportKind],
    candidates: &[HttpCandidate],
    base_cfg: enroll::Config,
    scan_cfg: &ScanConfig,
    scan_interval: Duration,
    ca_file: Option<&std::path::Path>,
    insecure: bool,
) -> Result<()> {
    let http_req = transports.contains(&TransportKind::Http);
    let ble_req = transports.contains(&TransportKind::Ble);

    // ── Phase 1: initial HTTP attempt with pre-probed candidates ─────────
    if http_req {
        match run_http_candidates(candidates, base_cfg.clone(), &scan_cfg.server_pubkey, ca_file, insecure) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if e.downcast_ref::<enroll::ServerUnreachableError>().is_none() {
                    return Err(e); // terminal
                }
                log::info!("HTTP exhausted on initial probe; entering concurrent scan/BLE phase");
            }
        }
    }

    // ── Phase 2: race the BLE peripheral against a periodic HTTP rescanner ─
    let run_scanner = http_req && scan_interval > Duration::ZERO;
    let run_ble_thread = ble_req;

    if !run_scanner && !run_ble_thread {
        return Err(Box::new(enroll::ServerUnreachableError {
            attempts: 0,
            message: "all transports exhausted".to_string(),
        }));
    }

    let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (tx, rx) = std::sync::mpsc::channel::<(&'static str, Result<()>)>();
    let mut workers = 0;

    if run_scanner {
        workers += 1;
        let tx = tx.clone();
        let cancel = cancel.clone();
        let scan_cfg = scan_cfg.clone();
        let base_cfg = base_cfg.clone();
        let ca_file_owned: Option<PathBuf> = ca_file.map(|p| p.to_path_buf());
        std::thread::Builder::new()
            .name("ztp-scan".into())
            .spawn(move || {
                let r = scan_and_enroll(
                    scan_interval,
                    &scan_cfg,
                    &base_cfg,
                    ca_file_owned.as_deref(),
                    insecure,
                    cancel,
                );
                let _ = tx.send(("http-scan", r));
            })
            .expect("spawn ztp-scan thread");
    }
    if run_ble_thread {
        workers += 1;
        let tx = tx.clone();
        let cancel = cancel.clone();
        let base_cfg = base_cfg.clone();
        std::thread::Builder::new()
            .name("ztp-ble".into())
            .spawn(move || {
                log::info!("trying BLE transport (concurrent with HTTP rescanner)");
                let r = ble::run_ble(&base_cfg, cancel);
                let _ = tx.send(("ble", r));
            })
            .expect("spawn ztp-ble thread");
    }
    drop(tx); // we hold no senders; channel closes once all workers exit.

    let mut success = false;
    let mut terminal_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    let mut last_unreachable_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;

    for _ in 0..workers {
        match rx.recv() {
            Ok((source, Ok(()))) => {
                log::info!("transport succeeded; cancelling other workers source={source}");
                success = true;
                cancel.store(true, std::sync::atomic::Ordering::Relaxed);
            }
            Ok((source, Err(e))) => {
                if e.downcast_ref::<ble::BleCancelledError>().is_some() {
                    // We cancelled this worker — expected, ignore.
                } else if e.downcast_ref::<enroll::ServerUnreachableError>().is_some() {
                    log::info!("transport unreachable source={source} err={e}");
                    last_unreachable_err = Some(e);
                } else if terminal_err.is_none() {
                    log::info!("transport returned terminal error; cancelling other workers source={source} err={e}");
                    terminal_err = Some(e);
                    cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
            Err(_) => break, // channel closed unexpectedly
        }
    }

    if success {
        Ok(())
    } else if let Some(e) = terminal_err {
        Err(e)
    } else if let Some(e) = last_unreachable_err {
        Err(e)
    } else {
        Err(Box::new(enroll::ServerUnreachableError {
            attempts: 0,
            message: "all transports exhausted".to_string(),
        }))
    }
}

fn resolve_token(token_flag: &str, token_file: Option<&std::path::Path>) -> Result<Option<String>> {
    if !token_flag.is_empty() {
        return Ok(Some(token_flag.to_string()));
    }
    if let Some(path) = token_file {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("read token file {}: {e}", path.display()))?;
        return Ok(Some(raw.trim().to_string()));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn parse_scan_interval_seconds_default() {
        assert_eq!(parse_scan_interval("30").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn parse_scan_interval_with_suffixes() {
        assert_eq!(parse_scan_interval("45s").unwrap(), Duration::from_secs(45));
        assert_eq!(parse_scan_interval("2m").unwrap(),  Duration::from_secs(120));
        assert_eq!(parse_scan_interval("1h").unwrap(),  Duration::from_secs(3600));
        assert_eq!(parse_scan_interval("250ms").unwrap(), Duration::from_millis(250));
    }

    #[test]
    fn parse_scan_interval_zero_disables() {
        assert_eq!(parse_scan_interval("0").unwrap(),   Duration::ZERO);
        assert_eq!(parse_scan_interval("0s").unwrap(),  Duration::ZERO);
    }

    #[test]
    fn parse_scan_interval_rejects_invalid() {
        assert!(parse_scan_interval("").is_err());
        assert!(parse_scan_interval("abc").is_err());
        assert!(parse_scan_interval("30x").is_err());
    }

    #[test]
    fn parse_scan_interval_trims_whitespace() {
        assert_eq!(parse_scan_interval("  30s  ").unwrap(), Duration::from_secs(30));
    }

    /// scan_and_enroll must return BleCancelledError promptly when the cancel
    /// flag is flipped, even if the candidate list keeps coming up empty.
    #[test]
    fn scan_and_enroll_returns_on_cancel() {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(80));
            cancel_clone.store(true, Ordering::Relaxed);
        });

        let scan_cfg = ScanConfig {
            server_url: String::new(),
            // Unreachable port — every tick produces zero candidates.
            fallbacks: vec!["http://127.0.0.1:19999".to_string()],
            use_mdns: false,
            mdns_service: "_ztp._tcp".to_string(),
            server_pubkey: String::new(),
        };
        let base_cfg = build_minimal_base_cfg();

        let start = std::time::Instant::now();
        let err = scan_and_enroll(
            Duration::from_millis(50),
            &scan_cfg,
            &base_cfg,
            None,
            true,
            cancel,
        )
        .expect_err("expected BleCancelledError");
        assert!(
            err.downcast_ref::<ble::BleCancelledError>().is_some(),
            "expected BleCancelledError, got: {err}"
        );
        assert!(
            start.elapsed() < Duration::from_millis(800),
            "scan_and_enroll took too long to honour cancel: {:?}",
            start.elapsed()
        );
    }

    /// Construct a minimal enroll::Config sufficient for scan_and_enroll to
    /// reach (and fail) the candidate-probe step. We never expect this to
    /// produce successful enrollment in the cancel test.
    fn build_minimal_base_cfg() -> enroll::Config {
        let tmp = tempfile::tempdir().unwrap();
        let id = identity::Identity::load_or_create(&tmp.path().join("id.key")).unwrap();
        let dispatcher = appliers::Dispatcher::new(tmp.path().to_path_buf());
        // tmp goes out of scope here; identity + dispatcher have already
        // captured what they need (file already created on disk for identity,
        // and dispatcher only references the path lazily on apply()).
        std::mem::forget(tmp);
        enroll::Config {
            server_url: String::new(),
            device_id: "test-dev".to_string(),
            bootstrap_token: None,
            profile: None,
            server_pub_key: None,
            ca_file: None,
            insecure: true,
            identity: id,
            dispatcher,
            agent_version: "test".to_string(),
            encrypt: false,
            pending_poll: Duration::from_millis(10),
            max_attempts: 0,
            max_network_failures: 1,
            debug: String::new(),
            dial_addr: None,
            clock_offset: chrono::Duration::zero(),
            ble_name_prefix: "ztp-".to_string(),
            system_clock_policy: ztp_agent::clock::Policy::Off,
            system_clock_threshold: chrono::Duration::zero(),
        }
    }
}
