//! HTTP transport layer — mirrors the HTTP path in internal/agent/run.go.
//!
//! Builds a `ureq::Agent` with optional CA pinning or TOFU TLS, then exposes
//! typed helpers for the two endpoints the agent needs:
//!   GET  /v1/server-info  → server signing pubkey
//!   POST /v1/enroll       → enrollment loop

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use ureq::AgentBuilder;

use crate::sign::SignedEnvelope;
use crate::wire::EnrollResponse;

/// Build a `ureq::Agent`.
///
/// | `ca_file` | `insecure` | behaviour                                              |
/// |-----------|------------|--------------------------------------------------------|
/// | Some      | false      | Verify against that CA (pinned cert)                   |
/// | None      | false      | TOFU — skip TLS verification (caller should warn user) |
/// | *         | true       | Skip TLS verification (dev only)                       |
///
/// When `dial_addr` is set (e.g. `192.168.68.56:8443` from mDNS discovery)
/// all TCP connections go directly to that IP, bypassing DNS.  TLS SNI still
/// uses the hostname from the URL so the server's virtual-host routing works.
pub fn build_agent(
    ca_file: Option<&std::path::Path>,
    insecure: bool,
    dial_addr: Option<&str>,
) -> crate::Result<ureq::Agent> {
    // rustls 0.23 requires a crypto provider; install ring as the default once.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tls_config = if let Some(path) = ca_file {
        build_pinned_tls(path)?
    } else if insecure {
        build_skip_verify_tls()
    } else {
        // TOFU: caller has already warned the user
        build_skip_verify_tls()
    };

    let mut builder = AgentBuilder::new()
        .tls_config(Arc::new(tls_config))
        .timeout_connect(std::time::Duration::from_secs(10))
        .timeout(std::time::Duration::from_secs(30));

    if let Some(addr_str) = dial_addr {
        let ip: IpAddr = addr_str
            .rsplit(':')
            .nth(1)
            .unwrap_or(addr_str)
            .parse()
            .map_err(|e| format!("dial_addr: invalid IP in {addr_str:?}: {e}"))?;
        builder = builder.resolver(MdnsResolver { ip });
    }

    Ok(builder.build())
}

/// Custom resolver that routes all TCP connections through a fixed IP.
///
/// Used for mDNS-discovered servers whose `.local` hostnames cannot be
/// resolved by the system's DNS resolver (Linux without nss-mdns).
/// The port is taken from `netloc` so ureq uses the correct URL port.
struct MdnsResolver {
    ip: IpAddr,
}

impl ureq::Resolver for MdnsResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<SocketAddr>> {
        let port = netloc
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(443);
        Ok(vec![SocketAddr::new(self.ip, port)])
    }
}

/// GET /v1/server-info and return the base64-encoded Ed25519 public key.
pub fn fetch_server_pubkey(agent: &ureq::Agent, server_url: &str) -> crate::Result<String> {
    let url = format!("{server_url}/v1/server-info");
    let resp = agent
        .get(&url)
        .call()
        .map_err(|e| format!("GET {url}: {e}"))?;

    #[derive(serde::Deserialize)]
    struct ServerInfo {
        public_key: String,
    }
    let info: ServerInfo = resp
        .into_json()
        .map_err(|e| format!("decode /v1/server-info: {e}"))?;

    if info.public_key.is_empty() {
        return Err("/v1/server-info: empty public_key field".into());
    }
    Ok(info.public_key)
}

/// POST /v1/enroll with `env` and return the parsed `EnrollResponse`.
pub fn post_enroll(
    agent: &ureq::Agent,
    server_url: &str,
    env: &SignedEnvelope,
) -> crate::Result<EnrollResponse> {
    let url = format!("{server_url}/v1/enroll");
    let body = serde_json::to_string(env)?;
    let resp = agent
        .post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body)
        .map_err(|e| format!("POST {url}: {e}"))?;

    let status = resp.status();
    let text = resp.into_string()?;

    if status >= 500 {
        return Err(format!("server error {status}: {text}").into());
    }

    serde_json::from_str(&text).map_err(|e| format!("decode enroll response: {e}").into())
}

/// TCP-probe a server URL (3-second timeout), returning true if connectable.
/// Mirrors probeServer() in cmd/ztp-agent/main.go.
pub fn probe_server(raw_url: &str) -> bool {
    // Manual URL parsing to avoid pulling in the `url` crate (and transitively icu_*).
    let without_scheme = raw_url
        .strip_prefix("https://")
        .or_else(|| raw_url.strip_prefix("http://"))
        .unwrap_or(raw_url);
    // Strip any path/query after first '/'
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let (host, port) = if let Some(bracket_end) = authority.find(']') {
        // IPv6 literal: [::1]:8080
        let after = &authority[bracket_end + 1..];
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(if raw_url.starts_with("https://") { 443 } else { 80 });
        (&authority[..bracket_end + 1], port)
    } else if let Some(colon) = authority.rfind(':') {
        // host:port
        let port = authority[colon + 1..]
            .parse::<u16>()
            .unwrap_or(if raw_url.starts_with("https://") { 443 } else { 80 });
        (&authority[..colon], port)
    } else {
        (authority, if raw_url.starts_with("https://") { 443 } else { 80 })
    };
    let addr = format!("{host}:{port}");
    std::net::TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .ok()
            .and_then(|mut i| i.next())
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
        std::time::Duration::from_secs(3),
    )
    .is_ok()
}

/// TCP-probe using an explicit `ip:port`, bypassing DNS.
/// Used after resolving a `.local` hostname via mDNS.
pub fn probe_server_dial(dial: &str) -> bool {
    use std::net::ToSocketAddrs;
    std::net::TcpStream::connect_timeout(
        &dial
            .to_socket_addrs()
            .ok()
            .and_then(|mut i| i.next())
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap()),
        std::time::Duration::from_secs(5),
    )
    .is_ok()
}

/// Probe `raw_url` for TCP reachability, with automatic mDNS fallback for
/// `.local` hostnames that the system resolver can't resolve (e.g.
/// systemd-resolved without per-link mDNS or nss-mdns).
///
/// Returns `Some(dial)` where `dial` is `"ip:port"` used to reach the server
/// (`""` when normal DNS succeeded), or `None` if unreachable.
pub fn probe_with_mdns(raw_url: &str) -> Option<String> {
    if probe_server(raw_url) {
        return Some(String::new());
    }

    // Extract host and port from the URL (same manual parsing as probe_server).
    let without_scheme = raw_url
        .strip_prefix("https://")
        .or_else(|| raw_url.strip_prefix("http://"))
        .unwrap_or(raw_url);
    let authority = without_scheme.split('/').next().unwrap_or(without_scheme);
    let (host, port) = if let Some(colon) = authority.rfind(':') {
        let p = authority[colon + 1..]
            .parse::<u16>()
            .unwrap_or(if raw_url.starts_with("https://") { 443 } else { 80 });
        (&authority[..colon], p)
    } else {
        (authority, if raw_url.starts_with("https://") { 443 } else { 80 })
    };

    if !host.to_lowercase().ends_with(".local") {
        return None;
    }

    log::debug!("probe: normal DNS failed for .local host, trying mDNS multicast host={host}");
    let ip = resolve_mdns_host(host, std::time::Duration::from_secs(3))?;
    let dial = format!("{ip}:{port}");
    if probe_server_dial(&dial) {
        Some(dial)
    } else {
        log::debug!("probe: mDNS resolved but TCP connect failed host={host} ip={ip}");
        None
    }
}

/// Resolve a `.local` hostname by sending a raw mDNS multicast A query to
/// 224.0.0.251:5353 and returning the first matching IPv4 address.
///
/// This is needed on systems where Go/Rust's pure resolver doesn't honour the
/// system stub's mDNS support — e.g. systemd-resolved without per-link mDNS
/// active for the current link, or without nss-mdns installed.
pub fn resolve_mdns_host(host: &str, timeout: std::time::Duration) -> Option<std::net::Ipv4Addr> {
    use std::net::UdpSocket;

    let host = host.trim_end_matches('.');
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.set_read_timeout(Some(timeout)).ok()?;

    let query = build_mdns_a_query(host);
    socket.send_to(&query, "224.0.0.251:5353").ok()?;

    let want = format!("{}.", host.to_lowercase());
    let mut buf = [0u8; 2048];
    loop {
        let (n, _) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(_) => return None, // timeout or error
        };
        if let Some(ip) = parse_mdns_a_record(&buf[..n], &want) {
            return Some(ip);
        }
    }
}

/// Build a minimal DNS message querying for an A record for `name`.
fn build_mdns_a_query(name: &str) -> Vec<u8> {
    let mut msg = Vec::new();
    // Header: ID=0, FLAGS=0 (standard query), QDCOUNT=1, rest=0
    msg.extend_from_slice(&[0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    // Encode the name as DNS labels
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() {
            continue;
        }
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0); // root label
    msg.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
    msg
}

/// Scan a DNS/mDNS response for an A record matching `want` (FQDN with trailing dot).
fn parse_mdns_a_record(data: &[u8], want: &str) -> Option<std::net::Ipv4Addr> {
    if data.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;

    let mut pos = 12;

    // Skip question section.
    for _ in 0..qdcount {
        let (_, next) = read_dns_name(data, pos)?;
        pos = next + 4; // skip QTYPE + QCLASS
    }

    // Scan answer + authority + additional sections for an A record.
    for _ in 0..(ancount + nscount + arcount) {
        let (name, next) = read_dns_name(data, pos)?;
        pos = next;
        if pos + 10 > data.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let rdlen = u16::from_be_bytes([data[pos + 8], data[pos + 9]]) as usize;
        pos += 10;
        if rtype == 1 && rdlen == 4 && pos + 4 <= data.len() {
            if name.to_lowercase() == want {
                return Some(std::net::Ipv4Addr::new(
                    data[pos],
                    data[pos + 1],
                    data[pos + 2],
                    data[pos + 3],
                ));
            }
        }
        pos = pos.checked_add(rdlen).filter(|&p| p <= data.len())?;
    }
    None
}

/// Read a DNS label-encoded name (with pointer-compression support) starting
/// at `pos`. Returns `(name_fqdn, next_pos)` where `next_pos` is the byte
/// immediately after the name in the wire encoding (following pointer bytes,
/// not the pointed-to bytes).
fn read_dns_name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut result = String::new();
    let mut cur = start;
    let mut caller_next: Option<usize> = None;
    let mut budget = 128usize; // guard against pointer loops

    loop {
        if budget == 0 || cur >= data.len() {
            return None;
        }
        budget -= 1;

        let b = data[cur];
        if b == 0 {
            // End of name.
            if caller_next.is_none() {
                caller_next = Some(cur + 1);
            }
            result.push('.'); // trailing dot → FQDN
            break;
        }

        if b & 0xC0 == 0xC0 {
            // Pointer compression: next 14 bits are the offset.
            if cur + 1 >= data.len() {
                return None;
            }
            if caller_next.is_none() {
                caller_next = Some(cur + 2);
            }
            let offset = (((b & 0x3F) as usize) << 8) | data[cur + 1] as usize;
            cur = offset;
            continue;
        }

        let label_len = b as usize;
        let end = cur + 1 + label_len;
        if end > data.len() {
            return None;
        }
        if !result.is_empty() {
            result.push('.');
        }
        result.push_str(std::str::from_utf8(&data[cur + 1..end]).ok()?);
        cur = end;
    }

    Some((result, caller_next?))
}

// ---- TLS builders -----------------------------------------------------------

fn build_pinned_tls(ca_path: &std::path::Path) -> crate::Result<ClientConfig> {
    let pem = std::fs::read(ca_path)
        .map_err(|e| format!("read CA cert {}: {e}", ca_path.display()))?;
    let mut reader = std::io::BufReader::new(pem.as_slice());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("parse CA cert: {e}"))?;

    let mut root_store = RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .map_err(|e| format!("add CA cert: {e}"))?;
    }

    ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .pipe(Ok)
}

fn build_skip_verify_tls() -> ClientConfig {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, Error, SignatureScheme};

    #[derive(Debug)]
    struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            Ok(ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Ok(HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA1,
                SignatureScheme::ECDSA_SHA1_Legacy,
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP521_SHA512,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
                SignatureScheme::ED448,
            ]
        }
    }

    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerifier))
        .with_no_client_auth()
}

// Pipeline helper to keep builder chains readable.
trait Pipe: Sized {
    fn pipe<F, R>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}
impl<T> Pipe for T {}
