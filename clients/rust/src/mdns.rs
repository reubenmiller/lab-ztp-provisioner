//! mDNS server discovery — mirrors internal/mdns/mdns.go.
//!
//! Discovers the ZTP server's `_ztp._tcp` service on the local network.
//! The server's signing public key is extracted from the TXT record `pubkey=`.

#[cfg(feature = "mdns")]
pub use imp::*;

#[cfg(feature = "mdns")]
mod imp {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    use mdns_sd::{ServiceDaemon, ServiceEvent};

    /// A discovered ZTP server instance.
    #[derive(Debug, Clone)]
    pub struct Entry {
        /// Hostname of the server, e.g. `ztp.local` (trailing dot stripped).
        /// Used as the URL host so TLS SNI and Caddy virtual-host routing work.
        pub host: String,
        /// Raw IP address — use for TCP dial when the hostname is not resolvable
        /// via system DNS (Linux without nss-mdns).
        pub addr: IpAddr,
        pub port: u16,
        pub txt: Vec<String>,
    }

    impl Entry {
        /// HTTP(S) URL of the server using the SRV hostname (e.g.
        /// `https://ztp.local:8443`) so that TLS SNI and the HTTP `Host`
        /// header match what the server expects.  Falls back to the raw IP
        /// when no hostname is available.
        pub fn url(&self) -> String {
            let scheme = self
                .txt_value("scheme")
                .unwrap_or_else(|| "http".to_string());
            let host = if self.host.is_empty() {
                self.addr.to_string()
            } else {
                self.host.clone()
            };
            format!("{}://{}:{}", scheme, host, self.port)
        }

        /// `ip:port` string for TCP dial-override (bypasses DNS).
        pub fn dial_addr(&self) -> String {
            format!("{}:{}", self.addr, self.port)
        }

        /// Server signing public key from `pubkey=<base64>` TXT record.
        pub fn pubkey(&self) -> Option<String> {
            self.txt_value("pubkey")
        }

        fn txt_value(&self, key: &str) -> Option<String> {
            let prefix = format!("{key}=");
            self.txt.iter().find_map(|t| t.strip_prefix(&prefix).map(str::to_string))
        }
    }

    /// Discover the ZTP server on the local LAN via mDNS/DNS-SD.
    ///
    /// Returns the first entry found within `timeout`, or an error.
    pub fn discover(service_type: &str, timeout: Duration) -> crate::Result<Entry> {
        let daemon = ServiceDaemon::new()
            .map_err(|e| format!("mdns daemon: {e}"))?;

        // The service type passed to mdns-sd must end with ".local."
        let query = if service_type.ends_with(".local.") {
            service_type.to_string()
        } else {
            format!("{service_type}.local.")
        };

        let receiver = daemon
            .browse(&query)
            .map_err(|e| format!("mdns browse {query}: {e}"))?;

        let deadline = std::time::Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                let _ = daemon.shutdown();
                return Err(format!("mDNS: no server found for {service_type} within {timeout:?}").into());
            }
            match receiver.recv_timeout(remaining.min(Duration::from_millis(200))) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    let addr = info
                        .get_addresses()
                        .iter()
                        .find(|a| a.is_ipv4())
                        .copied()
                        .or_else(|| info.get_addresses().iter().next().copied())
                        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                    let txt: Vec<String> = info.get_properties()
                        .iter()
                        .filter_map(|p| {
                            let val = p.val_str();
                            if val.is_empty() {
                                Some(p.key().to_string())
                            } else {
                                Some(format!("{}={}", p.key(), val))
                            }
                        })
                        .collect();
                    let entry = Entry {
                        host: info.get_hostname().trim_end_matches('.').to_string(),
                        addr,
                        port: info.get_port(),
                        txt,
                    };
                    let _ = daemon.shutdown();
                    return Ok(entry);
                }
                Ok(_) => {} // ServiceFound, ServiceRemoved, etc. — wait for Resolved
                Err(_) => {} // timeout on this iteration — loop back
            }
        }
    }
}

// Stub for when the feature is disabled
#[cfg(not(feature = "mdns"))]
pub fn discover(_service_type: &str, _timeout: std::time::Duration) -> crate::Result<()> {
    Err("mDNS support not compiled in; rebuild with --features mdns".into())
}
