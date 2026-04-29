//! Device facts collection — mirrors internal/agent/facts/facts.go.
//!
//! All collection is best-effort: missing fields on unusual platforms are fine.
//! The go agent uses runtime.GOOS/GOARCH which differ from Rust's consts —
//! we normalise to match Go's naming (amd64, arm64, arm, 386).

use crate::wire::DeviceFacts;

/// Collect device facts for inclusion in `EnrollRequest.facts`.
pub fn collect(agent_version: &str) -> DeviceFacts {
    DeviceFacts {
        machine_id: read_machine_id(),
        mac_addresses: collect_mac_addresses(),
        serial: read_trimmed("/sys/firmware/devicetree/base/serial-number"),
        model: read_trimmed("/sys/firmware/devicetree/base/model"),
        hostname: read_hostname(),
        os: Some(normalize_os(std::env::consts::OS).to_string()),
        arch: Some(normalize_arch(std::env::consts::ARCH).to_string()),
        agent_version: Some(agent_version.to_string()),
    }
}

/// Map Rust arch names to Go's naming convention.
///
/// Rust  →  Go
/// x86_64   amd64
/// aarch64  arm64
/// arm      arm
/// x86      386
fn normalize_arch(arch: &str) -> &str {
    match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        "x86" => "386",
        other => other, // "arm", "riscv64", etc. pass through unchanged
    }
}

/// Map Rust OS names to Go's convention (they match for common targets).
fn normalize_os(os: &str) -> &str {
    // Rust and Go both use "linux", "windows", "macos" → "darwin"
    match os {
        "macos" => "darwin",
        other => other,
    }
}

fn read_machine_id() -> Option<String> {
    std::fs::read_to_string("/etc/machine-id")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Read a file, stripping whitespace and embedded null bytes (device-tree files
/// sometimes have null terminators).
fn read_trimmed(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().trim_matches('\0').to_string())
        .filter(|s| !s.is_empty())
}

fn read_hostname() -> Option<String> {
    // On Linux, /proc/sys/kernel/hostname is the authoritative source.
    // Fall back to the system gethostname call via the gethostname crate.
    if let Ok(h) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        let s = h.trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    let h = gethostname::gethostname();
    let s = h.to_string_lossy().to_string();
    if s.is_empty() { None } else { Some(s) }
}

/// Enumerate non-loopback network interfaces and collect their MAC addresses
/// by reading /sys/class/net/<iface>/address on Linux.
fn collect_mac_addresses() -> Vec<String> {
    let mut macs = Vec::new();

    // Linux-specific: /sys/class/net
    let sys_net = std::path::Path::new("/sys/class/net");
    if let Ok(entries) = std::fs::read_dir(sys_net) {
        for entry in entries.flatten() {
            let name = entry.file_name();
            let iface = name.to_string_lossy();
            if iface == "lo" {
                continue; // skip loopback
            }
            // Check if this is a physical interface (has a real MAC)
            let addr_path = format!("/sys/class/net/{}/address", iface);
            if let Ok(mac) = std::fs::read_to_string(&addr_path) {
                let mac = mac.trim().to_string();
                if !mac.is_empty() && mac != "00:00:00:00:00:00" {
                    macs.push(mac);
                }
            }
        }
    }
    macs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arch_normalisation() {
        assert_eq!(normalize_arch("x86_64"), "amd64");
        assert_eq!(normalize_arch("aarch64"), "arm64");
        assert_eq!(normalize_arch("x86"), "386");
        assert_eq!(normalize_arch("arm"), "arm");
        assert_eq!(normalize_arch("riscv64"), "riscv64");
    }

    #[test]
    fn os_normalisation() {
        assert_eq!(normalize_os("macos"), "darwin");
        assert_eq!(normalize_os("linux"), "linux");
        assert_eq!(normalize_os("windows"), "windows");
    }

    #[test]
    fn collect_returns_sensible_values() {
        let f = collect("test-1.0");
        assert_eq!(f.agent_version.as_deref(), Some("test-1.0"));
        // os and arch are always populated
        assert!(f.os.is_some());
        assert!(f.arch.is_some());
    }
}
