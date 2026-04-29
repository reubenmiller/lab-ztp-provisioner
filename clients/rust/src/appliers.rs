//! Script applier dispatcher — mirrors internal/agent/appliers/dispatch.go.
//!
//! Only drop-in scripts are supported; there are no compiled-in handlers.
//! This keeps the binary small and lets operators override any module.
//!
//! A script at `<scripts_dir>/<sanitized_type>.sh` is invoked with the module's
//! payload on stdin (JSON for payload modules, raw bytes for raw_payload modules).
//! Combined stdout+stderr is captured as the result output. Non-zero exit = error.

use std::io::Write;
use std::path::PathBuf;
use std::time::Duration;

use crate::wire::{Module, ModuleResult, ProvisioningBundle};

#[derive(Clone)]
pub struct Dispatcher {
    /// Directory of drop-in shell scripts. Default: `/etc/ztp/appliers.d`.
    pub scripts_dir: PathBuf,
    /// Per-applier timeout. Default: 60 seconds.
    pub timeout: Duration,
    /// Log stdout/stderr of every applier, not only on failure.
    pub verbose: bool,
    /// Run scripts via `sh -x` to trace each command.
    pub shell_trace: bool,
    /// Optional path to an append-only log file for all applier output.
    pub log_file: Option<PathBuf>,
}

impl Dispatcher {
    pub fn new(scripts_dir: PathBuf) -> Self {
        Self {
            scripts_dir,
            timeout: Duration::from_secs(60),
            verbose: false,
            shell_trace: false,
            log_file: None,
        }
    }

    pub fn apply(&self, bundle: &ProvisioningBundle) -> Vec<ModuleResult> {
        bundle.modules.iter().map(|m| self.apply_one(m)).collect()
    }

    fn apply_one(&self, m: &Module) -> ModuleResult {
        eprintln!("[ztp-agent] applying module: {}", m.module_type);
        let sanitized = sanitize_type(&m.module_type);
        let script_path = self.scripts_dir.join(format!("{sanitized}.sh"));

        if script_path.is_file() {
            let (output, err) = run_script(&script_path, m, self.timeout, self.shell_trace);
            let trimmed = output.trim().to_string();
            let result = if let Some(ref e) = err {
                eprintln!("[ztp-agent] applier {} FAILED: {e}", m.module_type);
                if !trimmed.is_empty() {
                    eprintln!("[ztp-agent] applier {} output:\n{trimmed}", m.module_type);
                }
                ModuleResult {
                    module_type: m.module_type.clone(),
                    ok: false,
                    skipped: false,
                    error: Some(e.clone()),
                    output: if trimmed.is_empty() { None } else { Some(trimmed.clone()) },
                }
            } else {
                if self.verbose || self.shell_trace {
                    eprintln!("[ztp-agent] applier {} ok", m.module_type);
                    if !trimmed.is_empty() {
                        eprintln!("[ztp-agent] applier {} output:\n{trimmed}", m.module_type);
                    }
                }
                ModuleResult {
                    module_type: m.module_type.clone(),
                    ok: true,
                    skipped: false,
                    error: None,
                    output: if trimmed.is_empty() { None } else { Some(trimmed.clone()) },
                }
            };
            self.append_log(&m.module_type, script_path.display().to_string().as_str(), &trimmed, err.as_deref());
            result
        } else {
            ModuleResult {
                module_type: m.module_type.clone(),
                ok: false,
                skipped: true,
                error: Some("no applier registered for module type".to_string()),
                output: None,
            }
        }
    }

    fn append_log(&self, module_type: &str, source: &str, output: &str, err: Option<&str>) {
        let Some(ref log_path) = self.log_file else { return };
        if let Some(parent) = log_path.parent() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                eprintln!("could not create applier log directory {}: {e}", parent.display());
                return;
            }
        }
        let Ok(mut f) = std::fs::OpenOptions::new()
            .append(true).create(true).open(log_path)
        else { return };
        let status = if err.is_some() { "FAILED" } else { "ok" };
        let _ = writeln!(f, "\n=== applier {module_type} [{source}] status={status} ===");
        if !output.is_empty() {
            let _ = writeln!(f, "{output}");
        }
        if let Some(e) = err {
            let _ = writeln!(f, "error: {e}");
        }
    }
}

/// Sanitize a module type string to a safe filename component.
/// Mirrors Go's sanitizeType: replace `/`, `\`, and `..` with `_`.
fn sanitize_type(t: &str) -> String {
    let t = t.trim();
    let t = t.replace('/', "_");
    let t = t.replace('\\', "_");
    let t = t.replace("..", "_");
    t
}

/// Run a script with the module's payload on stdin.
/// Returns (combined_output, error_message).
fn run_script(path: &std::path::Path, module: &Module, timeout: Duration, shell_trace: bool) -> (String, Option<String>) {
    let stdin_bytes: Vec<u8> = if let Some(raw) = &module.raw_payload {
        raw.clone()
    } else if let Some(payload) = &module.payload {
        match serde_json::to_vec(payload) {
            Ok(b) => b,
            Err(e) => {
                return (String::new(), Some(format!("marshal payload: {e}")));
            }
        }
    } else {
        b"{}".to_vec()
    };

    let mut cmd = if shell_trace {
        let mut c = std::process::Command::new("sh");
        c.arg("-x").arg(path);
        c
    } else {
        std::process::Command::new(path)
    };
    cmd.stdin(std::process::Stdio::piped());
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            return (String::new(), Some(format!("spawn {}: {e}", path.display())));
        }
    };

    // Write stdin
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(&stdin_bytes);
    }

    // Wait with timeout using wait_timeout crate or a manual approach.
    // Since we have no wait_timeout dep for now, we use thread::spawn + join with deadline.
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // Process exited; collect output
                let out = child.stdout.take();
                let err = child.stderr.take();
                let mut combined = Vec::new();
                if let Some(mut r) = out {
                    use std::io::Read;
                    let _ = r.read_to_end(&mut combined);
                }
                if let Some(mut r) = err {
                    use std::io::Read;
                    let _ = r.read_to_end(&mut combined);
                }
                let output = String::from_utf8_lossy(&combined).to_string();
                if status.success() {
                    return (output, None);
                } else {
                    let basename = path.file_name().unwrap_or_default().to_string_lossy();
                    return (
                        output,
                        Some(format!("applier {basename}: exit status {status}")),
                    );
                }
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    let basename = path.file_name().unwrap_or_default().to_string_lossy();
                    return (
                        String::new(),
                        Some(format!("applier {basename}: timed out after {timeout:?}")),
                    );
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                return (String::new(), Some(format!("wait: {e}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_prevents_path_traversal() {
        assert_eq!(sanitize_type("../../../etc/passwd"), "______etc_passwd");
        assert_eq!(sanitize_type("wifi/v1"), "wifi_v1");
        assert_eq!(sanitize_type("wifi.v2"), "wifi.v2"); // dots (non-double) are fine
    }

    #[test]
    fn skipped_when_no_script() {
        let dir = tempfile::TempDir::new().unwrap();
        let d = Dispatcher::new(dir.path().to_path_buf());
        let bundle = ProvisioningBundle {
            protocol_version: "1".into(),
            device_id: "test".into(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            modules: vec![Module {
                module_type: "wifi.v2".into(),
                payload: Some(serde_json::Map::new()),
                sealed: None,
                raw_payload: None,
            }],
        };
        let results = d.apply(&bundle);
        assert_eq!(results.len(), 1);
        assert!(results[0].skipped);
        assert!(!results[0].ok);
    }

    #[cfg(unix)]
    #[test]
    fn runs_script_with_stdin() {
        use std::io::Write;
        let dir = tempfile::TempDir::new().unwrap();
        let script = dir.path().join("wifi.v2.sh");
        // Script that reads stdin and echoes it
        std::fs::write(
            &script,
            b"#!/bin/sh\ncat\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();

        let d = Dispatcher::new(dir.path().to_path_buf());
        let mut payload = serde_json::Map::new();
        payload.insert("ssid".into(), serde_json::Value::String("TestNet".into()));
        let bundle = ProvisioningBundle {
            protocol_version: "1".into(),
            device_id: "test".into(),
            issued_at: chrono::Utc::now(),
            expires_at: None,
            modules: vec![Module {
                module_type: "wifi.v2".into(),
                payload: Some(payload),
                sealed: None,
                raw_payload: None,
            }],
        };
        let results = d.apply(&bundle);
        assert!(results[0].ok, "err: {:?}", results[0].error);
        let out = results[0].output.as_deref().unwrap_or("");
        assert!(out.contains("TestNet"), "output: {out}");
    }
}
