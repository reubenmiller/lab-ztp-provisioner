//! Tee logger that mirrors `log` macro output to both stderr (via the inner
//! env_logger) and a size-rotated file. Used so devices whose journald is
//! volatile (tmpfs-backed) can persist provisioning history across reboots
//! without letting the on-disk log grow unbounded.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{SecondsFormat, Utc};

/// Default rotation cap when `--log-file-max-bytes` is unset (1 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 1024 * 1024;
/// Default number of rotated backups kept on disk.
pub const DEFAULT_MAX_BACKUPS: u32 = 3;

/// A `Write`-compatible file that caps its on-disk size by rotating to
/// `<path>.1`, `<path>.2`, ... when the next write would exceed `max_bytes`.
///
/// Rotation happens *before* the write, so each individual write call lands
/// entirely in a single file. Callers that feed it one complete log record
/// per write (the normal case for `log`/`slog`) get clean per-record splits.
///
/// `max_bytes == 0` disables rotation; the file then grows unbounded.
/// `max_backups == 0` means no rotated copies — once full, the file is
/// truncated in place, bounding disk use to `max_bytes` flat.
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    max_backups: u32,
    file: File,
    size: u64,
}

impl RotatingFile {
    /// Open `path` (creating parent dirs as needed). The file's existing
    /// size is read and counted, so a restart picks up the rotation
    /// schedule rather than starting from zero again.
    pub fn open<P: AsRef<Path>>(
        path: P,
        max_bytes: u64,
        max_backups: u32,
    ) -> Result<Self, String> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create log directory {}: {e}", parent.display()))?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| format!("open log file {}: {e}", path.display()))?;
        let size = file
            .metadata()
            .map_err(|e| format!("stat log file {}: {e}", path.display()))?
            .len();
        Ok(Self {
            path,
            max_bytes,
            max_backups,
            file,
            size,
        })
    }

    fn rotate(&mut self) -> std::io::Result<()> {
        // Cascade renames *before* dropping the old handle. On Unix renaming
        // an open file is safe — the open FD continues to point at the same
        // inode, which is now reachable as <path>.1 — so the tail of the
        // file written immediately before rotation is preserved in the
        // backup, and the fresh file we open below starts clean.
        if self.max_backups == 0 {
            // In-place truncate: discard history, bound size at max_bytes.
            // Removing the directory entry is atomic; the open FD is
            // dropped below when self.file is reassigned.
            let _ = std::fs::remove_file(&self.path);
        } else {
            // Cascade: .N → discard, .(N-1) → .N, ..., .1 → .2, current → .1
            let oldest = backup_name(&self.path, self.max_backups);
            let _ = std::fs::remove_file(&oldest);
            for i in (1..self.max_backups).rev() {
                let from = backup_name(&self.path, i);
                let to = backup_name(&self.path, i + 1);
                if from.exists() {
                    std::fs::rename(&from, &to)?;
                }
            }
            std::fs::rename(&self.path, backup_name(&self.path, 1))?;
        }

        // Reassign self.file — the old handle drops here, releasing the FD
        // that pointed at the now-renamed (or unlinked) inode.
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

impl Write for RotatingFile {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.max_bytes > 0
            && self.size > 0
            && self.size.saturating_add(buf.len() as u64) > self.max_bytes
        {
            if let Err(e) = self.rotate() {
                // Falling back to writing into whatever handle we still have
                // is safer than dropping the line; surface the rotation
                // failure on stderr so it isn't completely silent.
                eprintln!("ztp-agent: log rotation failed: {e}");
            }
        }
        let n = self.file.write(buf)?;
        self.size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

fn backup_name(path: &Path, n: u32) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(format!(".{n}"));
    PathBuf::from(s)
}

/// Wraps an inner `log::Log` (typically `env_logger::Logger`) and additionally
/// appends each accepted record to a rotating file. The file format is plain
/// `<rfc3339 utc> <LEVEL> <target> - <message>` so it is grep-friendly and
/// has no external format dependency.
pub struct TeeLogger {
    inner: Box<dyn log::Log>,
    file: Mutex<RotatingFile>,
    level: log::LevelFilter,
}

impl TeeLogger {
    /// Create a TeeLogger by opening `path` for append. The parent directory
    /// is created if it does not already exist; failure is propagated so
    /// operators who asked for a log file see it surface clearly.
    pub fn open<P: AsRef<Path>>(
        inner: Box<dyn log::Log>,
        path: P,
        max_bytes: u64,
        max_backups: u32,
        level: log::LevelFilter,
    ) -> Result<Self, String> {
        let f = RotatingFile::open(path, max_bytes, max_backups)?;
        Ok(Self {
            inner,
            file: Mutex::new(f),
            level,
        })
    }
}

impl log::Log for TeeLogger {
    fn enabled(&self, m: &log::Metadata) -> bool {
        m.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        // Forward to the inner logger first so the user still sees stderr
        // output even if the file write fails.
        self.inner.log(record);

        let line = format!(
            "{} {} {} - {}\n",
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            record.level(),
            record.target(),
            record.args()
        );

        // A poisoned mutex here would mean a previous write panicked; recover
        // so subsequent log calls keep working rather than going silent.
        let mut guard = match self.file.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        // Single write call — POSIX guarantees atomicity for writes ≤ PIPE_BUF
        // (typically 4 KiB) on append-mode files, so concurrent agent log
        // calls do not interleave at the line level for normal records.
        let _ = guard.write_all(line.as_bytes());
    }

    fn flush(&self) {
        self.inner.flush();
        if let Ok(mut g) = self.file.lock() {
            let _ = g.flush();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_n(rf: &mut RotatingFile, line: &str, n: usize) {
        for _ in 0..n {
            rf.write_all(line.as_bytes()).expect("write");
        }
    }

    #[test]
    fn does_not_rotate_below_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        let mut rf = RotatingFile::open(&path, 1024, 3).unwrap();
        write_n(&mut rf, "small\n", 5);
        let one = backup_name(&path, 1);
        assert!(!one.exists(), "no rotation expected below threshold");
    }

    #[test]
    fn rotates_at_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        let mut rf = RotatingFile::open(&path, 32, 2).unwrap();
        write_n(&mut rf, "0123456789ABCDE\n", 4);
        assert!(backup_name(&path, 1).exists(), ".1 should exist");
        assert!(!backup_name(&path, 2).exists(), ".2 must not yet exist");
    }

    #[test]
    fn cascades_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        let mut rf = RotatingFile::open(&path, 16, 2).unwrap();
        write_n(&mut rf, "0123456789ABCDE\n", 8);
        assert!(backup_name(&path, 1).exists());
        assert!(backup_name(&path, 2).exists());
        assert!(
            !backup_name(&path, 3).exists(),
            ".3 must not exist when max_backups=2"
        );
    }

    #[test]
    fn disabled_when_max_bytes_zero() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        let mut rf = RotatingFile::open(&path, 0, 3).unwrap();
        write_n(&mut rf, "filler line content here\n", 1000);
        assert!(
            !backup_name(&path, 1).exists(),
            "rotation must not happen when max_bytes=0"
        );
    }

    #[test]
    fn truncates_in_place_when_no_backups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        let mut rf = RotatingFile::open(&path, 32, 0).unwrap();
        write_n(&mut rf, "0123456789ABCDE\n", 10);
        assert!(
            !backup_name(&path, 1).exists(),
            "no backup should exist when max_backups=0"
        );
        let size = std::fs::metadata(&path).unwrap().len();
        assert!(size <= 32 + 16, "size {size} exceeds cap+1 record");
    }

    #[test]
    fn reopen_counts_existing_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.log");
        std::fs::write(&path, b"xxxxxxxxxxxxxxxxxxxxxxxxx\n").unwrap();
        let mut rf = RotatingFile::open(&path, 32, 1).unwrap();
        rf.write_all(b"0123456789\n").unwrap();
        assert!(
            backup_name(&path, 1).exists(),
            "expected rotation triggered by inherited size"
        );
    }
}
