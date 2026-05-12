//! Size + daily file rotation appender.
//!
//! `tracing-appender` 0.2 ships only time-based rotation (hourly/daily/never)
//! and exposes no clock-injection point. This module supplies a simple
//! synchronous appender that supports a **compound policy**:
//!
//! * Daily rotation by wall-clock day boundary.
//! * Size rotation when the active file would exceed `max_size_bytes`.
//! * Either, both, or neither — config-driven.
//!
//! The active file lives at `<dir>/<prefix>`; rotated files are renamed to
//! `<dir>/<prefix>.YYYY-MM-DD-NNN` where `NNN` is a per-day counter
//! starting at `001`. Rename is atomic on POSIX and best-effort atomic on
//! Windows (`std::fs::rename` swap). Old files are pruned to `max_files`.
//!
//! The struct itself is `std::io::Write`; pair it with
//! `tracing_appender::non_blocking` to avoid blocking the formatter.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;

use chrono::{DateTime, Datelike, Local};
use parking_lot::Mutex;

/// Compound rotation policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeRotationPolicy {
    /// If `Some(n)`, rotate when the active file would exceed `n` bytes.
    pub max_size_bytes: Option<u64>,
    /// If `true`, rotate at local-midnight.
    pub daily: bool,
    /// Maximum retained rotated files. `0` = unlimited.
    pub max_files: u32,
}

impl Default for SizeRotationPolicy {
    fn default() -> Self {
        Self {
            max_size_bytes: None,
            daily: true,
            max_files: 7,
        }
    }
}

/// Rotating appender supporting size + daily compound policy.
pub struct RotatingFileAppender {
    state: Mutex<State>,
    dir: PathBuf,
    prefix: String,
    policy: SizeRotationPolicy,
}

struct State {
    file: File,
    cur_size: u64,
    cur_day: i32, // day-of-year + year*1000 monotonic key
}

impl RotatingFileAppender {
    /// Create or open an appender at `dir/prefix` with `policy`.
    pub fn new(
        dir: impl Into<PathBuf>,
        prefix: impl Into<String>,
        policy: SizeRotationPolicy,
    ) -> io::Result<Self> {
        let dir = dir.into();
        let prefix = prefix.into();
        fs::create_dir_all(&dir)?;
        let path = dir.join(&prefix);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let cur_size = file.metadata()?.len();
        let cur_day = day_key(Local::now());
        Ok(Self {
            state: Mutex::new(State {
                file,
                cur_size,
                cur_day,
            }),
            dir,
            prefix,
            policy,
        })
    }

    fn rotate_locked(&self, st: &mut State) -> io::Result<()> {
        // Flush the current file.
        st.file.flush().ok();
        // Decide a unique rotated name.
        let now = Local::now();
        let stamp = format!("{:04}-{:02}-{:02}", now.year(), now.month(), now.day());
        let mut counter: u32 = 1;
        let rotated = loop {
            let name = format!("{}.{}-{:03}", self.prefix, stamp, counter);
            let candidate = self.dir.join(&name);
            if !candidate.exists() {
                break candidate;
            }
            counter = counter.checked_add(1).unwrap_or(u32::MAX);
            if counter == u32::MAX {
                break self
                    .dir
                    .join(format!("{}.{}-{}", self.prefix, stamp, "max"));
            }
        };
        let active = self.dir.join(&self.prefix);
        // Best-effort: drop file before rename on Windows.
        // We can't drop &mut without replacing; instead, rename then reopen.
        match fs::rename(&active, &rotated) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // On Windows the open handle may block rename; close, rename, reopen.
                // Replace file with a placeholder via take.
                drop(std::mem::replace(
                    &mut st.file,
                    OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(self.dir.join(".__spt_rotate_placeholder__"))?,
                ));
                fs::rename(&active, &rotated)?;
                // Remove placeholder.
                let _ = fs::remove_file(self.dir.join(".__spt_rotate_placeholder__"));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // Active file missing — treat as already-rotated.
            }
            Err(e) => return Err(e),
        }

        // Reopen a fresh active file.
        let new_file = OpenOptions::new().create(true).append(true).open(active)?;
        st.file = new_file;
        st.cur_size = 0;
        st.cur_day = day_key(now);

        // Prune oldest beyond max_files.
        if self.policy.max_files > 0 {
            self.prune();
        }
        Ok(())
    }

    fn prune(&self) {
        let Ok(rd) = fs::read_dir(&self.dir) else {
            return;
        };
        let prefix_dot = format!("{}.", self.prefix);
        let mut entries: Vec<(PathBuf, std::time::SystemTime)> = rd
            .filter_map(std::result::Result::ok)
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with(&prefix_dot) {
                    let mtime = e.metadata().ok().and_then(|m| m.modified().ok())?;
                    Some((e.path(), mtime))
                } else {
                    None
                }
            })
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        let max = self.policy.max_files as usize;
        if entries.len() > max {
            for (p, _) in entries.iter().take(entries.len() - max) {
                let _ = fs::remove_file(p);
            }
        }
    }
}

fn day_key(t: DateTime<Local>) -> i32 {
    t.year() * 1000 + t.ordinal() as i32
}

impl Write for RotatingFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Single writer path used by tests / direct callers.
        let mut st = self.state.lock();
        if needs_rotate(&self.policy, &st, buf.len() as u64) {
            self.rotate_locked(&mut st)?;
        }
        let n = st.file.write(buf)?;
        st.cur_size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.lock().file.flush()
    }
}

// Allow shared (`&self`) writes for compatibility with `MakeWriter` use.
impl Write for &RotatingFileAppender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut st = self.state.lock();
        if needs_rotate(&self.policy, &st, buf.len() as u64) {
            self.rotate_locked(&mut st)?;
        }
        let n = st.file.write(buf)?;
        st.cur_size += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.state.lock().file.flush()
    }
}

fn needs_rotate(p: &SizeRotationPolicy, st: &State, incoming: u64) -> bool {
    if p.daily && day_key(Local::now()) != st.cur_day {
        return true;
    }
    if let Some(cap) = p.max_size_bytes {
        if cap > 0 && st.cur_size + incoming > cap {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn writes_and_rotates_on_size() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(100 * 1024),
            daily: false,
            max_files: 5,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "spt.log", policy).unwrap();
        // Write ~250KiB in 1KiB chunks → expect 2 rotated files + active
        // (cap=100KiB triggers rotation on byte 102_401).
        let chunk = vec![b'x'; 1024];
        for _ in 0..250 {
            app.write_all(&chunk).unwrap();
        }
        app.flush().unwrap();
        let entries: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("spt.log"))
            .collect();
        assert!(
            entries.len() >= 3,
            "expected at least active+2 rotations, got {entries:?}"
        );
    }

    #[test]
    fn prune_keeps_max_files() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(1024),
            daily: false,
            max_files: 2,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "x.log", policy).unwrap();
        let chunk = vec![b'x'; 512];
        // 10 writes * 512B = 5KiB → at least 4 rotations triggered; pruned to 2.
        for _ in 0..10 {
            app.write_all(&chunk).unwrap();
        }
        app.flush().unwrap();
        let rotated: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("x.log."))
            .collect();
        assert!(
            rotated.len() <= 2,
            "expected pruned to <=2, got {rotated:?}"
        );
    }

    #[test]
    fn no_rotate_under_cap() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(1_000_000),
            daily: false,
            max_files: 5,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "y.log", policy).unwrap();
        app.write_all(b"hello world\n").unwrap();
        app.flush().unwrap();
        let rotated: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("y.log."))
            .collect();
        assert!(rotated.is_empty(), "no rotations expected, got {rotated:?}");
    }
}
