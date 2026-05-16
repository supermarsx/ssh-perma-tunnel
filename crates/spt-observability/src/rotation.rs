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
    use chrono::TimeZone;
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

    #[test]
    fn default_policy_is_daily_seven_retained() {
        let d = SizeRotationPolicy::default();
        assert_eq!(d.max_size_bytes, None);
        assert!(d.daily);
        assert_eq!(d.max_files, 7);
    }

    #[test]
    fn policy_derives_debug_clone_eq() {
        let a = SizeRotationPolicy {
            max_size_bytes: Some(1024),
            daily: false,
            max_files: 3,
        };
        let b = a;
        let c = a;
        assert_eq!(a, b);
        assert_eq!(b, c);
        let dbg = format!("{a:?}");
        assert!(dbg.contains("SizeRotationPolicy"));
    }

    #[test]
    fn day_key_is_monotonic_within_year() {
        let a = chrono::Local
            .with_ymd_and_hms(2026, 1, 1, 0, 0, 0)
            .single()
            .unwrap();
        let b = chrono::Local
            .with_ymd_and_hms(2026, 6, 15, 0, 0, 0)
            .single()
            .unwrap();
        assert!(day_key(a) < day_key(b));
    }

    #[test]
    fn needs_rotate_size_cap_zero_means_disabled() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(0),
            daily: false,
            max_files: 0,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "z.log", policy).unwrap();
        app.write_all(b"hello\n").unwrap();
        app.flush().unwrap();
        let rotated: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("z.log."))
            .collect();
        assert!(rotated.is_empty(), "cap=0 should disable size rotation");
    }

    #[test]
    fn max_files_zero_means_unlimited() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(256),
            daily: false,
            max_files: 0,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "u.log", policy).unwrap();
        let chunk = vec![b'u'; 256];
        for _ in 0..6 {
            app.write_all(&chunk).unwrap();
        }
        app.flush().unwrap();
        let rotated: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("u.log."))
            .collect();
        assert!(
            rotated.len() >= 3,
            "expected unbounded retention, got {rotated:?}"
        );
    }

    #[test]
    fn shared_ref_write_path() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(64),
            daily: false,
            max_files: 5,
        };
        let app = RotatingFileAppender::new(tmp.path(), "s.log", policy).unwrap();
        let mut r: &RotatingFileAppender = &app;
        let big = vec![b'a'; 200];
        r.write_all(&big).unwrap();
        r.flush().unwrap();
        let rotated: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("s.log."))
            .collect();
        assert!(
            !rotated.is_empty(),
            "expected rotation through &-write path, got {rotated:?}"
        );
    }

    #[test]
    fn opens_existing_file_and_tracks_size() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("k.log"), b"preexisting").unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(100),
            daily: false,
            max_files: 3,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "k.log", policy).unwrap();
        app.write_all(&[b'b'; 200]).unwrap();
        app.flush().unwrap();
        let rotated: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("k.log."))
            .collect();
        assert!(!rotated.is_empty(), "existing file should rotate");
    }

    #[test]
    fn rotated_filenames_use_date_stamp_pattern() {
        let tmp = tempdir().unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(64),
            daily: false,
            max_files: 5,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "p.log", policy).unwrap();
        app.write_all(&[b'.'; 100]).unwrap();
        app.flush().unwrap();
        let mut rotated: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != "p.log" && n.starts_with("p.log."))
            .collect();
        rotated.sort();
        assert!(!rotated.is_empty(), "expected at least one rotated file");
        for name in &rotated {
            let suffix = name.trim_start_matches("p.log.");
            let parts: Vec<&str> = suffix.split('-').collect();
            assert_eq!(
                parts.len(),
                4,
                "expected 4 dash-segments in {name:?}, got {parts:?}"
            );
            assert_eq!(parts[3].len(), 3, "expected 3-digit counter in {name:?}");
        }
    }

    #[test]
    fn prune_ignores_unrelated_files() {
        let tmp = tempdir().unwrap();
        std::fs::write(tmp.path().join("README"), b"hello").unwrap();
        let policy = SizeRotationPolicy {
            max_size_bytes: Some(64),
            daily: false,
            max_files: 1,
        };
        let mut app = RotatingFileAppender::new(tmp.path(), "w.log", policy).unwrap();
        for _ in 0..6 {
            app.write_all(&[b'w'; 100]).unwrap();
        }
        app.flush().unwrap();
        assert!(tmp.path().join("README").exists());
    }
}
