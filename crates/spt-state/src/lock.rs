//! Cross-platform process lock for the state directory.
//!
//! Acquires an exclusive `fs4` lock on `<dir>/spt.lock` and writes the current
//! PID to `<dir>/spt.pid`. A second acquisition by another process — or another
//! `File` handle within the same process — fails with [`Error::StateLockFailed`]
//! whose exit code is [`spt_core::ExitCode::StateLockFailed`] (16).
//!
//! Drop semantics:
//!
//! * The exclusive lock is released when [`StateLock`] is dropped (the `File`
//!   handle is closed).
//! * `spt.pid` is best-effort removed on drop.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

// t9-Bump: fs4 1.x moved the sync `FileExt` trait to the crate root,
// removed `fs4::fs_std`, renamed `try_lock_exclusive` → `try_lock`, and
// switched the try-lock error type from `io::Error` to a dedicated
// `TryLockError` enum (`WouldBlock` for contention, `Error(io::Error)`
// for real I/O failures).
use fs4::{FileExt, TryLockError};
use spt_core::{Error, Result};

use crate::atomic;
use crate::paths;

/// An acquired state-directory lock.
///
/// While alive, the underlying file is held with an exclusive `fs4` lock so
/// no other `spt` process — or other `File` handle — can lock the same
/// directory.
#[derive(Debug)]
pub struct StateLock {
    file: Option<File>,
    lock_path: PathBuf,
    pid_path: PathBuf,
}

impl StateLock {
    /// Acquire the exclusive lock for the given state directory.
    ///
    /// The directory must already exist (call [`crate::resolve_state_dir`]
    /// first). Returns [`Error::StateLockFailed`] on contention or I/O error.
    pub fn acquire(dir: &Path) -> Result<Self> {
        let lock_path = paths::lock_path(dir);
        let pid_path = paths::pid_path(dir);

        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| Error::StateLockFailed {
                path: lock_path.clone(),
                reason: format!("open lock file: {e}"),
            })?;

        match FileExt::try_lock(&file) {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(Error::StateLockFailed {
                    path: lock_path,
                    reason: "another spt instance is already running".into(),
                });
            }
            Err(TryLockError::Error(e)) if is_contention_error(&e) => {
                return Err(Error::StateLockFailed {
                    path: lock_path,
                    reason: "another spt instance is already running".into(),
                });
            }
            Err(TryLockError::Error(e)) => {
                return Err(Error::StateLockFailed {
                    path: lock_path,
                    reason: format!("file lock failed: {e}"),
                });
            }
        }

        // Write PID after lock acquisition. If this fails, surface as
        // StateLockFailed and release the lock via Drop.
        let pid = std::process::id().to_string();
        atomic::write_atomic_string(&pid_path, &pid)?;

        Ok(Self {
            file: Some(file),
            lock_path,
            pid_path,
        })
    }

    /// Path of the underlying lock file.
    #[must_use]
    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }

    /// Path of the PID file written under this lock.
    #[must_use]
    pub fn pid_path(&self) -> &Path {
        &self.pid_path
    }
}

/// Classify an `io::Error` from `try_lock_exclusive` as lock contention.
///
/// On Unix, `flock`-style failures surface as `WouldBlock`. On Windows
/// `LockFileEx` returns `ERROR_LOCK_VIOLATION` (os error 33) or
/// `ERROR_SHARING_VIOLATION` (os error 32), which Rust may map either to
/// `PermissionDenied` or to a generic `Other`. We treat any of these as
/// contention so the caller surfaces "another instance running" rather than
/// a low-level message.
fn is_contention_error(e: &io::Error) -> bool {
    if matches!(
        e.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::PermissionDenied
    ) {
        return true;
    }
    matches!(e.raw_os_error(), Some(11 | 32 | 33 | 35))
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // Best-effort: remove pid file then unlock+drop file.
        let _ = std::fs::remove_file(&self.pid_path);
        if let Some(f) = self.file.take() {
            let _ = FileExt::unlock(&f);
            drop(f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_core::ExitCode;
    use tempfile::tempdir;

    #[test]
    fn acquire_writes_pid_and_releases_on_drop() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path();

        let lock = StateLock::acquire(dir).unwrap();
        let pid_str = std::fs::read_to_string(lock.pid_path()).unwrap();
        assert_eq!(pid_str.trim(), std::process::id().to_string());
        let lock_file = lock.lock_path().to_path_buf();
        assert!(lock_file.is_file());

        drop(lock);
        // PID removed on drop; lock file may remain (it's the lock object itself).
        assert!(!paths::pid_path(dir).exists());

        // After drop, a new acquire works.
        let lock2 = StateLock::acquire(dir).unwrap();
        drop(lock2);
    }

    #[test]
    fn second_acquire_fails_with_state_lock_failed() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path();

        let _held = StateLock::acquire(dir).unwrap();
        let err = StateLock::acquire(dir).unwrap_err();
        assert_eq!(err.exit_code(), ExitCode::StateLockFailed);
        match &err {
            Error::StateLockFailed { reason, .. } => {
                assert!(reason.contains("already running"), "{reason}");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn lock_paths_are_under_dir() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path();
        let lock = StateLock::acquire(dir).unwrap();
        assert!(lock.lock_path().starts_with(dir));
        assert!(lock.pid_path().starts_with(dir));
        assert_eq!(lock.lock_path().file_name().unwrap(), "spt.lock");
        assert_eq!(lock.pid_path().file_name().unwrap(), "spt.pid");
    }

    #[test]
    fn drop_releases_lock_and_removes_pid_file() {
        let tmp = tempdir().unwrap();
        let dir = tmp.path();
        let lock = StateLock::acquire(dir).unwrap();
        let pid_path = lock.pid_path().to_path_buf();
        assert!(pid_path.exists());
        drop(lock);
        assert!(!pid_path.exists());
        // Lock released — a fresh acquire on the same dir must succeed.
        let l2 = StateLock::acquire(dir).unwrap();
        drop(l2);
    }

    #[test]
    fn is_contention_error_classifies_kinds() {
        let e_block = io::Error::from(io::ErrorKind::WouldBlock);
        assert!(is_contention_error(&e_block));
        let e_perm = io::Error::from(io::ErrorKind::PermissionDenied);
        assert!(is_contention_error(&e_perm));
        let e_not_found = io::Error::from(io::ErrorKind::NotFound);
        assert!(!is_contention_error(&e_not_found));
    }

    #[test]
    fn is_contention_error_recognises_raw_os_codes() {
        for code in [11, 32, 33, 35] {
            let e = io::Error::from_raw_os_error(code);
            assert!(
                is_contention_error(&e),
                "expected contention for raw os error {code}"
            );
        }
    }

    #[test]
    fn lock_is_debug() {
        let tmp = tempdir().unwrap();
        let lock = StateLock::acquire(tmp.path()).unwrap();
        let s = format!("{lock:?}");
        assert!(s.contains("StateLock"));
    }
}
