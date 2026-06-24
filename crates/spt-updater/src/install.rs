//! Platform-specific atomic-swap of the running spt binary.
//!
//! The caller is responsible for **verifying** `new_binary` (see
//! [`crate::verify`]) before invoking [`install_atomic`]. This module only
//! performs the swap.
//!
//! # Unix
//!
//! POSIX `rename(2)` is atomic within a filesystem and is permitted over a
//! currently-running executable — the kernel keeps the old inode alive for
//! the running process via its open text mapping, and unlinking the old
//! directory entry is harmless. We therefore:
//!
//! 1. copy `new_binary` to a temp file **in the same directory** as the
//!    target (so the final `rename` stays on one filesystem),
//! 2. copy the target's mode bits onto the temp file (preserve perms),
//! 3. `fsync` the temp file and its parent directory (durability), and
//! 4. `rename` the temp file over the target — a single atomic step.
//!
//! # Windows
//!
//! A running `.exe` cannot be overwritten or deleted, so an in-place rename
//! over the live target fails with `ERROR_ACCESS_DENIED`. We use the
//! standard rename-self dance with **std-only** primitives (no `windows` /
//! `windows-sys` dependency — the crate must not grow `Cargo.lock`):
//!
//! 1. move the running target aside to a `<target>.old` sidecar
//!    (`rename` of a *running* image to a sibling path **is** allowed on
//!    NTFS — the file is in use but not being deleted),
//! 2. move the new binary into the now-free target path,
//! 3. best-effort delete the `.old` sidecar (fails while the old process is
//!    still running — that is expected; it is cleaned on the next install
//!    or by [`cleanup_sidecars`]).
//!
//! If step 2 fails we roll the `.old` sidecar back into place so we never
//! leave the target missing.

use std::path::{Path, PathBuf};

#[cfg(any(unix, windows))]
use tracing::debug;
#[cfg(windows)]
use tracing::warn;

use crate::error::{UpdaterError, UpdaterResult};

/// Atomically replace the running binary with `new_binary`. The caller is
/// responsible for verifying `new_binary` before invoking this.
///
/// `target` is the path to replace; defaults to the current executable via
/// [`install_over_current`] when the caller doesn't have an explicit path.
pub async fn install_atomic(new_binary: &Path) -> UpdaterResult<()> {
    let target = std::env::current_exe()
        .map_err(|e| UpdaterError::Install(format!("resolve current_exe: {e}")))?;
    install_over(new_binary, &target).await
}

/// Replace `target` with `new_binary` atomically. Exposed so tests (and a
/// future caller with an explicit install path) can swap a non-running file.
pub async fn install_over(new_binary: &Path, target: &Path) -> UpdaterResult<()> {
    if !new_binary.exists() {
        return Err(UpdaterError::Install(format!(
            "new binary does not exist: {}",
            new_binary.display()
        )));
    }
    let new_binary = new_binary.to_path_buf();
    let target = target.to_path_buf();
    // The swap is blocking filesystem I/O; keep it off the async reactor.
    tokio::task::spawn_blocking(move || swap(&new_binary, &target))
        .await
        .map_err(|e| UpdaterError::Install(format!("join swap task: {e}")))?
}

/// The platform-specific atomic swap, run on a blocking thread.
#[cfg(unix)]
fn swap(new_binary: &Path, target: &Path) -> UpdaterResult<()> {
    use std::os::unix::fs::PermissionsExt;

    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let tmp = temp_sibling(target);

    // 1. Copy the new binary to a sibling temp file (same filesystem).
    std::fs::copy(new_binary, &tmp)
        .map_err(|e| UpdaterError::Install(format!("copy to {}: {e}", tmp.display())))?;

    // 2. Preserve the target's mode if it exists; else make it executable.
    let mode = std::fs::metadata(target)
        .map(|m| m.permissions().mode())
        .unwrap_or(0o755);
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        UpdaterError::Install(format!("set perms on {}: {e}", tmp.display()))
    })?;

    // 3. fsync the temp file + parent dir for durability across crash.
    if let Err(e) = fsync_path(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // 4. Atomic rename over the (possibly running) target.
    if let Err(e) = std::fs::rename(&tmp, target) {
        let _ = std::fs::remove_file(&tmp);
        return Err(UpdaterError::Install(format!(
            "rename {} -> {}: {e}",
            tmp.display(),
            target.display()
        )));
    }
    // Best-effort durability of the directory entry change.
    let _ = fsync_dir(dir);
    debug!(
        target: "spt_updater::install",
        target = %target.display(),
        "atomic rename swap complete"
    );
    Ok(())
}

/// The platform-specific atomic swap, run on a blocking thread.
#[cfg(windows)]
fn swap(new_binary: &Path, target: &Path) -> UpdaterResult<()> {
    let old = sidecar(target);

    // Pre-clean any stale sidecar from a previous install (best-effort —
    // the previous process may still hold it).
    let _ = std::fs::remove_file(&old);

    let target_exists = target.exists();

    // 1. Move the running/old target aside. `rename` of an in-use image to
    //    a sibling path is permitted on NTFS.
    if target_exists {
        std::fs::rename(target, &old).map_err(|e| {
            UpdaterError::Install(format!(
                "move running target {} -> {}: {e}",
                target.display(),
                old.display()
            ))
        })?;
    }

    // 2. Move the new binary into the now-free target path. Use copy+remove
    //    rather than rename so it works across filesystems (the staging dir
    //    may be on a different volume than the install path).
    if let Err(e) = std::fs::copy(new_binary, target) {
        // Roll back: restore the old target so we never leave it missing.
        if target_exists {
            let _ = std::fs::rename(&old, target);
        }
        return Err(UpdaterError::Install(format!(
            "install new binary to {}: {e}",
            target.display()
        )));
    }

    // 3. Best-effort delete the sidecar. While the old process is still
    //    running this fails with sharing-violation; that is expected and
    //    harmless — it is reaped on the next install via the pre-clean above.
    if let Err(e) = std::fs::remove_file(&old) {
        warn!(
            target: "spt_updater::install",
            sidecar = %old.display(),
            error = %e,
            "could not remove .old sidecar (old process still running?); \
             it will be cleaned on the next install"
        );
    }
    debug!(
        target: "spt_updater::install",
        target = %target.display(),
        "rename-self swap complete"
    );
    Ok(())
}

/// Fallback for non-unix, non-windows targets: a plain rename/copy. No
/// platform guarantees a running-exe swap here, so this is best-effort.
#[cfg(not(any(unix, windows)))]
fn swap(new_binary: &Path, target: &Path) -> UpdaterResult<()> {
    std::fs::copy(new_binary, target).map_err(|e| {
        UpdaterError::Install(format!(
            "copy {} -> {}: {e}",
            new_binary.display(),
            target.display()
        ))
    })?;
    Ok(())
}

/// Compute a unique temp-sibling path next to `target` (same directory).
/// Only the unix swap uses this (the Windows path renames the target aside
/// directly); also exercised by the cross-platform unit tests.
#[cfg(any(unix, test))]
fn temp_sibling(target: &Path) -> PathBuf {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let stem = target
        .file_name()
        .map_or_else(|| "spt".into(), |f| f.to_string_lossy().into_owned());
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    dir.join(format!(".{stem}.new.{pid}.{nanos}"))
}

/// The `<target>.old` sidecar path used by the Windows swap.
#[cfg(any(windows, test))]
fn sidecar(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_os_string();
    s.push(".old");
    PathBuf::from(s)
}

/// Best-effort cleanup of any leftover `<binary>.old` sidecar next to
/// `target`. Safe to call before/after install; ignores absence.
pub fn cleanup_sidecars(target: &Path) {
    #[cfg(any(windows, test))]
    {
        let old = sidecar(target);
        if old.exists() {
            let _ = std::fs::remove_file(&old);
        }
    }
    #[cfg(not(any(windows, test)))]
    {
        let _ = target;
    }
}

/// fsync a regular file at `path`.
#[cfg(unix)]
fn fsync_path(path: &Path) -> UpdaterResult<()> {
    let f = std::fs::File::open(path)
        .map_err(|e| UpdaterError::Install(format!("open for fsync {}: {e}", path.display())))?;
    f.sync_all()
        .map_err(|e| UpdaterError::Install(format!("fsync {}: {e}", path.display())))
}

/// fsync a directory so the rename is durable.
#[cfg(unix)]
fn fsync_dir(dir: &Path) -> UpdaterResult<()> {
    let f = std::fs::File::open(dir)
        .map_err(|e| UpdaterError::Install(format!("open dir for fsync {}: {e}", dir.display())))?;
    f.sync_all()
        .map_err(|e| UpdaterError::Install(format!("fsync dir {}: {e}", dir.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write(dir: &Path, name: &str, body: &[u8]) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[tokio::test]
    async fn install_over_replaces_target_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let target = write(tmp.path(), "spt-bin", b"OLD CONTENTS");
        let new = write(tmp.path(), "staged", b"NEW CONTENTS v2");

        install_over(&new, &target).await.unwrap();

        let got = std::fs::read(&target).unwrap();
        assert_eq!(got, b"NEW CONTENTS v2");
        // The temp sibling must not linger.
        let leftovers: Vec<_> = std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".new."))
            .collect();
        assert!(leftovers.is_empty(), "temp sibling leaked: {leftovers:?}");
    }

    #[tokio::test]
    async fn install_over_creates_target_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("spt-bin");
        let new = write(tmp.path(), "staged", b"FRESH");
        install_over(&new, &target).await.unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"FRESH");
    }

    #[tokio::test]
    async fn install_over_missing_new_binary_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let target = write(tmp.path(), "spt-bin", b"x");
        let missing = tmp.path().join("does-not-exist");
        let err = install_over(&missing, &target).await.unwrap_err();
        assert_eq!(err.code(), "updater_install");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn install_over_preserves_executable_mode() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let target = write(tmp.path(), "spt-bin", b"OLD");
        // Mark the target executable + setuid-ish bits to verify preservation.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        let new = write(tmp.path(), "staged", b"NEW");
        // Staged file deliberately not executable; swap must restore 0o755.
        std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o644)).unwrap();

        install_over(&new, &target).await.unwrap();

        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755, "executable mode not preserved");
        assert_eq!(std::fs::read(&target).unwrap(), b"NEW");
    }

    #[test]
    fn temp_sibling_is_in_same_dir() {
        let t = Path::new("/opt/spt/bin/spt");
        let s = temp_sibling(t);
        assert_eq!(s.parent(), Some(Path::new("/opt/spt/bin")));
        assert!(s
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".spt.new."));
    }

    #[test]
    fn cleanup_sidecars_removes_old() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("spt-bin");
        let old = sidecar(&target);
        std::fs::write(&old, b"stale").unwrap();
        assert!(old.exists());
        cleanup_sidecars(&target);
        assert!(!old.exists());
    }
}
