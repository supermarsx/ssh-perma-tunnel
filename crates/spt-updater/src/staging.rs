//! Staging-directory retention (`[updater.staging].keep_last`).
//!
//! Every download lands a fresh artifact (plus its `.minisig` sidecar) in the
//! staging directory. Before this module nothing ever removed them, so the
//! staging dir grew without bound — a slow disk leak (wire-observ finding 14).
//! [`prune`] keeps only the newest `keep_last` artifact archives and removes
//! the older ones together with their detached-signature sidecars.
//!
//! Files that are *not* per-build artifacts are deliberately preserved:
//! * dotfiles (e.g. the append-only install-history trail written by
//!   [`crate::audit`]),
//! * the shared, per-fetch-overwritten `SHA256SUMS` and
//!   `release-manifest.json`,
//! * sub-directories.

use std::path::Path;
use std::time::SystemTime;

use tracing::{debug, warn};

use crate::error::{UpdaterError, UpdaterResult};

/// The detached-signature sidecar suffix.
const SIG_SUFFIX: &str = ".minisig";

/// Names that are shared across builds (overwritten in place each fetch) and
/// must never be counted as a distinct "build" nor pruned.
fn is_shared_name(name: &str) -> bool {
    name.eq_ignore_ascii_case("SHA256SUMS")
        || name.ends_with("SHA256SUMS")
        || name == "release-manifest.json"
}

/// Prune the staging directory `dir` to at most `keep_last` artifact archives.
///
/// Returns the number of files removed. A `keep_last` of 0 is treated as 1 so
/// the just-staged artifact is never deleted. A missing directory is a no-op
/// (`Ok(0)`); other IO errors surface so a persistently un-prunable staging dir
/// is visible rather than silently leaking.
pub fn prune(dir: &Path, keep_last: u32) -> UpdaterResult<u32> {
    let keep = keep_last.max(1) as usize;

    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => {
            return Err(UpdaterError::Install(format!(
                "prune staging {}: {e}",
                dir.display()
            )));
        }
    };

    // Collect candidate artifact archives with their mtimes. Skip dirs,
    // dotfiles, signature sidecars, and shared/reused names.
    let mut archives: Vec<(SystemTime, std::path::PathBuf)> = Vec::new();
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };
        if !ft.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.starts_with('.') || name.ends_with(SIG_SUFFIX) || is_shared_name(name) {
            continue;
        }
        let mtime = entry
            .metadata()
            .and_then(|m| m.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        archives.push((mtime, path));
    }

    if archives.len() <= keep {
        return Ok(0);
    }

    // Newest first; delete everything past `keep`.
    archives.sort_by(|a, b| b.0.cmp(&a.0));
    let mut removed = 0u32;
    for (_, path) in archives.into_iter().skip(keep) {
        // Remove the artifact...
        if let Err(e) = std::fs::remove_file(&path) {
            warn!(
                target: "spt_updater::staging",
                artifact = %path.display(),
                error = %e,
                "failed to prune staged artifact"
            );
            continue;
        }
        removed += 1;
        // ...and its detached-signature sidecar, if any.
        let mut sig = path.clone().into_os_string();
        sig.push(SIG_SUFFIX);
        let sig = std::path::PathBuf::from(sig);
        if sig.exists() && std::fs::remove_file(&sig).is_ok() {
            removed += 1;
        }
    }

    if removed > 0 {
        debug!(
            target: "spt_updater::staging",
            dir = %dir.display(),
            keep_last = keep_last,
            removed,
            "pruned staged artifacts"
        );
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn write_with_mtime(dir: &Path, name: &str, body: &[u8], mtime: SystemTime) {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        let f = std::fs::File::options().write(true).open(&p).unwrap();
        f.set_modified(mtime).unwrap();
    }

    #[test]
    fn prunes_oldest_archives_and_their_sidecars() {
        let dir = tempfile::tempdir().unwrap();
        let base = SystemTime::UNIX_EPOCH;
        // 5 builds, increasing mtimes; each with a .minisig sidecar.
        for i in 0..5u64 {
            let t = base + Duration::from_secs(i * 100);
            let name = format!("spt-{i}-target.tar.gz");
            write_with_mtime(dir.path(), &name, b"bin", t);
            write_with_mtime(dir.path(), &format!("{name}.minisig"), b"sig", t);
        }
        // A dotfile history trail + a shared SHA256SUMS must be preserved.
        write_with_mtime(dir.path(), ".spt-update-history.jsonl", b"{}", base);
        write_with_mtime(dir.path(), "SHA256SUMS", b"sums", base);

        let removed = prune(dir.path(), 2).unwrap();
        // 3 oldest archives + their 3 sidecars removed.
        assert_eq!(removed, 6);

        // Newest two builds survive.
        assert!(dir.path().join("spt-4-target.tar.gz").exists());
        assert!(dir.path().join("spt-3-target.tar.gz").exists());
        assert!(dir.path().join("spt-4-target.tar.gz.minisig").exists());
        // Oldest removed.
        assert!(!dir.path().join("spt-0-target.tar.gz").exists());
        assert!(!dir.path().join("spt-0-target.tar.gz.minisig").exists());
        // Preserved specials.
        assert!(dir.path().join(".spt-update-history.jsonl").exists());
        assert!(dir.path().join("SHA256SUMS").exists());
    }

    #[test]
    fn keep_last_zero_keeps_the_newest_one() {
        let dir = tempfile::tempdir().unwrap();
        let base = SystemTime::UNIX_EPOCH;
        for i in 0..3u64 {
            write_with_mtime(
                dir.path(),
                &format!("spt-{i}.tar.gz"),
                b"x",
                base + Duration::from_secs(i * 10),
            );
        }
        let removed = prune(dir.path(), 0).unwrap();
        assert_eq!(removed, 2);
        assert!(dir.path().join("spt-2.tar.gz").exists());
    }

    #[test]
    fn under_limit_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        write_with_mtime(dir.path(), "spt-a.tar.gz", b"x", SystemTime::UNIX_EPOCH);
        assert_eq!(prune(dir.path(), 3).unwrap(), 0);
        assert!(dir.path().join("spt-a.tar.gz").exists());
    }

    #[test]
    fn missing_dir_is_noop() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope");
        assert_eq!(prune(&missing, 3).unwrap(), 0);
    }
}
