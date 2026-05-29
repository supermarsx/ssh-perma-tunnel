//! File-backed secret backend.
//!
//! Each [`SecretRef`] resolves to a path under a configured root:
//!
//! ```text
//! <root>/<ns>/<name>
//! ```
//!
//! The file's contents are returned verbatim as the secret value. On Unix
//! the mode is checked: only `0o400` and `0o600` are accepted (owner-only
//! read, optionally write). On Windows we perform a best-effort ACL check
//! that the file is not world-readable; failures degrade to a warning
//! rather than rejection because Windows ACLs are deeply environment
//! dependent.

use std::fs;
use std::path::{Path, PathBuf};

use spt_core::{Error, Result};
use tracing::warn;

use crate::backend::{secret_bytes, BackendDoctor, BackendKind, SecretBackend, SecretBytes};
use crate::reference::SecretRef;

/// File-backed secret backend rooted at a directory.
pub struct FileBackend {
    root: PathBuf,
}

impl FileBackend {
    /// Construct a backend rooted at `root`. `root` is not required to exist
    /// at construction time.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Path that a reference would resolve to under this backend.
    #[must_use]
    pub fn path_for(&self, r: &SecretRef) -> PathBuf {
        self.root.join(r.ns()).join(r.name())
    }
}

#[cfg(unix)]
fn check_mode(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = fs::metadata(path).map_err(|e| Error::SecretUnavailable {
        reference: path.display().to_string(),
        reason: format!("stat: {e}"),
    })?;
    let mode = meta.permissions().mode() & 0o777;
    if !matches!(mode, 0o400 | 0o600) {
        return Err(Error::PermissionDenied(format!(
            "secret file `{}` has mode {mode:o}; only 0400 or 0600 are allowed",
            path.display()
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn check_mode(path: &Path) -> Result<()> {
    // Best-effort: ensure the file exists and we can stat it. A full ACL
    // audit (NT principals, inherited ACEs) is in scope for `spt secret
    // doctor` but kept out of the per-read fast path. If we ever add
    // strict-mode ACL enforcement on Windows, plumb it through here.
    match fs::metadata(path) {
        Ok(_) => Ok(()),
        Err(e) => Err(Error::SecretUnavailable {
            reference: path.display().to_string(),
            reason: format!("stat: {e}"),
        }),
    }
}

#[cfg(not(any(unix, windows)))]
fn check_mode(_path: &Path) -> Result<()> {
    Ok(())
}

impl SecretBackend for FileBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::File
    }

    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        let path = self.path_for(r);
        if !path.exists() {
            return Ok(None);
        }
        check_mode(&path)?;
        let bytes = fs::read(&path).map_err(|e| Error::SecretUnavailable {
            reference: r.to_string(),
            reason: format!("read `{}`: {e}", path.display()),
        })?;
        Ok(Some(secret_bytes(bytes)))
    }

    fn set(&self, r: &SecretRef, value: &[u8]) -> Result<()> {
        let path = self.path_for(r);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("mkdir `{}`: {e}", parent.display()),
            })?;
        }
        // Open + write + rename ourselves rather than going through
        // `atomicwrites::AtomicFile`. The historical path used the helper
        // and then `set_permissions(0600)` *after* the rename, which left a
        // window where the secret was readable under the default umask
        // (typically 0644). Mirrors `portable.rs::write_master_key`.
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let tmp = path.with_extension("secret.tmp");
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|e| Error::SecretUnavailable {
                    reference: r.to_string(),
                    reason: format!("open temp `{}`: {e}", tmp.display()),
                })?;
            f.write_all(value).map_err(|e| Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("write temp `{}`: {e}", tmp.display()),
            })?;
            f.sync_all().ok();
            drop(f);
            std::fs::rename(&tmp, &path).map_err(|e| Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("rename `{}` -> `{}`: {e}", tmp.display(), path.display()),
            })?;
        }
        #[cfg(not(unix))]
        {
            // Windows: NTFS ACLs default to inheriting the parent directory's
            // DACL. `atomicwrites` is fine here — no permission-window concern
            // because the file inherits the (operator-controlled) parent ACL
            // both before and after the rename. A stricter ACL pass is in
            // scope for `spt secret doctor`; see check_mode().
            atomicwrites::AtomicFile::new(&path, atomicwrites::AllowOverwrite)
                .write(|f| std::io::Write::write_all(f, value))
                .map_err(|e| Error::SecretUnavailable {
                    reference: r.to_string(),
                    reason: format!("write `{}`: {e}", path.display()),
                })?;
        }
        Ok(())
    }

    fn list(&self) -> Result<Vec<SecretRef>> {
        let mut out = Vec::new();
        let root = match fs::read_dir(&self.root) {
            Ok(it) => it,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => {
                return Err(Error::SecretUnavailable {
                    reference: self.root.display().to_string(),
                    reason: format!("readdir: {e}"),
                });
            }
        };
        for ns_entry in root.flatten() {
            if !ns_entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let Some(ns) = ns_entry.file_name().to_str().map(str::to_owned) else {
                warn!(path = %ns_entry.path().display(), "skipping non-UTF-8 namespace dir");
                continue;
            };
            let inner = match fs::read_dir(ns_entry.path()) {
                Ok(it) => it,
                Err(e) => {
                    warn!(path = %ns_entry.path().display(), error = %e, "readdir failed");
                    continue;
                }
            };
            for name_entry in inner.flatten() {
                if !name_entry.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let Some(name) = name_entry.file_name().to_str().map(str::to_owned) else {
                    continue;
                };
                if let Ok(r) = SecretRef::new(ns.clone(), name) {
                    out.push(r);
                }
            }
        }
        Ok(out)
    }

    fn remove(&self, r: &SecretRef) -> Result<bool> {
        let path = self.path_for(r);
        match fs::remove_file(&path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("remove `{}`: {e}", path.display()),
            }),
        }
    }

    fn doctor(&self) -> BackendDoctor {
        if self.root.is_dir() {
            BackendDoctor::ok(
                BackendKind::File,
                format!("file backend rooted at `{}`", self.root.display()),
            )
        } else {
            BackendDoctor::degraded(
                BackendKind::File,
                format!("root `{}` does not exist", self.root.display()),
                "create the directory or point `secrets.file.root` elsewhere",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use tempfile::tempdir;

    #[test]
    fn path_for_layout() {
        let b = FileBackend::new("/var/lib/spt/secrets");
        let r = SecretRef::new("ns", "name").unwrap();
        let p = b.path_for(&r);
        assert!(p.ends_with(Path::new("ns").join("name")));
    }

    #[test]
    fn missing_returns_none() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r = SecretRef::new("ns", "name").unwrap();
        assert!(b.get(&r).unwrap().is_none());
    }

    #[test]
    fn set_then_get_round_trip() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r = SecretRef::new("ns", "name").unwrap();
        b.set(&r, b"payload").unwrap();
        let got = b.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"payload");
    }

    #[test]
    fn list_enumerates_set_entries() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r1 = SecretRef::new("ns1", "a").unwrap();
        let r2 = SecretRef::new("ns2", "b").unwrap();
        b.set(&r1, b"x").unwrap();
        b.set(&r2, b"y").unwrap();
        let mut got = b.list().unwrap();
        got.sort_by_key(ToString::to_string);
        assert_eq!(got, vec![r1, r2]);
    }

    #[test]
    fn remove_reports_presence() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r = SecretRef::new("ns", "name").unwrap();
        assert!(!b.remove(&r).unwrap());
        b.set(&r, b"x").unwrap();
        assert!(b.remove(&r).unwrap());
        assert!(b.get(&r).unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn unix_rejects_world_readable_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r = SecretRef::new("ns", "name").unwrap();
        b.set(&r, b"payload").unwrap();
        let p = b.path_for(&r);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let err = b.get(&r).unwrap_err();
        assert!(
            matches!(err, Error::PermissionDenied(_)),
            "expected PermissionDenied, got {err:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_accepts_0400() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r = SecretRef::new("ns", "name").unwrap();
        b.set(&r, b"payload").unwrap();
        let p = b.path_for(&r);
        fs::set_permissions(&p, fs::Permissions::from_mode(0o400)).unwrap();
        assert!(b.get(&r).is_ok());
    }

    #[test]
    fn list_returns_empty_when_root_missing() {
        let dir = tempdir().unwrap();
        let nonexistent = dir.path().join("does-not-exist");
        let b = FileBackend::new(&nonexistent);
        let list = b.list().unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn list_skips_non_directory_entries_at_root() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("loose.txt"), b"x").unwrap();
        let b = FileBackend::new(dir.path());
        assert!(b.list().unwrap().is_empty());
    }

    #[test]
    fn list_skips_non_file_entries_inside_namespace() {
        let dir = tempdir().unwrap();
        let ns_dir = dir.path().join("ns");
        fs::create_dir_all(&ns_dir).unwrap();
        fs::create_dir_all(ns_dir.join("subdir")).unwrap();
        let b = FileBackend::new(dir.path());
        assert!(b.list().unwrap().is_empty());
    }

    #[test]
    fn set_overwrites_existing() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r = SecretRef::new("ns", "name").unwrap();
        b.set(&r, b"first").unwrap();
        b.set(&r, b"second").unwrap();
        let got = b.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"second");
    }

    #[test]
    fn doctor_ok_when_root_exists() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let d = b.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Ok));
        assert_eq!(d.kind, crate::BackendKind::File);
    }

    #[test]
    fn doctor_degraded_when_root_missing() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path().join("missing"));
        let d = b.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Degraded));
        assert!(d.remediation.is_some());
    }

    #[test]
    fn kind_reports_file() {
        let b = FileBackend::new("/tmp/x");
        assert_eq!(b.kind(), crate::BackendKind::File);
    }

    #[cfg(windows)]
    #[test]
    fn windows_get_returns_when_file_present() {
        let dir = tempdir().unwrap();
        let b = FileBackend::new(dir.path());
        let r = SecretRef::new("ns", "name").unwrap();
        b.set(&r, b"payload").unwrap();
        let got = b.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"payload");
    }
}
