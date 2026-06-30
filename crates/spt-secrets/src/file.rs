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

    /// Build the on-disk path for a reference, re-verifying that it stays
    /// lexically within the configured root before any I/O.
    ///
    /// [`SecretRef`] already rejects `.`/`..`, path separators, absolute/drive
    /// markers, and NUL at construction, so a traversal cannot reach this point
    /// through the normal parse path. This containment check is defense in
    /// depth: a future change to the reference grammar (or a hand-built
    /// reference) can never make the backend read or write outside `<root>`.
    fn resolve_within_root(&self, r: &SecretRef) -> Result<PathBuf> {
        let path = self.path_for(r);
        if !path_within_root(&self.root, &path) {
            return Err(Error::PermissionDenied(format!(
                "secret reference `{r}` resolves outside the secrets root `{}`",
                self.root.display()
            )));
        }
        Ok(path)
    }
}

/// Lexical (no-filesystem) containment check: does `candidate` stay within
/// `root` after folding `.`/`..` components purely textually? The file need not
/// exist. Fails closed — anything that would ascend above `root` (or any path
/// we cannot normalize) returns `false`.
fn path_within_root(root: &Path, candidate: &Path) -> bool {
    use std::path::Component;
    fn lexical(p: &Path) -> Option<PathBuf> {
        let mut out = PathBuf::new();
        for comp in p.components() {
            match comp {
                Component::ParentDir => {
                    // Refuse to ascend past the accumulated prefix — a `..` that
                    // pops nothing means the path escapes its root.
                    if !out.pop() {
                        return None;
                    }
                }
                Component::CurDir => {}
                other => out.push(other.as_os_str()),
            }
        }
        Some(out)
    }
    match (lexical(root), lexical(candidate)) {
        (Some(root), Some(candidate)) => candidate.starts_with(&root),
        _ => false,
    }
}

/// Enforce owner-only permissions on a secret file before reading it.
///
/// On Unix this is a hard check: only `0o400` and `0o600` are accepted;
/// anything broader returns [`Error::PermissionDenied`]. On Windows this
/// performs a best-effort DACL audit and emits a `warn!` when read access is
/// granted to a non-owner principal, but never rejects (NTFS ACLs are too
/// environment-dependent for a hard per-read gate; strict enforcement lives in
/// `spt secret doctor`). On other platforms it is a no-op.
///
/// Exposed so the SSH auth fast-paths (`spt-ssh2`, `spt-ssh3`) that resolve
/// `file://` references can apply the same enforcement instead of doing a bare
/// `fs::read`.
#[cfg(unix)]
pub fn check_mode(path: &Path) -> Result<()> {
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

/// See the Unix variant for the full contract.
#[cfg(windows)]
pub fn check_mode(path: &Path) -> Result<()> {
    // First confirm the file exists / is stat-able. A missing or unreadable
    // file is the same error the read would surface.
    if let Err(e) = fs::metadata(path) {
        return Err(Error::SecretUnavailable {
            reference: path.display().to_string(),
            reason: format!("stat: {e}"),
        });
    }
    // Best-effort DACL audit: warn (never reject) when a non-owner principal
    // has read access. Full enforcement stays in `spt secret doctor`.
    if let Some(principal) = windows_dacl::non_owner_reader(path) {
        warn!(
            path = %path.display(),
            principal = %principal,
            "secret file DACL grants read access to a non-owner principal; \
             restrict it to the owner (run `spt secret doctor` for details)"
        );
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn check_mode(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
mod windows_dacl {
    //! Best-effort DACL inspection: returns a label for the first non-owner
    //! principal that is granted read access, or `None` when the DACL is
    //! owner-clean (or the inspection could not be performed — failures are
    //! swallowed so a quirky ACL never blocks a read).

    use std::ffi::c_void;
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HLOCAL};
    use windows::Win32::Security::Authorization::{
        ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
    };
    use windows::Win32::Security::{
        EqualSid, GetAce, IsValidAcl, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
        DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    };

    // `ACCESS_ALLOWED_ACE_TYPE` == 0 (winnt.h). Inlined to avoid pulling in the
    // `Win32_System_SystemServices` feature just for one constant.
    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
    // Read-implying bits: GENERIC_READ | GENERIC_ALL | FILE_GENERIC_READ |
    // FILE_READ_DATA | the generic-mapping superset. We treat any of these as
    // "can read".
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;
    const FILE_READ_DATA: u32 = 0x0000_0001;
    const FILE_GENERIC_READ: u32 = 0x0012_0089;

    fn grants_read(mask: u32) -> bool {
        mask & (GENERIC_READ | GENERIC_ALL | FILE_GENERIC_READ | FILE_READ_DATA) != 0
    }

    fn sid_to_string(sid: PSID) -> String {
        // SAFETY: `sid` came from a valid security descriptor; on success the
        // returned PWSTR points at a LocalAlloc buffer we free below.
        unsafe {
            let mut out = PWSTR::null();
            if ConvertSidToStringSidW(sid, &raw mut out).is_ok() && !out.is_null() {
                // 1.88 lint: implicit raw-pointer borrow
                let s = out.to_string().unwrap_or_else(|_| "<sid>".into());
                let _ = LocalFree(HLOCAL(out.0.cast::<c_void>()));
                s
            } else {
                "<sid>".into()
            }
        }
    }

    pub(super) fn non_owner_reader(path: &Path) -> Option<String> {
        let wide: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut owner = PSID::default();
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR::default();

        // SAFETY: all out-params are owned locals; `sd` is freed before return.
        unsafe {
            let rc = GetNamedSecurityInfoW(
                PCWSTR(wide.as_ptr()),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                Some(&raw mut owner),
                None,
                Some(&raw mut dacl),
                None,
                &raw mut sd, // 1.88 lint: implicit raw-pointer borrow
            );
            if rc != ERROR_SUCCESS {
                return None;
            }

            let result = (|| {
                if dacl.is_null() || !IsValidAcl(dacl).as_bool() {
                    // A null DACL grants everyone full access — flag it.
                    return if dacl.is_null() {
                        Some("Everyone (null DACL)".to_string())
                    } else {
                        None
                    };
                }
                let count = (*dacl).AceCount;
                for i in 0..count {
                    let mut ace: *mut c_void = std::ptr::null_mut();
                    if GetAce(dacl, u32::from(i), &raw mut ace).is_err() || ace.is_null() {
                        // 1.88 lint: implicit raw-pointer borrow
                        continue;
                    }
                    let header = ace.cast::<ACE_HEADER>();
                    if (*header).AceType != ACCESS_ALLOWED_ACE_TYPE {
                        continue;
                    }
                    let allowed = ace.cast::<ACCESS_ALLOWED_ACE>();
                    if !grants_read((*allowed).Mask) {
                        continue;
                    }
                    // The SID is laid out starting at `SidStart`.
                    let sid = PSID(std::ptr::addr_of!((*allowed).SidStart) as *mut c_void);
                    let is_owner = !owner.is_invalid() && EqualSid(sid, owner).is_ok();
                    if !is_owner {
                        return Some(sid_to_string(sid));
                    }
                }
                None
            })();

            if !sd.is_invalid() {
                let _ = LocalFree(HLOCAL(sd.0));
            }
            result
        }
    }
}

impl SecretBackend for FileBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::File
    }

    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        let path = self.resolve_within_root(r)?;
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
        let path = self.resolve_within_root(r)?;
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
        let path = self.resolve_within_root(r)?;
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
    fn path_within_root_accepts_in_root_and_rejects_escape() {
        let root = Path::new("/var/lib/spt/secrets");
        // Normal, in-root paths.
        assert!(path_within_root(root, &root.join("ns").join("name")));
        assert!(path_within_root(root, root));
        // A `..` that climbs out of the root is rejected.
        assert!(!path_within_root(
            root,
            Path::new("/var/lib/spt/secrets/../foo")
        ));
        assert!(!path_within_root(
            root,
            Path::new("/var/lib/spt/secrets/ns/../../../etc/passwd")
        ));
        // A sibling directory that merely shares a prefix string is rejected.
        assert!(!path_within_root(
            root,
            Path::new("/var/lib/spt/secrets-evil/x")
        ));
        // Relative roots work symmetrically (used in tests / portable layouts).
        let rel = Path::new("secrets");
        assert!(path_within_root(rel, &rel.join("ns").join("name")));
        assert!(!path_within_root(rel, Path::new("secrets/../escape")));
    }

    #[test]
    fn resolve_within_root_allows_valid_reference() {
        let b = FileBackend::new("/var/lib/spt/secrets");
        let r = SecretRef::new("ns", "name").unwrap();
        let p = b.resolve_within_root(&r).unwrap();
        assert_eq!(p, b.path_for(&r));
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

    #[cfg(unix)]
    #[test]
    fn check_mode_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let p = dir.path().join("s");
        fs::write(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let err = check_mode(&p).unwrap_err();
        assert!(matches!(err, Error::PermissionDenied(_)), "got {err:?}");
    }

    #[cfg(unix)]
    #[test]
    fn check_mode_accepts_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let p = dir.path().join("s");
        fs::write(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_mode(&p).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn check_mode_missing_file_is_unavailable() {
        let dir = tempdir().unwrap();
        let err = check_mode(&dir.path().join("nope")).unwrap_err();
        assert!(
            matches!(err, Error::SecretUnavailable { .. }),
            "got {err:?}"
        );
    }

    // On Windows `check_mode` is best-effort: it must never reject a readable
    // file (the DACL audit only warns). A freshly-created file in a temp dir
    // typically inherits a permissive DACL (Users:R), which exercises the
    // non-owner-reader warn path without failing the read.
    #[cfg(windows)]
    #[test]
    fn windows_check_mode_never_rejects_readable_file() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("s");
        fs::write(&p, b"x").unwrap();
        // Whether or not the DACL is owner-clean, the call must succeed.
        assert!(check_mode(&p).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_check_mode_missing_file_is_unavailable() {
        let dir = tempdir().unwrap();
        let err = check_mode(&dir.path().join("nope")).unwrap_err();
        assert!(
            matches!(err, Error::SecretUnavailable { .. }),
            "got {err:?}"
        );
    }
}
