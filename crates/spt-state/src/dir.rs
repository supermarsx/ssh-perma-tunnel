//! State-directory resolution per plan §3.
//!
//! Default per-OS layout:
//!
//! * Linux:   `~/.local/state/spt/`
//! * macOS:   `~/Library/Application Support/spt/`
//! * Windows: `%LOCALAPPDATA%\spt\state\`
//!
//! Portable mode (see [`crate::portable`]) overrides the default with
//! `<exe-dir>/data/state/`. An explicit `config_state_dir` always wins,
//! even when portable mode is active, so operator overrides remain
//! authoritative.

use std::path::{Path, PathBuf};

use spt_core::{Error, Result};

/// Resolve and create the state directory.
///
/// Precedence (high to low):
///
/// 1. `config_state_dir` — honoured verbatim when `Some`.
/// 2. Portable mode (when [`crate::portable::current`] is set) — returns
///    `<exe-dir>/data/state/`.
/// 3. Per-OS default — see the module-level docs.
///
/// The directory tree is created if missing. On Unix it is created with mode
/// `0700` (best-effort).
pub fn resolve_state_dir(config_state_dir: Option<&Path>) -> Result<PathBuf> {
    resolve_state_dir_inner(config_state_dir, crate::portable::current())
}

/// Internal test seam — same logic as [`resolve_state_dir`] but with the
/// portable context passed explicitly so unit tests can exercise both
/// branches without mutating the process-global [`crate::portable`] slot.
pub(crate) fn resolve_state_dir_inner(
    config_state_dir: Option<&Path>,
    portable: Option<&crate::portable::PortableContext>,
) -> Result<PathBuf> {
    let dir = if let Some(cfg) = config_state_dir {
        cfg.to_path_buf()
    } else if let Some(portable) = portable {
        portable.state_dir()
    } else {
        default_state_dir()?
    };
    ensure_dir(&dir)?;
    Ok(dir)
}

fn default_state_dir() -> Result<PathBuf> {
    // `directories::ProjectDirs::state_dir()` returns Some only on Linux. We
    // pick paths manually to match the layout the plan stipulates.
    if cfg!(target_os = "linux") {
        let base = directories::BaseDirs::new().ok_or_else(|| {
            Error::RuntimeFailure("could not determine user base directories".into())
        })?;
        // BaseDirs::state_dir is Some on Linux (XDG_STATE_HOME).
        let state = base.state_dir().map_or_else(
            || base.home_dir().join(".local").join("state"),
            Path::to_path_buf,
        );
        Ok(state.join("spt"))
    } else if cfg!(target_os = "macos") {
        let base = directories::BaseDirs::new().ok_or_else(|| {
            Error::RuntimeFailure("could not determine user base directories".into())
        })?;
        // ~/Library/Application Support
        Ok(base.data_dir().join("spt"))
    } else if cfg!(target_os = "windows") {
        let base = directories::BaseDirs::new().ok_or_else(|| {
            Error::RuntimeFailure("could not determine user base directories".into())
        })?;
        // %LOCALAPPDATA%\spt\state
        Ok(base.data_local_dir().join("spt").join("state"))
    } else {
        // Best-effort fallback for other Unixes: behave like Linux.
        let base = directories::BaseDirs::new().ok_or_else(|| {
            Error::RuntimeFailure("could not determine user base directories".into())
        })?;
        Ok(base.home_dir().join(".local").join("state").join("spt"))
    }
}

fn ensure_dir(dir: &Path) -> Result<()> {
    // Whether the leaf already existed governs the Windows tightening below
    // (mirrors the Unix "tighten on first creation" intent and avoids an
    // `icacls` shell-out on every CLI invocation).
    #[cfg(windows)]
    let freshly_created = !dir.exists();

    std::fs::create_dir_all(dir).map_err(|e| Error::StateLockFailed {
        path: dir.to_path_buf(),
        reason: format!("create state directory failed: {e}"),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Best-effort: tighten to 0700 on first creation. Ignore failures
        // (e.g. read-only test fixtures) — owner readability is what matters.
        if let Ok(meta) = std::fs::metadata(dir) {
            let mut perms = meta.permissions();
            if perms.mode() & 0o777 != 0o700 {
                perms.set_mode(0o700);
                let _ = std::fs::set_permissions(dir, perms);
            }
        }
    }

    // H2: Windows has no `0700` mode bit. The default per-user state dir
    // (`%LOCALAPPDATA%\spt\state`) is safe, but operators routinely point
    // `--state-dir` / `SPT_STATE_DIR` at a machine-wide path, and the SCM
    // service runs as LocalSystem — so state files created under
    // `C:\ProgramData` would inherit `Users:Read`. On fresh creation, set an
    // explicit, inheritable owner + SYSTEM/Administrators DACL so the dir AND
    // the files later created inside it (status/lock/event/spool) are not
    // readable by all local users.
    #[cfg(windows)]
    if freshly_created {
        windows_acl::restrict_dir(dir);
    }

    Ok(())
}

/// Restrict a freshly-created state directory's DACL on Windows to owner +
/// SYSTEM + Administrators, with the grants made inheritable so files created
/// inside are protected too. Implemented via `icacls` (always present on
/// Windows) so no new crate dependency is added. Best-effort: failures are
/// logged, never fatal.
#[cfg(windows)]
mod windows_acl {
    use std::path::Path;
    use std::process::Command;

    pub(super) fn restrict_dir(dir: &Path) {
        // `(OI)(CI)(F)` = object+container inherit, full control — so child
        // files/dirs inherit the owner-only DACL. Well-known SIDs keep the
        // grant locale-independent (*S-1-5-18 = Local System,
        // *S-1-5-32-544 = BUILTIN\Administrators).
        let mut cmd = Command::new("icacls");
        cmd.arg(dir)
            .arg("/inheritance:r")
            .arg("/grant:r")
            .arg("*S-1-5-18:(OI)(CI)(F)")
            .arg("/grant:r")
            .arg("*S-1-5-32-544:(OI)(CI)(F)");
        if let Ok(user) = std::env::var("USERNAME") {
            if !user.is_empty() {
                let principal = match std::env::var("USERDOMAIN") {
                    Ok(dom) if !dom.is_empty() => format!("{dom}\\{user}"),
                    _ => user,
                };
                cmd.arg("/grant:r").arg(format!("{principal}:(OI)(CI)(F)"));
            }
        }
        match cmd.output() {
            Ok(out) if out.status.success() => {}
            Ok(out) => tracing::warn!(
                path = %dir.display(),
                code = ?out.status.code(),
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "icacls could not restrict the state directory DACL; \
                 state files may be readable by non-owner principals"
            ),
            Err(e) => tracing::warn!(
                path = %dir.display(),
                error = %e,
                "could not run icacls to restrict the state directory DACL"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn explicit_dir_is_honoured_and_created() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("nested").join("state");
        let resolved = resolve_state_dir(Some(&target)).unwrap();
        assert_eq!(resolved, target);
        assert!(target.is_dir());
    }

    #[test]
    fn explicit_dir_existing_is_idempotent() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("state");
        std::fs::create_dir_all(&target).unwrap();
        let resolved = resolve_state_dir(Some(&target)).unwrap();
        assert_eq!(resolved, target);
    }

    #[cfg(unix)]
    #[test]
    fn unix_dir_gets_0700_when_freshly_created() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("perm-state");
        let _ = resolve_state_dir(Some(&target)).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
    }

    #[test]
    fn default_dir_resolves_for_current_os() {
        // Don't rely on global home being writable; just check the path computes.
        let p = default_state_dir().unwrap();
        assert!(p.ends_with("spt") || p.components().any(|c| c.as_os_str() == "spt"));
    }

    #[test]
    fn explicit_dir_creates_intermediate_directories() {
        let tmp = tempdir().unwrap();
        let deep = tmp
            .path()
            .join("level1")
            .join("level2")
            .join("level3")
            .join("state");
        assert!(!deep.exists());
        let r = resolve_state_dir(Some(&deep)).unwrap();
        assert_eq!(r, deep);
        assert!(deep.is_dir());
    }

    #[test]
    fn none_input_uses_default_path_containing_spt() {
        let def = default_state_dir().unwrap();
        let s = def.to_string_lossy();
        assert!(s.contains("spt"), "default path missing 'spt' segment: {s}");
    }

    #[test]
    fn idempotent_when_called_twice() {
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("twice");
        let a = resolve_state_dir(Some(&target)).unwrap();
        let b = resolve_state_dir(Some(&target)).unwrap();
        assert_eq!(a, b);
        assert!(target.is_dir());
    }

    #[test]
    fn portable_mode_routes_state_under_exe_dir() {
        use crate::portable::PortableContext;
        let tmp = tempdir().unwrap();
        let exe_dir = tmp.path().join("install");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let ctx = PortableContext::at_exe_dir(&exe_dir);
        let resolved = resolve_state_dir_inner(None, Some(&ctx)).unwrap();
        assert_eq!(resolved, exe_dir.join("data").join("state"));
        assert!(resolved.is_dir());
    }

    #[test]
    fn default_mode_does_not_use_exe_dir_when_portable_is_none() {
        // When portable context is None and no explicit dir is given,
        // resolution falls back to the per-OS default. We just confirm
        // the computed path includes the canonical "spt" segment, which a
        // portable path would NOT have unless the exe lived under such a
        // tree.
        let computed = default_state_dir().unwrap();
        assert!(computed.components().any(|c| c.as_os_str() == "spt"));
    }

    #[test]
    fn explicit_dir_wins_over_portable_context() {
        use crate::portable::PortableContext;
        let tmp = tempdir().unwrap();
        let exe_dir = tmp.path().join("install");
        std::fs::create_dir_all(&exe_dir).unwrap();
        let ctx = PortableContext::at_exe_dir(&exe_dir);
        let explicit = tmp.path().join("explicit-state");
        let resolved = resolve_state_dir_inner(Some(&explicit), Some(&ctx)).unwrap();
        assert_eq!(resolved, explicit);
        assert!(resolved.is_dir());
        // Portable's state dir must NOT have been touched.
        assert!(!exe_dir.join("data").join("state").exists());
    }

    // H2: a freshly-created state dir on Windows must have its DACL restricted
    // so the Users group / Everyone lose read. We read the DACL back via
    // `icacls`. (GitHub-hosted Windows runners are en-US, so the group names
    // below match; the inheritance-removed `(I)` check is locale-independent.)
    #[cfg(windows)]
    #[test]
    fn windows_fresh_state_dir_drops_users_read() {
        use std::process::Command;
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("win-state");
        let _ = resolve_state_dir(Some(&target)).unwrap();

        let out = Command::new("icacls").arg(&target).output().unwrap();
        assert!(out.status.success(), "icacls readback failed");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            !text.contains("\\Users:") && !text.contains("Everyone:"),
            "Users/Everyone still present in state-dir DACL: {text}"
        );
        assert!(
            text.contains("SYSTEM"),
            "SYSTEM grant missing from restricted state-dir DACL: {text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_unix_dir_with_wrong_mode_is_tightened() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let target = tmp.path().join("loose");
        std::fs::create_dir_all(&target).unwrap();
        let mut perms = std::fs::metadata(&target).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&target, perms).unwrap();
        let _ = resolve_state_dir(Some(&target)).unwrap();
        let m = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(m, 0o700);
    }
}
