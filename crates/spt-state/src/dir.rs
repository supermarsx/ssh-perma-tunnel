//! State-directory resolution per plan §3.
//!
//! Default per-OS layout:
//!
//! * Linux:   `~/.local/state/spt/`
//! * macOS:   `~/Library/Application Support/spt/`
//! * Windows: `%LOCALAPPDATA%\spt\state\`

use std::path::{Path, PathBuf};

use spt_core::{Error, Result};

/// Resolve and create the state directory.
///
/// If `config_state_dir` is `Some`, that path is honoured verbatim. Otherwise
/// a per-OS default is chosen as documented at the module level.
///
/// The directory tree is created if missing. On Unix it is created with mode
/// `0700` (best-effort).
pub fn resolve_state_dir(config_state_dir: Option<&Path>) -> Result<PathBuf> {
    let dir = if let Some(cfg) = config_state_dir {
        cfg.to_path_buf()
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

    Ok(())
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
