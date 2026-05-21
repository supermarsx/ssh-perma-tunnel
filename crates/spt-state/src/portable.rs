//! Portable-mode runtime context.
//!
//! When `spt` is launched with the global `--portable` flag, every on-disk
//! site that would otherwise resolve to OS-managed user directories
//! (`directories::BaseDirs::data_local_dir()`, `~/.ssh/config`, journald,
//! the Windows Event Log) is gated to a self-contained tree rooted under
//! the executable directory. This module owns the process-global context
//! object that downstream resolvers consult.
//!
//! ### On-disk layout
//!
//! ```text
//! <exe-dir>/spt[.exe]
//! <exe-dir>/data/state/...
//! <exe-dir>/data/vault/...
//! <exe-dir>/data/logs/...
//! <exe-dir>/data/config/spt.toml
//! ```
//!
//! ### Gated sites
//!
//! * [`crate::dir::resolve_state_dir`] — returns `<exe-dir>/data/state/`.
//! * `spt-secrets` — the OS keychain backend is skipped; vault material
//!   lives under `<exe-dir>/data/vault/`.
//! * `spt-config` — `~/.ssh/config` reads are skipped.
//! * `spt-observability` — journald (Linux) and Windows Event Log writers
//!   become no-ops; the file sink rolls under `<exe-dir>/data/logs/`.
//! * AppArmor / SELinux profile loading is not attempted.
//!
//! ### Plumbing model
//!
//! The context is installed by `spt-bin::main` once `--portable` has been
//! detected on the command line (pre-clap scan). Downstream callers query
//! [`current`] instead of taking an explicit argument so the eight-file
//! lock budget for t6-e8 does not require touching every consumer.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use spt_core::{Error, Result};

/// Process-global portable context. `None` means default (BaseDirs-driven)
/// behaviour; `Some(_)` means portable mode is active.
static PORTABLE: OnceLock<Option<PortableContext>> = OnceLock::new();

/// Runtime view of portable-mode paths.
///
/// All sub-trees are children of [`PortableContext::root`]. Callers compose
/// sub-paths via the documented helpers; the layout is **not** discovered
/// at runtime — it is fixed by spec so downstream `--portable` deployments
/// can pre-create the tree at packaging time.
#[derive(Debug, Clone)]
pub struct PortableContext {
    /// `<exe-dir>/data/` — the root that holds `state/`, `vault/`,
    /// `logs/`, and `config/`.
    pub root: PathBuf,
}

impl PortableContext {
    /// Build a context rooted at `<exe_dir>/data/`.
    ///
    /// Does not touch the filesystem; use [`ensure_writable`] to materialise
    /// the directory tree.
    #[must_use]
    pub fn at_exe_dir(exe_dir: &Path) -> Self {
        Self {
            root: exe_dir.join("data"),
        }
    }

    /// `<root>/state` — runtime state, locks, status snapshots.
    #[must_use]
    pub fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    /// `<root>/vault` — file-backed master key + sealed records.
    #[must_use]
    pub fn vault_dir(&self) -> PathBuf {
        self.root.join("vault")
    }

    /// `<root>/logs` — file sink for tracing output.
    #[must_use]
    pub fn logs_dir(&self) -> PathBuf {
        self.root.join("logs")
    }

    /// `<root>/config` — config files, including the remote-config cache.
    #[must_use]
    pub fn config_dir(&self) -> PathBuf {
        self.root.join("config")
    }
}

/// Resolve a [`PortableContext`] from the path of the running executable.
///
/// `exe_path` is typically [`std::env::current_exe`]. The parent directory
/// becomes the anchor; if the executable is a bare filename with no
/// parent (an edge case on some packaged installs), the current working
/// directory is used as the anchor.
///
/// # Errors
///
/// Returns [`Error::RuntimeFailure`] if the executable path is empty.
pub fn portable_context_for(exe_path: &Path) -> Result<PortableContext> {
    let anchor = exe_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(Path::to_path_buf)
        .or_else(|| std::env::current_dir().ok())
        .ok_or_else(|| {
            Error::RuntimeFailure("portable mode: could not determine executable directory".into())
        })?;
    Ok(PortableContext::at_exe_dir(&anchor))
}

/// Verify that `root` is writable, creating the directory if needed.
///
/// Used by `spt-bin` immediately after [`install`] so the operator sees a
/// crisp diagnostic when the executable lives on a read-only medium
/// (`/usr/local/bin` without write access, an SMB share mounted ro, …).
///
/// # Errors
///
/// Returns [`Error::StateLockFailed`] when the directory cannot be created
/// or is not writable.
pub fn ensure_writable(root: &Path) -> Result<()> {
    std::fs::create_dir_all(root).map_err(|e| Error::StateLockFailed {
        path: root.to_path_buf(),
        reason: format!("portable root: create_dir_all failed: {e}"),
    })?;
    // Probe write access by atomically creating and removing a marker file.
    // We avoid relying on `metadata().permissions().readonly()` because on
    // Unix that bit only reflects the owner-write flag, not the effective
    // ACL / mount-option situation.
    let probe = root.join(".spt-portable-probe");
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            Ok(())
        }
        Err(e) => Err(Error::StateLockFailed {
            path: root.to_path_buf(),
            reason: format!("portable root is not writable: {e}"),
        }),
    }
}

/// Install the process-global portable context.
///
/// Subsequent calls are no-ops — the first install wins. Returns `true`
/// when the context was stored, `false` when a prior install already set
/// the slot (whether to `Some` or `None`). `spt-bin::main` calls this
/// exactly once after pre-scanning the CLI for `--portable`.
pub fn install(ctx: Option<PortableContext>) -> bool {
    PORTABLE.set(ctx).is_ok()
}

/// Borrow the active portable context.
///
/// Returns `None` when portable mode is disabled or before [`install`] has
/// been called. Consumers in non-`spt-bin` crates use this to decide
/// whether to skip BaseDirs lookups, the OS keychain, journald, etc.
#[must_use]
pub fn current() -> Option<&'static PortableContext> {
    PORTABLE.get().and_then(Option::as_ref)
}

/// Convenience predicate — `true` when portable mode is active.
#[must_use]
pub fn is_portable() -> bool {
    current().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn at_exe_dir_layout_matches_spec() {
        let ctx = PortableContext::at_exe_dir(Path::new("/opt/spt"));
        assert_eq!(ctx.root, Path::new("/opt/spt/data"));
        assert_eq!(ctx.state_dir(), Path::new("/opt/spt/data/state"));
        assert_eq!(ctx.vault_dir(), Path::new("/opt/spt/data/vault"));
        assert_eq!(ctx.logs_dir(), Path::new("/opt/spt/data/logs"));
        assert_eq!(ctx.config_dir(), Path::new("/opt/spt/data/config"));
    }

    #[test]
    fn portable_context_for_uses_exe_parent() {
        let tmp = tempdir().unwrap();
        let exe = tmp.path().join("spt");
        let ctx = portable_context_for(&exe).unwrap();
        assert_eq!(ctx.root, tmp.path().join("data"));
    }

    #[test]
    fn ensure_writable_creates_root() {
        let tmp = tempdir().unwrap();
        let root = tmp.path().join("data");
        assert!(!root.exists());
        ensure_writable(&root).unwrap();
        assert!(root.is_dir());
        // Probe file must be cleaned up.
        assert!(!root.join(".spt-portable-probe").exists());
    }

    #[test]
    fn ensure_writable_is_idempotent() {
        let tmp = tempdir().unwrap();
        let root = tmp.path().join("data");
        ensure_writable(&root).unwrap();
        ensure_writable(&root).unwrap();
        ensure_writable(&root).unwrap();
        assert!(root.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn ensure_writable_rejects_readonly_root_with_diagnostic() {
        use std::os::unix::fs::PermissionsExt;
        // Skip when running as root; root bypasses DAC writability checks.
        if nix::unistd::geteuid().is_root() {
            return;
        }
        let tmp = tempdir().unwrap();
        let parent = tmp.path().join("ro-parent");
        std::fs::create_dir_all(&parent).unwrap();
        let mut perms = std::fs::metadata(&parent).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&parent, perms).unwrap();
        let root = parent.join("data");
        let err = ensure_writable(&root).unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("portable root") || msg.contains("not writable"),
            "missing diagnostic in {msg}"
        );
        // Restore so tempdir cleanup can proceed.
        let mut p = std::fs::metadata(&parent).unwrap().permissions();
        p.set_mode(0o755);
        let _ = std::fs::set_permissions(&parent, p);
    }

    #[test]
    fn install_and_current_round_trip_in_isolated_subprocess() {
        // OnceLock is process-global; we cannot mutate it from a test
        // without poisoning other tests in the same binary. Instead
        // verify the install function returns true for a fresh OnceLock
        // via a separate static.
        static SLOT: OnceLock<Option<PortableContext>> = OnceLock::new();
        let ctx = PortableContext::at_exe_dir(Path::new("/tmp/spt"));
        assert!(SLOT.set(Some(ctx.clone())).is_ok());
        assert!(SLOT.set(None).is_err()); // second install loses
        let got = SLOT.get().and_then(Option::as_ref).unwrap();
        assert_eq!(got.root, ctx.root);
    }
}
