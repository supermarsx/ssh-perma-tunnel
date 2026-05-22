//! Process-scoped registry of live SFTP mounts (t7-B2, closes
//! Bwire follow-up #3).
//!
//! The original `mount stop` implementation in `spt-bin` re-opened an SSH
//! session and called `umount` on a freshly constructed mounter. That worked
//! for in-process backends with a stateless umount (sshfs shell-out, FUSE
//! kernel umount-by-path) but was structurally wrong for backends that hold
//! a live in-process session loop — most notably the Linux `fuser` /
//! Windows WinFsp backends, where the live [`SftpMounter`] *is* the mount.
//! Re-creating a fresh mounter only to tear it down loses the handle to the
//! background session and forces every backend to grow a "umount by path"
//! escape hatch.
//!
//! This module owns the supervisor-side registry. The CLI surface in
//! `spt-bin::cli::sftp_ops` holds a process-global [`MountRegistry`] via
//! `OnceLock` and threads each `mount_start` success through
//! [`MountRegistry::register`], so the live mounter survives until the
//! matching [`MountRegistry::tear_down`] call (typically `mount stop`).
//!
//! ## Thread safety
//!
//! `SftpMounter` (in `spt_sftp::mount`) requires only `Send`; the
//! registry stores each mounter behind a `parking_lot::Mutex` so
//! `tear_down` can run from any thread. This is the correct contract for
//! the current backends (`sshfs` shell-out is trivially `Send`; `fuser` and
//! `winfsp` accept umount from any thread once the session is up). If a
//! future backend needs umount on the original mount thread, that
//! constraint must be enforced inside the backend itself — the registry
//! cannot honour a thread-affinity invariant without `!Send` bounds it
//! cannot express.
//!
//! ## Audit
//!
//! The registry is intentionally **silent**: it neither emits audit events
//! nor touches `tracing`. The caller (`spt-bin::cli::sftp_ops::mount_stop`)
//! continues to call `crate::audit::emit_sftp_umount` after a successful
//! tear-down. Keeping the registry pure makes it testable without the
//! workspace audit sink.

use std::collections::HashMap;
use std::path::PathBuf;

use parking_lot::Mutex;
use spt_sftp::mount::{MountHandle, SftpMounter};
use thiserror::Error;

/// Identifier for a live mount. Profile name + local mountpoint together
/// uniquely name a mount; the same profile can have multiple mounts at
/// different paths, and the same path could in principle (though not
/// in practice — the OS rejects double-mounts) be re-used across profiles.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct MountKey {
    /// Owning profile name (matches [`spt_config::schema::Profile::name`]).
    pub profile: String,
    /// Resolved local mountpoint (the same `PathBuf` passed to
    /// [`SftpMounter::mount`]).
    pub mountpoint: PathBuf,
}

impl MountKey {
    /// Construct a key from owned components.
    #[must_use]
    pub fn new(profile: impl Into<String>, mountpoint: impl Into<PathBuf>) -> Self {
        Self {
            profile: profile.into(),
            mountpoint: mountpoint.into(),
        }
    }
}

/// Errors surfaced by [`MountRegistry`].
#[derive(Debug, Error)]
pub enum MountRegistryError {
    /// [`MountRegistry::register`] was called twice with the same key
    /// without an intervening [`MountRegistry::tear_down`]. The caller
    /// almost certainly wants to tear the previous mount down first.
    #[error(
        "SFTP mount already registered for profile `{profile}` at `{mountpoint}`; \
         call tear_down before re-registering"
    )]
    AlreadyRegistered {
        /// The profile portion of the rejected key.
        profile: String,
        /// The mountpoint portion of the rejected key.
        mountpoint: PathBuf,
    },
    /// [`MountRegistry::tear_down`] was called with a key the registry has
    /// no record of. The most common cause is a `mount stop` issued
    /// against a mount that was created out-of-band (e.g. a previous
    /// process invocation, or directly via `sshfs`); the CLI surface falls
    /// back to the legacy "open new mounter and umount by path" code path
    /// in that case.
    #[error(
        "no SFTP mount registered for profile `{profile}` at `{mountpoint}`; \
         the mount may have been created out-of-band or already torn down"
    )]
    UnknownKey {
        /// The profile portion of the rejected key.
        profile: String,
        /// The mountpoint portion of the rejected key.
        mountpoint: PathBuf,
    },
    /// The mounter's `umount` call surfaced an error. The handle is
    /// preserved on the error so the caller can decide whether to retry,
    /// log, or drop it.
    #[error("umount failed for `{mountpoint}`: {source}")]
    Umount {
        /// The mountpoint the registry attempted to tear down.
        mountpoint: PathBuf,
        /// Underlying error from the platform mounter.
        #[source]
        source: spt_sftp::SftpError,
    },
}

/// Single entry stored by the registry: the live mounter, plus its handle.
struct MountEntry {
    /// Live mounter. `Box<dyn SftpMounter>` is `Send` because the trait
    /// itself is `Send`; the surrounding `Mutex` in [`MountRegistry::inner`]
    /// gives us the `Sync` bound the public API exposes.
    mounter: Box<dyn SftpMounter>,
    /// Handle returned by the original `mount` call. Cloned out on
    /// `tear_down` so callers can inspect the backend identity / helper
    /// PID after the registry has forgotten the entry.
    handle: MountHandle,
}

/// Process-scoped registry of live SFTP mounts.
///
/// Constructed once per process (typically via [`std::sync::OnceLock`] in
/// the CLI binary) and shared across CLI subcommand invocations through
/// `&'static MountRegistry`. The internal map is guarded by a
/// `parking_lot::Mutex` so the registry is `Send + Sync` regardless of the
/// `Send`-only contract on [`SftpMounter`].
pub struct MountRegistry {
    inner: Mutex<HashMap<MountKey, MountEntry>>,
}

impl Default for MountRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for MountRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let guard = self.inner.lock();
        f.debug_struct("MountRegistry")
            .field("entries", &guard.len())
            .field("keys", &guard.keys().cloned().collect::<Vec<_>>())
            .finish()
    }
}

impl MountRegistry {
    /// Construct an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
        }
    }

    /// Register a live mounter under `key`. Returns
    /// [`MountRegistryError::AlreadyRegistered`] if an entry already
    /// exists for the same key — the caller must explicitly
    /// [`MountRegistry::tear_down`] the previous mount first.
    pub fn register(
        &self,
        key: MountKey,
        mounter: Box<dyn SftpMounter>,
        handle: MountHandle,
    ) -> Result<(), MountRegistryError> {
        let mut guard = self.inner.lock();
        if guard.contains_key(&key) {
            return Err(MountRegistryError::AlreadyRegistered {
                profile: key.profile,
                mountpoint: key.mountpoint,
            });
        }
        guard.insert(key, MountEntry { mounter, handle });
        Ok(())
    }

    /// Tear down the live mount registered under `key`. Removes the entry
    /// from the registry (so a subsequent `tear_down` returns
    /// [`MountRegistryError::UnknownKey`]) and returns the original
    /// [`MountHandle`] for diagnostic / audit purposes.
    ///
    /// On `umount` failure the entry is **not** re-inserted — the live
    /// `Box<dyn SftpMounter>` is dropped (which on most backends triggers
    /// a best-effort `umount` in `Drop`) and the error is surfaced to the
    /// caller as [`MountRegistryError::Umount`]. The caller is then free
    /// to fall back to the legacy "umount by path" code path.
    pub fn tear_down(&self, key: &MountKey) -> Result<MountHandle, MountRegistryError> {
        // Remove the entry first so the lock is released before we call
        // into the (potentially blocking) `umount`. Holding the registry
        // mutex across a kernel call would serialise every other registry
        // operation on the slow path.
        let MountEntry {
            mut mounter,
            handle,
        } = {
            let mut guard = self.inner.lock();
            guard
                .remove(key)
                .ok_or_else(|| MountRegistryError::UnknownKey {
                    profile: key.profile.clone(),
                    mountpoint: key.mountpoint.clone(),
                })?
        };
        // `SftpMounter::umount` consumes the handle by value but
        // documents idempotency, so cloning here is safe and lets us
        // return the handle to the caller for logging.
        let result_handle = handle.clone();
        mounter
            .umount(handle)
            .map_err(|source| MountRegistryError::Umount {
                mountpoint: result_handle.mountpoint.clone(),
                source,
            })?;
        Ok(result_handle)
    }

    /// Snapshot of every currently registered key. Useful for diagnostics
    /// and the `spt sftp mount list --live` surface (to be added).
    #[must_use]
    pub fn list(&self) -> Vec<MountKey> {
        self.inner.lock().keys().cloned().collect()
    }

    /// Returns `true` if a live mount is registered under `key`.
    #[must_use]
    pub fn contains(&self, key: &MountKey) -> bool {
        self.inner.lock().contains_key(key)
    }

    /// Number of live mounts currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// `true` iff no live mounts are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_sftp::mount::{MountOpts, NullMounter};

    fn make_key(profile: &str, path: &str) -> MountKey {
        MountKey::new(profile, PathBuf::from(path))
    }

    fn mount_target() -> &'static str {
        if cfg!(windows) {
            "C:/mnt/data"
        } else {
            "/mnt/data"
        }
    }

    fn live_mounter_and_handle(target: &str) -> (Box<dyn SftpMounter>, MountHandle) {
        let mut m = NullMounter::default();
        let handle = m
            .mount(MountOpts::new(target, "/srv/data"))
            .expect("null mount succeeds");
        (Box::new(m), handle)
    }

    #[test]
    fn new_registry_is_empty() {
        let reg = MountRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.list().is_empty());
    }

    #[test]
    fn register_then_tear_down_returns_handle() {
        let reg = MountRegistry::new();
        let target = mount_target();
        let (mounter, handle) = live_mounter_and_handle(target);
        let key = make_key("edge", target);
        reg.register(key.clone(), mounter, handle)
            .expect("register");
        assert!(reg.contains(&key));
        assert_eq!(reg.len(), 1);
        let returned = reg.tear_down(&key).expect("tear_down");
        assert_eq!(returned.mountpoint, PathBuf::from(target));
        assert_eq!(returned.backend, "null");
        assert!(!reg.contains(&key));
        assert!(reg.is_empty());
    }

    #[test]
    fn tear_down_unknown_key_errors_with_diagnostic() {
        let reg = MountRegistry::new();
        let key = make_key("edge", mount_target());
        let err = reg.tear_down(&key).unwrap_err();
        match err {
            MountRegistryError::UnknownKey {
                profile,
                mountpoint,
            } => {
                assert_eq!(profile, "edge");
                assert_eq!(mountpoint, PathBuf::from(mount_target()));
            }
            other => panic!("expected UnknownKey, got {other:?}"),
        }
        // The diagnostic text mentions the path so operators can grep for it.
        let err = reg.tear_down(&key).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains("edge"),
            "diagnostic mentions profile: {rendered}"
        );
        assert!(
            rendered.contains(&mount_target().replace('\\', "/"))
                || rendered.contains(mount_target()),
            "diagnostic mentions mountpoint: {rendered}",
        );
    }

    #[test]
    fn double_register_same_key_errors() {
        let reg = MountRegistry::new();
        let target = mount_target();
        let key = make_key("edge", target);
        let (mounter1, handle1) = live_mounter_and_handle(target);
        reg.register(key.clone(), mounter1, handle1)
            .expect("first register");
        let (mounter2, handle2) = live_mounter_and_handle(target);
        let err = reg.register(key.clone(), mounter2, handle2).unwrap_err();
        match err {
            MountRegistryError::AlreadyRegistered {
                profile,
                mountpoint,
            } => {
                assert_eq!(profile, "edge");
                assert_eq!(mountpoint, PathBuf::from(target));
            }
            other => panic!("expected AlreadyRegistered, got {other:?}"),
        }
        // The original entry is still live and tearable.
        assert!(reg.contains(&key));
        reg.tear_down(&key).expect("tear_down original entry");
    }

    #[test]
    fn list_returns_all_active_mounts() {
        let reg = MountRegistry::new();
        let targets = if cfg!(windows) {
            ["C:/mnt/a", "C:/mnt/b", "C:/mnt/c"]
        } else {
            ["/mnt/a", "/mnt/b", "/mnt/c"]
        };
        for (idx, target) in targets.iter().enumerate() {
            let (mounter, handle) = live_mounter_and_handle(target);
            let key = make_key(&format!("p{idx}"), target);
            reg.register(key, mounter, handle).expect("register");
        }
        let mut listed = reg.list();
        listed.sort_by(|a, b| a.profile.cmp(&b.profile));
        assert_eq!(listed.len(), 3);
        for (idx, key) in listed.iter().enumerate() {
            assert_eq!(key.profile, format!("p{idx}"));
            assert_eq!(key.mountpoint, PathBuf::from(targets[idx]));
        }
    }

    #[test]
    fn tear_down_idempotent_after_drop() {
        // After a successful tear_down the entry is gone, so a second
        // tear_down on the same key must report UnknownKey (matching the
        // explicit `tear_down_unknown_key_errors_with_diagnostic`
        // contract). This pins the semantics: tear_down is *not*
        // silently idempotent — repeated tear_down is a programming
        // error the caller can choose to swallow.
        let reg = MountRegistry::new();
        let target = mount_target();
        let (mounter, handle) = live_mounter_and_handle(target);
        let key = make_key("edge", target);
        reg.register(key.clone(), mounter, handle)
            .expect("register");
        reg.tear_down(&key).expect("first tear_down");
        let err = reg.tear_down(&key).unwrap_err();
        assert!(matches!(err, MountRegistryError::UnknownKey { .. }));
    }

    #[test]
    fn concurrent_register_and_tear_down() {
        use std::sync::Arc;
        use std::thread;

        let reg = Arc::new(MountRegistry::new());
        let target_root = if cfg!(windows) { "C:/mnt" } else { "/mnt" };
        let mut handles = Vec::new();
        for tid in 0..8u32 {
            let reg = Arc::clone(&reg);
            let target = format!("{target_root}/concurrent-{tid}");
            handles.push(thread::spawn(move || {
                let mut m = NullMounter::default();
                let handle = m
                    .mount(MountOpts::new(target.clone(), "/srv/data"))
                    .expect("null mount");
                let key = MountKey::new(format!("p{tid}"), PathBuf::from(&target));
                reg.register(key.clone(), Box::new(m), handle)
                    .expect("register");
                // Tear down from the same worker thread to exercise the
                // cross-thread `Send` contract on the boxed mounter.
                let h = reg.tear_down(&key).expect("tear_down");
                assert_eq!(h.mountpoint, PathBuf::from(&target));
            }));
        }
        for h in handles {
            h.join().expect("worker panic");
        }
        assert!(reg.is_empty(), "all keys cleared after worker join");
    }

    #[test]
    fn tear_down_returns_handle_metadata_for_audit() {
        let reg = MountRegistry::new();
        let target = mount_target();
        let (mounter, mut handle) = live_mounter_and_handle(target);
        handle.helper_pid = Some(4242);
        let key = make_key("edge", target);
        reg.register(key.clone(), mounter, handle)
            .expect("register");
        let returned = reg.tear_down(&key).expect("tear_down");
        assert_eq!(returned.helper_pid, Some(4242));
        assert_eq!(returned.backend(), "null");
    }
}
