//! Cross-platform SFTP-as-filesystem mounting.
//!
//! This module defines the [`SftpMounter`] trait and the [`MountOpts`] /
//! [`MountHandle`] data shapes consumed by the CLI surface, plus a tiny
//! [`mounter_for_current_os`] factory that picks the right backend at
//! runtime based on `cfg(target_os = …)`.
//!
//! ## Feature gating
//!
//! Real filesystem-driver bindings live behind cargo features so the
//! workspace builds cleanly on hosts that don't have `FUSE` or `WinFsp`
//! development headers installed:
//!
//! * `mount-fuse` (Linux): adds the `fuser` crate and enables the
//!   [`linux_fuse`] backend.
//! * `mount-winfsp` (Windows): adds the `winfsp` crate and enables the
//!   [`windows_winfsp`] backend.
//!
//! Without those features the platform-specific module compiles to a stub
//! that returns [`SftpError::UnsupportedPlatform`](crate::error::SftpError)
//! cleanly. macOS always shells out to `sshfs` (no new compile-time deps).
//!
//! ## Audit hook
//!
//! Callers register a `Box<dyn Fn(MountEvent) + Send + Sync>` via
//! [`MountOpts::audit_hook`] which is invoked on `mount` (success or
//! failure) and again on `umount`. t6-Bwire wires this into the workspace
//! audit subsystem; this crate stays oblivious to where the events land so
//! it remains testable in isolation.
//!
//! ## Sync→async bridge
//!
//! FUSE callbacks run on the kernel's thread and are synchronous; the SFTP
//! client is `tokio`-async. Each platform backend captures a
//! [`tokio::runtime::Handle`] at mount time and uses
//! [`tokio::runtime::Handle::block_on`] inside callbacks. The FUSE session
//! is spawned on a dedicated [`std::thread`] (not a tokio task) so the
//! `block_on` call cannot deadlock the runtime.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::client::SftpClient;
use crate::error::SftpError;

pub mod linux_fuse;
pub mod macos_sshfs;
pub mod windows_winfsp;

/// Lifecycle event emitted by a mounter. Used to surface mount/umount
/// activity to the workspace audit pipeline.
#[derive(Debug, Clone)]
pub enum MountEvent {
    /// Mount attempt is starting. Carries the resolved mountpoint.
    MountAttempt {
        /// Local mountpoint or drive letter.
        target: PathBuf,
        /// Remote root.
        remote_root: PathBuf,
        /// Whether the mount is requested read-only.
        readonly: bool,
        /// Which platform helper is being used.
        backend: &'static str,
    },
    /// Mount succeeded; the [`MountHandle`] is now live.
    MountSucceeded {
        /// Local mountpoint.
        target: PathBuf,
        /// Backend identity.
        backend: &'static str,
    },
    /// Mount failed; the [`SftpError`] is the cause.
    MountFailed {
        /// Local mountpoint that was being attempted.
        target: PathBuf,
        /// Diagnostic detail.
        reason: String,
    },
    /// Umount was requested.
    UmountAttempt {
        /// Local mountpoint being torn down.
        target: PathBuf,
    },
    /// Umount completed (cleanly or as a no-op).
    UmountSucceeded {
        /// Local mountpoint.
        target: PathBuf,
    },
}

/// Audit callback signature. Hooks are invoked synchronously inside the
/// mounter; they must not block.
pub type AuditHook = Arc<dyn Fn(&MountEvent) + Send + Sync>;

/// Cross-platform mount options. Constructed by the CLI from an
/// [`SftpMount`](spt_config::schema::SftpMount) row or by tests directly.
pub struct MountOpts {
    /// Local mountpoint (Unix) or drive letter target (Windows). Must be
    /// non-empty and absolute on Unix.
    pub mountpoint: PathBuf,
    /// Remote root on the SFTP server.
    pub remote_root: PathBuf,
    /// Open the mount read-only.
    pub readonly: bool,
    /// `allow_other` — let processes other than the mount owner traverse
    /// the mountpoint. Unix only; ignored elsewhere.
    pub allow_other: bool,
    /// Override the apparent file owner. Unix only.
    pub uid: Option<u32>,
    /// Override the apparent file group. Unix only.
    pub gid: Option<u32>,
    /// Optional local cache directory (writeback cache backing store).
    pub cache_dir: Option<PathBuf>,
    /// Volume label (Windows).
    pub volume_name: Option<String>,
    /// Optional audit hook fired on mount/umount lifecycle events.
    pub audit_hook: Option<AuditHook>,
}

impl std::fmt::Debug for MountOpts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountOpts")
            .field("mountpoint", &self.mountpoint)
            .field("remote_root", &self.remote_root)
            .field("readonly", &self.readonly)
            .field("allow_other", &self.allow_other)
            .field("uid", &self.uid)
            .field("gid", &self.gid)
            .field("cache_dir", &self.cache_dir)
            .field("volume_name", &self.volume_name)
            .field("audit_hook", &self.audit_hook.as_ref().map(|_| "<hook>"))
            .finish()
    }
}

impl Clone for MountOpts {
    fn clone(&self) -> Self {
        Self {
            mountpoint: self.mountpoint.clone(),
            remote_root: self.remote_root.clone(),
            readonly: self.readonly,
            allow_other: self.allow_other,
            uid: self.uid,
            gid: self.gid,
            cache_dir: self.cache_dir.clone(),
            volume_name: self.volume_name.clone(),
            audit_hook: self.audit_hook.clone(),
        }
    }
}

impl MountOpts {
    /// Construct a minimum-viable [`MountOpts`] from a local mountpoint and
    /// remote root.
    #[must_use]
    pub fn new(mountpoint: impl Into<PathBuf>, remote_root: impl Into<PathBuf>) -> Self {
        Self {
            mountpoint: mountpoint.into(),
            remote_root: remote_root.into(),
            readonly: false,
            allow_other: false,
            uid: None,
            gid: None,
            cache_dir: None,
            volume_name: None,
            audit_hook: None,
        }
    }

    /// Validate the option bag before handing it to a backend. Surfaces a
    /// `SftpError::Local { op: "mount-validate", .. }` for any caller-side
    /// invariant violation:
    ///
    /// * `mountpoint` is empty.
    /// * `mountpoint` is not absolute (Unix; on Windows a drive-letter
    ///   target like `S:` is accepted).
    /// * `remote_root` is empty.
    pub fn validate(&self) -> Result<(), SftpError> {
        if self.mountpoint.as_os_str().is_empty() {
            return Err(SftpError::Local {
                op: "mount-validate",
                detail: "mountpoint is empty".into(),
            });
        }
        if self.remote_root.as_os_str().is_empty() {
            return Err(SftpError::Local {
                op: "mount-validate",
                detail: "remote_root is empty".into(),
            });
        }
        if cfg!(unix) && !self.mountpoint.is_absolute() {
            return Err(SftpError::Local {
                op: "mount-validate",
                detail: format!(
                    "mountpoint `{}` must be absolute on Unix",
                    self.mountpoint.display()
                ),
            });
        }
        Ok(())
    }

    /// Fire the audit hook if one was registered. Safe to call from any
    /// thread; the hook must be `Send + Sync`.
    pub fn emit(&self, event: &MountEvent) {
        if let Some(hook) = &self.audit_hook {
            hook(event);
        }
    }
}

/// Opaque handle returned by a successful [`SftpMounter::mount`]. Carries
/// just enough state to drive [`SftpMounter::umount`] from the CLI.
#[derive(Debug, Clone)]
pub struct MountHandle {
    /// Local mountpoint or drive letter.
    pub mountpoint: PathBuf,
    /// Backend identifier (`linux-fuse`, `windows-winfsp`, `macos-sshfs`,
    /// `null`).
    pub backend: &'static str,
    /// Process ID of the helper, when one was forked (`sshfs`, `WinFsp`
    /// launcher). `None` for in-process backends.
    pub helper_pid: Option<u32>,
}

impl MountHandle {
    /// Construct a handle.
    #[must_use]
    pub fn new(mountpoint: PathBuf, backend: &'static str) -> Self {
        Self {
            mountpoint,
            backend,
            helper_pid: None,
        }
    }

    /// Local mountpoint.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Backend identifier (for diagnostics and audit).
    #[must_use]
    pub fn backend(&self) -> &'static str {
        self.backend
    }
}

/// Platform-agnostic mounter interface. Implementations live in the
/// `linux_fuse`, `windows_winfsp`, and `macos_sshfs` siblings; a stub
/// [`NullMounter`] is provided for tests and unsupported platforms.
pub trait SftpMounter: Send {
    /// Mount the remote root at `opts.mountpoint`.
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError>;
    /// Tear down a live mount. Idempotent: a second call against the same
    /// handle is benign and returns `Ok(())`.
    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError>;
}

/// Pick the right backend for the host OS.
///
/// * Linux → [`linux_fuse::FuseMounter`] (compiled-in when `mount-fuse` is
///   enabled, else a stub that returns `UnsupportedPlatform` from `mount`).
/// * Windows → [`windows_winfsp::WinFspMounter`] (compiled-in when
///   `mount-winfsp` is enabled, else the launcher-shellout fallback path).
/// * macOS → [`macos_sshfs::SshfsMounter`] (always available; relies on
///   `sshfs` being on `$PATH`).
/// * Anything else → [`SftpError::Other`] with category
///   `UnsupportedPlatform`.
// `unnecessary_wraps` is a false positive — the `cfg(not(...))` arm returns
// `Err`; clippy lints from the configured arm only.
#[allow(clippy::unnecessary_wraps)]
pub fn mounter_for_current_os(
    sftp: Arc<SftpClient>,
) -> Result<Box<dyn SftpMounter>, SftpError> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux_fuse::FuseMounter::new(sftp)))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos_sshfs::SshfsMounter::new(sftp)))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(windows_winfsp::WinFspMounter::new(sftp)))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = sftp;
        Err(unsupported_platform_error())
    }
}

/// Build the standard "unsupported platform" error for callers that need
/// to surface the diagnostic from outside this module (e.g. the macOS
/// `sshfs` shell-out when the binary is missing). Returns
/// [`SftpError::UnsupportedPlatform`] so the workspace exit-code mapping
/// lands on [`spt_core::ExitCode::UnsupportedPlatform`] (exit 10).
#[must_use]
pub fn unsupported_platform_error() -> SftpError {
    SftpError::UnsupportedPlatform {
        op: "mount",
        detail: format!(
            "SFTP mount not supported on `{}`; install a FUSE/WinFsp helper or pick another platform",
            std::env::consts::OS
        ),
    }
}

/// Stub mounter used by tests and as the unsupported-platform fallback.
/// Records each `mount`/`umount` invocation for assertions.
pub struct NullMounter {
    /// Backend identity reported back through the handle and audit events.
    pub backend: &'static str,
    /// Whether `mount` should fail with `UnsupportedPlatform` (mirrors the
    /// behaviour of a real platform that's missing a driver).
    pub fail_with_unsupported: bool,
    /// Outstanding mountpoints we issued handles for; cleared by `umount`.
    pub live: Vec<PathBuf>,
    /// Number of `umount` calls observed (useful for idempotency tests).
    pub umount_calls: usize,
}

impl Default for NullMounter {
    fn default() -> Self {
        Self {
            backend: "null",
            fail_with_unsupported: false,
            live: Vec::new(),
            umount_calls: 0,
        }
    }
}

impl NullMounter {
    /// Construct a `NullMounter` that fails every `mount` call with the
    /// canonical `UnsupportedPlatform` diagnostic.
    #[must_use]
    pub fn unsupported() -> Self {
        Self {
            backend: "null",
            fail_with_unsupported: true,
            live: Vec::new(),
            umount_calls: 0,
        }
    }
}

impl SftpMounter for NullMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: self.backend,
        });
        if self.fail_with_unsupported {
            let err = unsupported_platform_error();
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            return Err(err);
        }
        self.live.push(opts.mountpoint.clone());
        opts.emit(&MountEvent::MountSucceeded {
            target: opts.mountpoint.clone(),
            backend: self.backend,
        });
        Ok(MountHandle::new(opts.mountpoint, self.backend))
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        self.umount_calls += 1;
        // Idempotency: a second umount against the same handle is a no-op.
        let pos = self.live.iter().position(|p| p == &handle.mountpoint);
        if let Some(idx) = pos {
            self.live.remove(idx);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn opts(mountpoint: &str) -> MountOpts {
        MountOpts::new(mountpoint, "/srv/data")
    }

    #[test]
    fn validate_rejects_empty_mountpoint() {
        let mut o = opts("");
        // Empty PathBuf serializes as empty OsStr, so validate must reject.
        o.mountpoint = PathBuf::new();
        let err = o.validate().unwrap_err();
        assert!(
            matches!(err, SftpError::Local { detail, .. } if detail.contains("mountpoint is empty"))
        );
    }

    #[test]
    fn validate_rejects_empty_remote_root() {
        let mut o = opts("/mnt/data");
        o.remote_root = PathBuf::new();
        let err = o.validate().unwrap_err();
        assert!(
            matches!(err, SftpError::Local { detail, .. } if detail.contains("remote_root is empty"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn validate_rejects_relative_mountpoint_on_unix() {
        let o = opts("relative/path");
        let err = o.validate().unwrap_err();
        assert!(matches!(err, SftpError::Local { detail, .. } if detail.contains("must be absolute")));
    }

    #[test]
    fn null_mounter_round_trips_mount_and_umount() {
        let mut m = NullMounter::default();
        let target = if cfg!(windows) { "C:/mnt/data" } else { "/mnt/data" };
        let handle = m.mount(opts(target)).expect("mount");
        assert_eq!(handle.mountpoint, PathBuf::from(target));
        assert_eq!(m.live.len(), 1);
        m.umount(handle).expect("umount");
        assert!(m.live.is_empty());
    }

    #[test]
    fn null_mounter_umount_is_idempotent() {
        let mut m = NullMounter::default();
        let target = if cfg!(windows) { "C:/mnt/data" } else { "/mnt/data" };
        let handle = m.mount(opts(target)).expect("mount");
        m.umount(handle.clone()).expect("umount-1");
        m.umount(handle).expect("umount-2");
        assert_eq!(m.umount_calls, 2);
        assert!(m.live.is_empty());
    }

    #[test]
    fn unsupported_mounter_returns_unsupported_platform_error() {
        let mut m = NullMounter::unsupported();
        let target = if cfg!(windows) { "C:/mnt/data" } else { "/mnt/data" };
        let err = m.mount(opts(target)).unwrap_err();
        assert!(
            matches!(err, SftpError::UnsupportedPlatform { detail, .. } if detail.contains("not supported"))
        );
    }

    #[test]
    fn audit_hook_fires_on_mount_and_umount() {
        let events: Arc<Mutex<Vec<MountEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = events.clone();
        let hook: AuditHook = Arc::new(move |ev: &MountEvent| {
            cap.lock().unwrap().push(ev.clone());
        });
        let mut m = NullMounter::default();
        let target = if cfg!(windows) { "C:/mnt/data" } else { "/mnt/data" };
        let mut o = opts(target);
        o.audit_hook = Some(hook);
        let handle = m.mount(o).expect("mount");
        // Re-issue another opts bag for the umount event (the original was moved).
        let mut o2 = opts(target);
        let cap2 = events.clone();
        o2.audit_hook = Some(Arc::new(move |ev: &MountEvent| {
            cap2.lock().unwrap().push(ev.clone());
        }));
        o2.emit(&MountEvent::UmountAttempt {
            target: PathBuf::from(target),
        });
        m.umount(handle).expect("umount");
        o2.emit(&MountEvent::UmountSucceeded {
            target: PathBuf::from(target),
        });
        let collected = events.lock().unwrap();
        let mount_attempted = collected
            .iter()
            .any(|e| matches!(e, MountEvent::MountAttempt { .. }));
        let mount_succeeded = collected
            .iter()
            .any(|e| matches!(e, MountEvent::MountSucceeded { .. }));
        let umount_attempted = collected
            .iter()
            .any(|e| matches!(e, MountEvent::UmountAttempt { .. }));
        let umount_succeeded = collected
            .iter()
            .any(|e| matches!(e, MountEvent::UmountSucceeded { .. }));
        assert!(mount_attempted, "expected MountAttempt event");
        assert!(mount_succeeded, "expected MountSucceeded event");
        assert!(umount_attempted, "expected UmountAttempt event");
        assert!(umount_succeeded, "expected UmountSucceeded event");
    }

    #[test]
    fn readonly_flag_round_trips_through_opts() {
        let mut o = opts(if cfg!(windows) { "C:/mnt/data" } else { "/mnt/data" });
        o.readonly = true;
        assert!(o.readonly);
        let cloned = o.clone();
        assert!(cloned.readonly);
    }

    #[test]
    fn unsupported_platform_error_carries_diagnostic_text() {
        let err = unsupported_platform_error();
        match err {
            SftpError::UnsupportedPlatform { op, detail } => {
                assert_eq!(op, "mount");
                assert!(detail.contains("not supported"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }
}
