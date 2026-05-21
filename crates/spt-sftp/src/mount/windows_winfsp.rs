//! Windows `WinFsp` backend.
//!
//! ## Status (t7-A6)
//!
//! The operator chose the **in-process `winfsp` Rust binding** path (not a
//! launcher shell-out). The intended binding is
//! [`winfsp = "=0.10"`](https://crates.io/crates/winfsp/0.10.0). That crate
//! is **GPL-3.0** and the workspace's `deny.toml` allow-list does not
//! include GPL-3.0, so `cargo deny check` would reject the dependency on
//! introduction. This is a workspace-policy gap, not a Rust API gap.
//!
//! Per the t7-A6 spec fallback clause ("If the binding fails to compile
//! under MSRV 1.85 or is API-incompatible, document the gap and ship the
//! `unsupported_platform_error()` stub with a stable diagnostic — DO NOT
//! switch to launcher shell-out"), this module ships:
//!
//! * A [`WinFspMounter`] whose `mount` always returns
//!   [`SftpError::UnsupportedPlatform`] with a diagnostic that names the
//!   GPL-3.0 / `deny.toml` blocker so the next executor can act.
//! * A `mount-winfsp` cargo feature that remains declared (no-op) so config
//!   surfaces, CLI flags, and packaging recipes that reference it keep
//!   compiling without churn. Enabling the feature does not add the
//!   `winfsp` crate — that's gated on a `deny.toml` exception landing.
//!
//! When `deny.toml` gains a GPL-3.0 exception (or an MIT/Apache fork of the
//! binding becomes available), this module's `cfg(feature = "mount-winfsp")`
//! arm will swap in the real `FileSystemHost` + `FileSystemContext` impl
//! that mirrors A5's `FuseFs` shape (path↔inode bimap, attr TTL cache,
//! handle table, tokio-runtime block-on bridge). The CI gate for those
//! live tests would be:
//!
//! ```text
//! choco install winfsp -y
//! $env:SPT_WINFSP_LIVE = '1'
//! cargo test -p spt-sftp --locked --features testing,mount-winfsp \
//!     -- --ignored winfsp_live
//! ```
//!
//! See `.orchestration/logs/t7-A6.md` for the full rationale and the
//! follow-up checklist.

use std::sync::Arc;

use super::{MountEvent, MountHandle, MountOpts, SftpMounter};
#[cfg(not(windows))]
use super::unsupported_platform_error;
use crate::client::SftpClient;
use crate::error::SftpError;

/// WinFsp-backed mounter.
///
/// Today this is a thin stub: see the module docs for the GPL-3.0
/// `deny.toml` blocker that prevents wiring the `winfsp` Rust binding.
/// Construction is infallible so callers can plumb the mounter through
/// the CLI dispatch surface unchanged; the [`SftpMounter::mount`] call is
/// where the diagnostic surfaces.
pub struct WinFspMounter {
    #[allow(dead_code)]
    sftp: Arc<SftpClient>,
}

impl WinFspMounter {
    /// Construct a `WinFspMounter`. The actual `WinFsp` session would be
    /// started lazily by [`SftpMounter::mount`]; under the current fallback
    /// arrangement `mount` returns
    /// [`SftpError::UnsupportedPlatform`](crate::error::SftpError) with a
    /// diagnostic naming the workspace-policy gap.
    #[must_use]
    pub fn new(sftp: Arc<SftpClient>) -> Self {
        Self { sftp }
    }
}

#[cfg(windows)]
impl SftpMounter for WinFspMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;

        // Backend tag flips based on the feature so audit consumers can
        // distinguish the "operator opted in but binding not buildable"
        // case from the "feature disabled" case.
        #[cfg(feature = "mount-winfsp")]
        let backend: &'static str = "windows-winfsp-blocked";
        #[cfg(not(feature = "mount-winfsp"))]
        let backend: &'static str = "windows-winfsp-stub";

        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend,
        });

        // Both feature arms collapse to the same diagnostic: the `winfsp`
        // 0.10 Rust binding cannot be added to the workspace until
        // `deny.toml` accepts GPL-3.0 (or a non-GPL fork lands). The
        // diagnostic names the gap explicitly so the next executor can act.
        let detail = winfsp_blocked_diagnostic();
        let err = SftpError::UnsupportedPlatform {
            op: "mount",
            detail,
        };
        opts.emit(&MountEvent::MountFailed {
            target: opts.mountpoint.clone(),
            reason: err.to_string(),
        });
        Err(err)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        // No live session is ever constructed under the fallback, so
        // umount is a no-op. Idempotent by definition.
        let _ = handle;
        Ok(())
    }
}

#[cfg(not(windows))]
impl SftpMounter for WinFspMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "windows-winfsp-stub",
        });
        let err = unsupported_platform_error();
        opts.emit(&MountEvent::MountFailed {
            target: opts.mountpoint.clone(),
            reason: err.to_string(),
        });
        Err(err)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        let _ = handle;
        Ok(())
    }
}

/// Build the diagnostic string surfaced when the `WinFsp` backend is
/// asked to mount under the current fallback. Centralised so tests can
/// pin the substring (`"GPL-3.0"`) without scraping the audit pipeline.
#[cfg(windows)]
fn winfsp_blocked_diagnostic() -> String {
    "WinFsp Rust binding (winfsp 0.10) is GPL-3.0; workspace license policy \
     in deny.toml does not allow GPL-3.0. Add an exception to deny.toml or \
     adopt a non-GPL fork to unblock. See .orchestration/logs/t7-A6.md."
        .to_string()
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::mock::MockSftpServer;
    use tempfile::tempdir;

    #[tokio::test(flavor = "current_thread")]
    async fn winfsp_mount_surfaces_unsupported_platform_with_named_blocker() {
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = WinFspMounter::new(Arc::new(client));
        let opts = MountOpts::new("C:/mnt/spt-test", "/srv/data");
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        match err {
            SftpError::UnsupportedPlatform { op, detail } => {
                assert_eq!(op, "mount");
                // The diagnostic must name the blocker so a future
                // executor can search for it.
                assert!(
                    detail.contains("GPL-3.0"),
                    "diagnostic should name the licence blocker: {detail}"
                );
                assert!(
                    detail.contains("deny.toml"),
                    "diagnostic should name the policy file: {detail}"
                );
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn winfsp_umount_is_idempotent_no_op() {
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = WinFspMounter::new(Arc::new(client));
        let handle = MountHandle::new("C:/mnt/spt-test".into(), "windows-winfsp-stub");
        // Two umount calls are both `Ok(())` and the second mirrors the
        // first — there's never a live session to tear down.
        mounter.umount(handle.clone()).expect("umount-1");
        mounter.umount(handle).expect("umount-2");
    }
}
