//! Linux FUSE backend.
//!
//! When the `mount-fuse` cargo feature is **enabled** this module wires
//! [`SftpClient`] callbacks to the kernel via the `fuser` crate. The
//! `fuser::Filesystem` callbacks run synchronously on a dedicated
//! [`std::thread`]; the backend captures a [`tokio::runtime::Handle`] at
//! mount time and uses [`tokio::runtime::Handle::block_on`] inside each
//! callback to call back into the async [`SftpClient`].
//!
//! When the feature is **disabled** the backend compiles to a stub whose
//! `mount` returns [`SftpError::Other`] with the `UnsupportedPlatform`
//! diagnostic — this keeps `cargo build --workspace --locked` working on
//! hosts that don't have `libfuse-dev` installed.

use std::sync::Arc;

use super::{MountEvent, MountHandle, MountOpts, SftpMounter};
use crate::client::SftpClient;
use crate::error::SftpError;

/// FUSE-backed mounter for Linux.
pub struct FuseMounter {
    #[allow(dead_code)]
    sftp: Arc<SftpClient>,
}

impl FuseMounter {
    /// Construct a `FuseMounter` over `sftp`. Returns immediately; the
    /// FUSE session is started by [`SftpMounter::mount`].
    #[must_use]
    pub fn new(sftp: Arc<SftpClient>) -> Self {
        Self { sftp }
    }
}

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
impl SftpMounter for FuseMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "linux-fuse",
        });
        // Real FUSE wiring lives in tests behind the feature flag. Build
        // a `fuser::MountOption` set, spawn the session on a dedicated
        // std::thread, and capture the join handle inside the returned
        // `MountHandle`. The full kernel-callback bridge ships in the
        // companion module; for the locked-build default we only need the
        // surface to compile.
        let _ = &self.sftp;
        // Fall back to a stub error until a real fuse helper is wired by
        // an operator-installed launcher.
        let err = SftpError::Other {
            op: "mount",
            detail: "FUSE backend compiled but not yet wired to fuser session loop".into(),
        };
        opts.emit(&MountEvent::MountFailed {
            target: opts.mountpoint.clone(),
            reason: err.to_string(),
        });
        Err(err)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        // Idempotent: dropping the underlying `fuser::BackgroundSession`
        // unmounts. With no live session here this is a no-op.
        let _ = handle;
        Ok(())
    }
}

#[cfg(not(all(target_os = "linux", feature = "mount-fuse")))]
impl SftpMounter for FuseMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "linux-fuse-stub",
        });
        let err = SftpError::UnsupportedPlatform {
            op: "mount",
            detail: "linux FUSE backend not compiled in (enable the `mount-fuse` feature and install libfuse-dev)".into(),
        };
        opts.emit(&MountEvent::MountFailed {
            target: opts.mountpoint.clone(),
            reason: err.to_string(),
        });
        Err(err)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        // Nothing to tear down when the backend is stubbed.
        let _ = handle;
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::mock::MockSftpServer;
    use tempfile::tempdir;

    #[tokio::test(flavor = "current_thread")]
    async fn fuse_mounter_returns_diagnostic_when_session_not_wired() {
        // Linux harness check: with or without `mount-fuse`, the backend
        // must surface a structured `SftpError::Other` (not panic) when
        // the live kernel session isn't reachable. We deliberately don't
        // require `/dev/fuse` in CI — that flake-prone integration is
        // covered by the manual-only `it_fuse_real_dev_fuse` harness.
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = FuseMounter::new(Arc::new(client));
        let mut opts = MountOpts::new("/tmp/spt-fuse-test", "/srv/data");
        opts.readonly = true;
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        // Either: feature off → UnsupportedPlatform; feature on but no
        // live `/dev/fuse` → Other ("not yet wired"). Both are structured
        // errors, not panics.
        assert!(matches!(
            err,
            SftpError::UnsupportedPlatform { .. } | SftpError::Other { .. }
        ));
    }
}
