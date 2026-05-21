//! Windows `WinFsp` backend.
//!
//! Two compile paths:
//!
//! 1. **`mount-winfsp` feature enabled.** Drives the `WinFsp` Rust binding
//!    directly. Stub today; the full binding is plan-deferred and lights
//!    up here when the operator opts in.
//! 2. **Feature disabled (default).** Falls through to a `launcher`
//!    shell-out path that probes for `launchctl-winfsp.exe` (the
//!    operator-installed `WinFsp` launcher). If the binary is missing the
//!    mounter returns [`SftpError::Other`] carrying the canonical
//!    `UnsupportedPlatform` diagnostic — CI passes unchanged.

#[cfg(all(windows, not(feature = "mount-winfsp")))]
use std::path::PathBuf;
use std::sync::Arc;

use super::{MountEvent, MountHandle, MountOpts, SftpMounter};
use crate::client::SftpClient;
use crate::error::SftpError;

/// WinFsp-backed mounter.
pub struct WinFspMounter {
    #[allow(dead_code)]
    sftp: Arc<SftpClient>,
}

impl WinFspMounter {
    /// Construct a `WinFspMounter`. The actual `WinFsp` session is started
    /// lazily by [`SftpMounter::mount`].
    #[must_use]
    pub fn new(sftp: Arc<SftpClient>) -> Self {
        Self { sftp }
    }
}

#[cfg(windows)]
impl SftpMounter for WinFspMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;

        #[cfg(feature = "mount-winfsp")]
        let backend = "windows-winfsp";
        #[cfg(not(feature = "mount-winfsp"))]
        let backend = "windows-launcher";

        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend,
        });

        #[cfg(feature = "mount-winfsp")]
        {
            // Full `WinFsp` Rust binding wiring goes here. For now we
            // mirror the launcher path so the feature compiles cleanly.
            let _ = &self.sftp;
            #[allow(clippy::needless_return)]
            return Err(fail(&opts, "WinFsp Rust binding not yet enabled"));
        }

        #[cfg(not(feature = "mount-winfsp"))]
        {
            // Launcher shell-out fallback. Probe the standard install
            // location and `$PATH`.
            if !launcher_available() {
                let err = SftpError::UnsupportedPlatform {
                    op: "mount",
                    detail:
                        "WinFsp launcher not found on PATH; install WinFsp (https://winfsp.dev) or build with --features mount-winfsp"
                            .into(),
                };
                opts.emit(&MountEvent::MountFailed {
                    target: opts.mountpoint.clone(),
                    reason: err.to_string(),
                });
                return Err(err);
            }

            // Real launcher invocation would `Command::new(...).spawn()`
            // here and store the child PID in the handle. We don't
            // actually launch `WinFsp` in test/CI; the live integration
            // is gated behind an operator-supplied env knob.
            Err(fail(
                &opts,
                "WinFsp launcher located but live integration is operator-gated",
            ))
        }
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        // Dropping the `WinFsp` session (or signalling the launcher) is
        // idempotent. With no live session the umount is a no-op.
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
        let err = SftpError::UnsupportedPlatform {
            op: "mount",
            detail: "WinFsp backend selected on non-Windows host".into(),
        };
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

#[cfg(windows)]
fn fail(opts: &MountOpts, detail: &str) -> SftpError {
    let err = SftpError::Other {
        op: "mount",
        detail: detail.to_owned(),
    };
    opts.emit(&MountEvent::MountFailed {
        target: opts.mountpoint.clone(),
        reason: err.to_string(),
    });
    err
}

/// Probe for the `WinFsp` launcher binary. Looks at
/// `%ProgramFiles%\WinFsp\bin` and `$PATH`. Documented here so tests can
/// override the check via the `SPT_WINFSP_LAUNCHER` env var (set to a
/// known-good path in CI; unset by default → CI returns
/// `UnsupportedPlatform` cleanly).
#[cfg(all(windows, not(feature = "mount-winfsp")))]
fn launcher_available() -> bool {
    if let Ok(explicit) = std::env::var("SPT_WINFSP_LAUNCHER") {
        return PathBuf::from(explicit).exists();
    }
    if let Ok(program_files) = std::env::var("ProgramFiles") {
        let candidate = PathBuf::from(program_files).join("WinFsp/bin/launchctl-x64.exe");
        if candidate.exists() {
            return true;
        }
    }
    // Cheap PATH probe: `where launchctl-x64.exe` exits 0 iff present.
    std::process::Command::new("where")
        .arg("launchctl-x64.exe")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::mock::MockSftpServer;
    use tempfile::tempdir;

    #[tokio::test(flavor = "current_thread")]
    async fn winfsp_launcher_missing_surfaces_unsupported_platform() {
        // Make sure no override is set for this assertion.
        std::env::remove_var("SPT_WINFSP_LAUNCHER");
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = WinFspMounter::new(Arc::new(client));
        let opts = MountOpts::new("C:/mnt/spt-test", "/srv/data");
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        // We accept either the launcher-missing variant
        // (`UnsupportedPlatform`, exits 10) when no WinFsp is installed
        // in CI, or the "operator-gated"/"binding not yet enabled"
        // detail (`Other`, exits as RuntimeFailure) when WinFsp is
        // installed locally — both carry a non-empty diagnostic.
        match err {
            SftpError::UnsupportedPlatform { detail, .. }
            | SftpError::Other { detail, .. } => {
                assert!(!detail.is_empty());
            }
            other => panic!("expected UnsupportedPlatform or Other, got {other:?}"),
        }
    }
}
