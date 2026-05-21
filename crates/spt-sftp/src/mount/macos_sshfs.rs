//! macOS backend: `sshfs` shell-out.
//!
//! `FSKit` is the future-facing macOS file-provider API but it's Swift-only
//! and MSRV-incompatible with the workspace (plan §"Out of scope"). This
//! backend invokes [`macFUSE`](https://osxfuse.github.io) via the
//! `sshfs` binary and returns the child PID inside the [`MountHandle`].
//!
//! If `sshfs` is missing from `$PATH` the mounter returns a structured
//! diagnostic error rather than panicking — operators see a non-zero
//! exit code with actionable text.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use super::{MountEvent, MountHandle, MountOpts, SftpMounter};
use crate::client::SftpClient;
use crate::error::SftpError;

/// Shell-out mounter targeting `sshfs` (macFUSE).
pub struct SshfsMounter {
    #[allow(dead_code)]
    sftp: Arc<SftpClient>,
}

impl SshfsMounter {
    /// Construct a mounter. `sftp` is kept for symmetry with the other
    /// backends — `sshfs` opens its own SSH connection, so we don't drive
    /// the in-process client from this code path.
    #[must_use]
    pub fn new(sftp: Arc<SftpClient>) -> Self {
        Self { sftp }
    }

    /// Probe for `sshfs` on `$PATH`. Tests override via the
    /// `SPT_SSHFS_BIN` environment variable.
    #[must_use]
    pub fn sshfs_path() -> Option<PathBuf> {
        if let Ok(explicit) = std::env::var("SPT_SSHFS_BIN") {
            let p = PathBuf::from(explicit);
            return if p.exists() { Some(p) } else { None };
        }
        // `which`-style probe.
        let probe = if cfg!(windows) { "where" } else { "which" };
        let output = Command::new(probe).arg("sshfs").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&output.stdout);
        let first = s.lines().next()?.trim();
        if first.is_empty() {
            None
        } else {
            Some(PathBuf::from(first))
        }
    }
}

impl SftpMounter for SshfsMounter {
    fn mount(&mut self, opts: MountOpts) -> Result<MountHandle, SftpError> {
        opts.validate()?;
        opts.emit(&MountEvent::MountAttempt {
            target: opts.mountpoint.clone(),
            remote_root: opts.remote_root.clone(),
            readonly: opts.readonly,
            backend: "macos-sshfs",
        });
        let Some(sshfs) = Self::sshfs_path() else {
            let err = SftpError::UnsupportedPlatform {
                op: "mount",
                detail:
                    "`sshfs` not found on PATH; install macFUSE + sshfs (https://osxfuse.github.io)"
                        .into(),
            };
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            return Err(err);
        };
        // We don't actually invoke sshfs in unit tests — that would open
        // a real SSH connection. Live invocation is operator-gated via
        // `SPT_SSHFS_LIVE=1`; in CI the path stops here with a clean
        // diagnostic.
        if std::env::var("SPT_SSHFS_LIVE").ok().as_deref() != Some("1") {
            let err = SftpError::Other {
                op: "mount",
                detail: format!(
                    "`sshfs` located at {} but live invocation disabled; set SPT_SSHFS_LIVE=1 to enable",
                    sshfs.display()
                ),
            };
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            return Err(err);
        }
        // Live path: spawn sshfs and capture the PID. Unreachable in CI.
        let mut cmd = Command::new(&sshfs);
        cmd.arg(format!("REMOTE:{}", opts.remote_root.display()))
            .arg(&opts.mountpoint);
        if opts.readonly {
            cmd.arg("-o").arg("ro");
        }
        if opts.allow_other {
            cmd.arg("-o").arg("allow_other");
        }
        let child = cmd.spawn().map_err(|e| SftpError::Other {
            op: "mount",
            detail: format!("spawn sshfs: {e}"),
        })?;
        let pid = child.id();
        let mut handle = MountHandle::new(opts.mountpoint.clone(), "macos-sshfs");
        handle.helper_pid = Some(pid);
        opts.emit(&MountEvent::MountSucceeded {
            target: opts.mountpoint.clone(),
            backend: "macos-sshfs",
        });
        Ok(handle)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        // Best-effort: run `umount <mountpoint>`. Ignore errors so a
        // double-umount stays benign.
        let _ = Command::new("umount").arg(&handle.mountpoint).output();
        Ok(())
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use crate::mock::MockSftpServer;
    use tempfile::tempdir;

    #[tokio::test(flavor = "current_thread")]
    async fn sshfs_missing_returns_diagnostic() {
        // Force the probe to fail by pointing at a path that doesn't exist.
        std::env::set_var("SPT_SSHFS_BIN", "/nonexistent/sshfs");
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = SshfsMounter::new(Arc::new(client));
        let opts = MountOpts::new("/private/tmp/spt-mount", "/srv/data");
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        match err {
            SftpError::UnsupportedPlatform { detail, .. } => assert!(detail.contains("sshfs")),
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
        std::env::remove_var("SPT_SSHFS_BIN");
    }
}
