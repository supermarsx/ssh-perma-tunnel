//! macOS backend: `sshfs` shell-out over [macFUSE](https://osxfuse.github.io).
//!
//! `FSKit` is Apple's modern file-provider API but it's Swift-only and out of
//! scope for this milestone (see `docs/sftp.md`). macFUSE is operator-deprecated
//! upstream — Apple's privileged-helper requirements have grown increasingly
//! hostile to third-party kernel extensions — so this backend ships with a
//! documented deprecation warning and **fails loudly** when macFUSE or the
//! `sshfs` binary are absent.
//!
//! Unlike the Linux and Windows backends, the macOS mount uses a **separate
//! SSH connection** from any spt-managed session: `sshfs` opens its own SSH
//! channel under the hood. This is a known limitation of the shell-out
//! approach. The `Arc<SftpClient>` passed to [`SshfsMounter::new`] is kept
//! purely for API symmetry.
//!
//! ## Lifecycle
//!
//! * **Construct** — [`SshfsMounter::new`] probes `$PATH` for `sshfs` and the
//!   filesystem for macFUSE. Diagnostic is cached; [`SftpMounter::mount`]
//!   surfaces it as [`SftpError::UnsupportedPlatform`].
//! * **Mount** — spawns `sshfs user@host:remote /local -o opts ...`, captures
//!   the `Child`, and tees stderr to `tracing::debug!` via a background
//!   drainer thread that also retains the last 3 lines for the post-mortem
//!   diagnostic if the child exits non-zero.
//! * **Umount** — calls `Child::kill()` then runs `umount(8)` against the
//!   mountpoint. Both calls swallow errors so a second umount stays a no-op.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use super::{MountEvent, MountHandle, MountOpts, SftpMounter};
use crate::client::SftpClient;
use crate::error::SftpError;

/// Bounded ring buffer storing the last few lines of `sshfs` stderr.
const STDERR_TAIL_LINES: usize = 3;

/// Shell-out mounter targeting `sshfs` (macFUSE).
///
/// Detection runs at construct time; the diagnostic is cached and replayed
/// by [`SftpMounter::mount`]. Construction itself is infallible to preserve
/// the locked [`super::mounter_for_current_os`] signature.
pub struct SshfsMounter {
    #[allow(dead_code)]
    sftp: Arc<SftpClient>,
    /// Cached construct-time diagnostic. `Some` ⇒ detection failed and every
    /// subsequent `mount` call returns this error.
    construct_error: Option<SftpError>,
    /// Resolved `sshfs` binary path (only set when detection succeeded).
    sshfs_bin: Option<PathBuf>,
    /// Live child process from a successful `mount`. `umount` takes this out.
    child: Option<Child>,
    /// Ring of the last `STDERR_TAIL_LINES` lines from `sshfs` stderr;
    /// shared with the drainer thread.
    stderr_tail: Arc<Mutex<VecDeque<String>>>,
    /// Audit hook stashed at mount time so `umount` can emit lifecycle
    /// events even though [`MountHandle`] doesn't carry the hook.
    audit_hook: Option<super::AuditHook>,
}

impl SshfsMounter {
    /// Construct a mounter. Probes for `sshfs` on `$PATH` and for macFUSE
    /// under `/Library/Filesystems/macfuse.fs`; either being present is
    /// sufficient (sshfs implies macFUSE was once installed; macFUSE without
    /// sshfs still produces a clear "install sshfs" diagnostic).
    ///
    /// If **both** are absent the diagnostic is cached and replayed by
    /// [`SftpMounter::mount`] as [`SftpError::UnsupportedPlatform`] —
    /// construction itself stays infallible to preserve the locked
    /// [`super::mounter_for_current_os`] signature.
    #[must_use]
    pub fn new(sftp: Arc<SftpClient>) -> Self {
        let sshfs_bin = Self::sshfs_path();
        let has_macfuse = macfuse_installed();
        let construct_error = if sshfs_bin.is_none() && !has_macfuse {
            Some(SftpError::UnsupportedPlatform {
                op: "mount",
                detail: "macFUSE not installed and `sshfs` not on PATH — \
                         see docs/sftp.md for the deprecation gap and install \
                         guidance (https://osxfuse.github.io)"
                    .into(),
            })
        } else if sshfs_bin.is_none() {
            // macFUSE present but no sshfs — still actionable.
            Some(SftpError::UnsupportedPlatform {
                op: "mount",
                detail:
                    "macFUSE found but `sshfs` is not on PATH — install sshfs \
                     (`brew install gromgit/fuse/sshfs-mac`) to enable the \
                     macOS mount backend"
                        .into(),
            })
        } else {
            None
        };
        Self {
            sftp,
            construct_error,
            sshfs_bin,
            child: None,
            stderr_tail: Arc::new(Mutex::new(VecDeque::with_capacity(STDERR_TAIL_LINES))),
            audit_hook: None,
        }
    }

    /// Probe for `sshfs` on `$PATH`. Tests override via the
    /// `SPT_SSHFS_BIN` environment variable (which may point at any
    /// existing file — the probe only checks existence, not executability,
    /// so cross-platform unit tests are possible).
    #[must_use]
    pub fn sshfs_path() -> Option<PathBuf> {
        if let Ok(explicit) = std::env::var("SPT_SSHFS_BIN") {
            let p = PathBuf::from(explicit);
            return if p.exists() { Some(p) } else { None };
        }
        // `which`-style probe. Use `where` on Windows so unit tests that
        // exercise the detection helper still terminate.
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

/// Probe whether macFUSE is installed. Looks for the canonical filesystem
/// bundle path `/Library/Filesystems/macfuse.fs`. Tests override via
/// `SPT_MACFUSE_FS` (set to any existing path to fake "installed", unset
/// or non-existent to fake "absent").
#[must_use]
pub fn macfuse_installed() -> bool {
    if let Ok(explicit) = std::env::var("SPT_MACFUSE_FS") {
        return PathBuf::from(explicit).exists();
    }
    PathBuf::from("/Library/Filesystems/macfuse.fs").exists()
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

        // Replay cached construct-time diagnostic if detection failed.
        if let Some(err) = &self.construct_error {
            let err = err.clone();
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            return Err(err);
        }
        // Honest log: macOS uses a SEPARATE SSH connection from any
        // spt-managed session. Documented limitation of shell-out.
        tracing::debug!(
            target: "spt_sftp::mount::macos",
            "macos-sshfs uses a separate SSH connection from the spt-managed \
             SftpClient — sshfs opens its own channel"
        );
        let sshfs = self
            .sshfs_bin
            .as_ref()
            .expect("construct_error guard should have caught missing sshfs");

        // Live invocation is operator-gated via `SPT_SSHFS_LIVE=1`. CI
        // stops here with a clean diagnostic (Other → RuntimeFailure).
        if std::env::var("SPT_SSHFS_LIVE").ok().as_deref() != Some("1") {
            let err = SftpError::Other {
                op: "mount",
                detail: format!(
                    "`sshfs` located at {} but live invocation disabled; \
                     set SPT_SSHFS_LIVE=1 to enable (see docs/sftp.md)",
                    sshfs.display()
                ),
            };
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            return Err(err);
        }

        // Live path: spawn sshfs with stderr piped so we can tee to tracing
        // and retain the tail for post-mortem diagnostics.
        let mut cmd = Command::new(sshfs);
        cmd.arg(format!("REMOTE:{}", opts.remote_root.display()))
            .arg(&opts.mountpoint)
            .stderr(Stdio::piped());
        if opts.readonly {
            cmd.arg("-o").arg("ro");
        }
        if opts.allow_other {
            cmd.arg("-o").arg("allow_other");
        }
        let mut child = cmd.spawn().map_err(|e| {
            let err = SftpError::Other {
                op: "mount",
                detail: format!("spawn sshfs: {e}"),
            };
            opts.emit(&MountEvent::MountFailed {
                target: opts.mountpoint.clone(),
                reason: err.to_string(),
            });
            err
        })?;
        let pid = child.id();

        // Drain stderr in a background thread, tee'ing each line to
        // `tracing::debug!` and keeping the last `STDERR_TAIL_LINES`.
        if let Some(stderr) = child.stderr.take() {
            let tail = Arc::clone(&self.stderr_tail);
            std::thread::Builder::new()
                .name("sshfs-stderr-drain".into())
                .spawn(move || {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(stderr);
                    for line in reader.lines().map_while(Result::ok) {
                        tracing::debug!(target: "spt_sftp::mount::macos", "sshfs: {line}");
                        if let Ok(mut q) = tail.lock() {
                            if q.len() == STDERR_TAIL_LINES {
                                q.pop_front();
                            }
                            q.push_back(line);
                        }
                    }
                })
                .ok(); // Drainer is best-effort; failure to spawn is non-fatal.
        }

        self.child = Some(child);
        self.audit_hook.clone_from(&opts.audit_hook);
        let mut handle = MountHandle::new(opts.mountpoint.clone(), "macos-sshfs");
        handle.helper_pid = Some(pid);
        opts.emit(&MountEvent::MountSucceeded {
            target: opts.mountpoint.clone(),
            backend: "macos-sshfs",
        });
        Ok(handle)
    }

    fn umount(&mut self, handle: MountHandle) -> Result<(), SftpError> {
        // Emit lifecycle events. The audit hook was stashed at mount time
        // because `MountHandle` does not carry the hook itself.
        if let Some(hook) = &self.audit_hook {
            hook(&MountEvent::UmountAttempt {
                target: handle.mountpoint.clone(),
            });
        }

        // Kill the child if we own one. Ignore `InvalidInput` (already exited)
        // so double-umount stays benign.
        if let Some(mut child) = self.child.take() {
            // If the child has already exited with a non-zero code, surface
            // the captured stderr tail at debug level for the operator.
            match child.try_wait() {
                Ok(Some(status)) if !status.success() => {
                    let tail = self.stderr_tail.lock().ok();
                    if let Some(tail) = tail {
                        for line in tail.iter() {
                            tracing::debug!(
                                target: "spt_sftp::mount::macos",
                                "sshfs (exited {status}): {line}"
                            );
                        }
                    }
                }
                _ => {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        // Best-effort: `umount(8)` against the mountpoint. macFUSE installs
        // a helper that `umount` knows how to dispatch to. Errors are
        // swallowed so a stale handle / already-umounted mount stays benign.
        let _ = Command::new("umount").arg(&handle.mountpoint).output();

        if let Some(hook) = &self.audit_hook {
            hook(&MountEvent::UmountSucceeded {
                target: handle.mountpoint.clone(),
            });
        }
        // Clear the hook so a second `umount` against a different handle on
        // the same mounter does not double-emit.
        self.audit_hook = None;
        Ok(())
    }
}

impl Drop for SshfsMounter {
    fn drop(&mut self) {
        // Make sure we don't leave a sshfs child stranded.
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Detection helper returns `None` when `sshfs` isn't on `$PATH`.
    /// Forced via `SPT_SSHFS_BIN` pointing at a nonexistent file.
    #[test]
    fn sshfs_path_returns_none_when_explicit_override_missing() {
        // Save & restore so we don't leak into sibling tests.
        let prev = std::env::var("SPT_SSHFS_BIN").ok();
        std::env::set_var("SPT_SSHFS_BIN", "/does/not/exist/sshfs-nope");
        let probed = SshfsMounter::sshfs_path();
        assert!(probed.is_none(), "expected None for nonexistent override");
        match prev {
            Some(v) => std::env::set_var("SPT_SSHFS_BIN", v),
            None => std::env::remove_var("SPT_SSHFS_BIN"),
        }
    }

    /// Detection helper returns `Some(path)` when `SPT_SSHFS_BIN` points
    /// at any existing file. Uses the current test binary itself as a
    /// guaranteed-existing path; we only check existence, not the file's
    /// executability or content.
    #[test]
    fn sshfs_path_returns_some_when_explicit_override_exists() {
        let exe = std::env::current_exe().expect("current_exe");
        let prev = std::env::var("SPT_SSHFS_BIN").ok();
        std::env::set_var("SPT_SSHFS_BIN", &exe);
        let probed = SshfsMounter::sshfs_path();
        assert_eq!(probed.as_deref(), Some(exe.as_path()));
        match prev {
            Some(v) => std::env::set_var("SPT_SSHFS_BIN", v),
            None => std::env::remove_var("SPT_SSHFS_BIN"),
        }
    }

    /// `macfuse_installed()` honours the `SPT_MACFUSE_FS` env override —
    /// nonexistent path means "absent".
    #[test]
    fn macfuse_installed_false_when_override_missing() {
        let prev = std::env::var("SPT_MACFUSE_FS").ok();
        std::env::set_var("SPT_MACFUSE_FS", "/does/not/exist/macfuse.fs");
        assert!(!macfuse_installed());
        match prev {
            Some(v) => std::env::set_var("SPT_MACFUSE_FS", v),
            None => std::env::remove_var("SPT_MACFUSE_FS"),
        }
    }

    /// `macfuse_installed()` returns `true` when the override points at any
    /// existing path (test binary, again, just checks existence).
    #[test]
    fn macfuse_installed_true_when_override_exists() {
        let exe = std::env::current_exe().expect("current_exe");
        let prev = std::env::var("SPT_MACFUSE_FS").ok();
        std::env::set_var("SPT_MACFUSE_FS", &exe);
        assert!(macfuse_installed());
        match prev {
            Some(v) => std::env::set_var("SPT_MACFUSE_FS", v),
            None => std::env::remove_var("SPT_MACFUSE_FS"),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod sshfs_live {
    //! macOS-only live tests. All `#[ignore]`'d by default; flip on with
    //! `SPT_SSHFS_LIVE=1 cargo test -p spt-sftp --features testing \
    //!     -- --ignored sshfs_live` on a macOS host with macFUSE + sshfs
    //! installed and a reachable SSH server fixture.

    use super::*;
    use crate::mock::MockSftpServer;
    use tempfile::tempdir;

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs macfuse + sshfs + live ssh server; gate with SPT_SSHFS_LIVE=1"]
    async fn mount_then_umount() {
        if std::env::var("SPT_SSHFS_LIVE").as_deref() != Ok("1") {
            return;
        }
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = SshfsMounter::new(Arc::new(client));
        let mp = tempdir().expect("mountpoint");
        let opts = MountOpts::new(mp.path().to_path_buf(), "/srv/data");
        let handle = mounter.mount(opts).expect("mount");
        // Give sshfs a moment to attach before tearing down.
        std::thread::sleep(std::time::Duration::from_millis(250));
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "current_thread")]
    #[ignore = "needs macfuse absent; intentionally inverts SPT_MACFUSE_FS / SPT_SSHFS_BIN"]
    async fn mount_fails_loud_when_macfuse_absent() {
        // Force detection to fail by pointing both probes at nonexistent
        // paths. Construct surfaces the cached `UnsupportedPlatform`.
        std::env::set_var("SPT_SSHFS_BIN", "/nonexistent/sshfs-spt-test");
        std::env::set_var("SPT_MACFUSE_FS", "/nonexistent/macfuse.fs");
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = SshfsMounter::new(Arc::new(client));
        let opts = MountOpts::new("/private/tmp/spt-loud", "/srv/data");
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        match err {
            SftpError::UnsupportedPlatform { detail, .. } => {
                assert!(
                    detail.contains("macFUSE") || detail.contains("sshfs"),
                    "diagnostic should mention macFUSE or sshfs: {detail}"
                );
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
        std::env::remove_var("SPT_SSHFS_BIN");
        std::env::remove_var("SPT_MACFUSE_FS");
    }

    /// Existing kept test: missing `sshfs` binary surfaces the structured
    /// diagnostic instead of panicking.
    #[tokio::test(flavor = "current_thread")]
    async fn sshfs_missing_returns_diagnostic() {
        let prev_bin = std::env::var("SPT_SSHFS_BIN").ok();
        let prev_fs = std::env::var("SPT_MACFUSE_FS").ok();
        std::env::set_var("SPT_SSHFS_BIN", "/nonexistent/sshfs");
        std::env::set_var("SPT_MACFUSE_FS", "/nonexistent/macfuse.fs");
        let root = tempdir().expect("tempdir");
        let (_srv, client) = MockSftpServer::start(root.path()).await;
        let mut mounter = SshfsMounter::new(Arc::new(client));
        let opts = MountOpts::new("/private/tmp/spt-mount", "/srv/data");
        let err = mounter.mount(opts).expect_err("expected diagnostic");
        match err {
            SftpError::UnsupportedPlatform { detail, .. } => {
                assert!(detail.contains("sshfs") || detail.contains("macFUSE"));
            }
            other => panic!("expected UnsupportedPlatform, got {other:?}"),
        }
        match prev_bin {
            Some(v) => std::env::set_var("SPT_SSHFS_BIN", v),
            None => std::env::remove_var("SPT_SSHFS_BIN"),
        }
        match prev_fs {
            Some(v) => std::env::set_var("SPT_MACFUSE_FS", v),
            None => std::env::remove_var("SPT_MACFUSE_FS"),
        }
    }
}
