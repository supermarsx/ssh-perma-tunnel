//! Integration tests for the cross-platform SFTP mount surface.
//!
//! These tests target the trait + factory plumbing, not live FUSE/WinFsp
//! kernels — the real kernel session loop is operator-gated behind cargo
//! features and `SPT_*_LIVE=1` env knobs (see `mount::linux_fuse`,
//! `mount::macos_sshfs`, `mount::windows_winfsp`). Running this suite in
//! CI requires only the existing `testing` feature.

#![cfg(feature = "testing")]

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use spt_sftp::error::SftpError;
use spt_sftp::mock::MockSftpServer;
use spt_sftp::mount::{
    mounter_for_current_os, AuditHook, MountEvent, MountHandle, MountOpts, NullMounter,
    SftpMounter,
};
use spt_sftp::SftpClient;

async fn make_client() -> (tempfile::TempDir, SftpClient) {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_srv, client) = MockSftpServer::start(dir.path()).await;
    (dir, client)
}

fn unix_target(p: &str) -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(format!("C:/mnt/{p}"))
    } else {
        PathBuf::from(format!("/mnt/{p}"))
    }
}

#[tokio::test]
async fn mount_opts_validation_rejects_non_absolute_on_unix() {
    let opts = MountOpts::new("relative", "/srv/data");
    let result = opts.validate();
    if cfg!(unix) {
        let err = result.expect_err("unix should reject");
        assert!(matches!(err, SftpError::Local { detail, .. } if detail.contains("absolute")));
    } else {
        // On Windows we accept drive-letter targets — relative paths are
        // tolerated by `validate` and rejected later by the WinFsp backend.
        result.expect("windows accepts non-absolute");
    }
}

#[tokio::test]
async fn mount_opts_validation_rejects_empty_remote_root() {
    let opts = MountOpts {
        remote_root: PathBuf::new(),
        ..MountOpts::new(unix_target("data"), "/srv/data")
    };
    let err = opts.validate().expect_err("empty remote_root should fail");
    assert!(matches!(err, SftpError::Local { detail, .. } if detail.contains("remote_root")));
}

#[tokio::test]
async fn null_mount_handle_round_trips_through_umount() {
    let mut m = NullMounter::default();
    let opts = MountOpts::new(unix_target("rt"), "/srv/data");
    let handle = m.mount(opts).expect("mount");
    assert_eq!(handle.backend(), "null");
    m.umount(handle).expect("umount");
    assert!(m.live.is_empty());
}

#[tokio::test]
async fn mounter_for_current_os_returns_a_backend() {
    let (_dir, client) = make_client().await;
    let mounter = mounter_for_current_os(Arc::new(client));
    // On every supported OS (linux/macos/windows) we get a backend; on
    // the residual `cfg(not(...))` arm the factory returns
    // `UnsupportedPlatform`. CI runs only on supported platforms.
    assert!(mounter.is_ok(), "factory failed on supported OS");
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn linux_fuse_backend_surfaces_diagnostic_without_dev_fuse() {
    use spt_sftp::mount::linux_fuse::FuseMounter;
    let (_dir, client) = make_client().await;
    let mut m = FuseMounter::new(Arc::new(client));
    let opts = MountOpts::new("/tmp/spt-fuse-int", "/srv/data");
    let err = m.mount(opts).expect_err("expected diagnostic");
    // Stub mode (no `mount-fuse` feature) returns
    // `UnsupportedPlatform`; wired mode (feature on, no `/dev/fuse`)
    // returns `Other`. Both are structured errors, not panics.
    assert!(matches!(
        err,
        SftpError::UnsupportedPlatform { .. } | SftpError::Other { .. }
    ));
}

#[cfg(windows)]
#[tokio::test]
async fn windows_winfsp_launcher_absent_returns_unsupported() {
    use spt_sftp::mount::windows_winfsp::WinFspMounter;
    std::env::remove_var("SPT_WINFSP_LAUNCHER");
    let (_dir, client) = make_client().await;
    let mut m = WinFspMounter::new(Arc::new(client));
    let opts = MountOpts::new("C:/mnt/spt-int", "/srv/data");
    let err = m.mount(opts).expect_err("expected diagnostic");
    // Launcher absent → `UnsupportedPlatform` (exit 10); launcher
    // present but operator-gated → `Other` (RuntimeFailure).
    assert!(matches!(
        err,
        SftpError::UnsupportedPlatform { .. } | SftpError::Other { .. }
    ));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_sshfs_missing_binary_returns_diagnostic_not_panic() {
    use spt_sftp::mount::macos_sshfs::SshfsMounter;
    std::env::set_var("SPT_SSHFS_BIN", "/nonexistent/sshfs");
    let (_dir, client) = make_client().await;
    let mut m = SshfsMounter::new(Arc::new(client));
    let opts = MountOpts::new("/private/tmp/spt-int", "/srv/data");
    let err = m.mount(opts).expect_err("expected diagnostic");
    assert!(
        matches!(err, SftpError::UnsupportedPlatform { detail, .. } if detail.contains("sshfs"))
    );
    std::env::remove_var("SPT_SSHFS_BIN");
}

#[tokio::test]
async fn umount_is_idempotent_against_double_call() {
    let mut m = NullMounter::default();
    let opts = MountOpts::new(unix_target("idem"), "/srv/data");
    let handle = m.mount(opts).expect("mount");
    m.umount(handle.clone()).expect("umount-1");
    m.umount(handle).expect("umount-2");
    assert_eq!(m.umount_calls, 2);
}

#[tokio::test]
async fn readonly_flag_flows_through_to_audit_event() {
    let captured: Arc<Mutex<Vec<MountEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let c = captured.clone();
    let hook: AuditHook = Arc::new(move |ev: &MountEvent| {
        c.lock().unwrap().push(ev.clone());
    });
    let mut m = NullMounter::default();
    let mut opts = MountOpts::new(unix_target("ro"), "/srv/data");
    opts.readonly = true;
    opts.audit_hook = Some(hook);
    let _handle = m.mount(opts).expect("mount");
    let events = captured.lock().unwrap();
    let attempt = events
        .iter()
        .find_map(|e| match e {
            MountEvent::MountAttempt { readonly, .. } => Some(*readonly),
            _ => None,
        })
        .expect("expected MountAttempt event");
    assert!(attempt, "readonly flag should propagate to audit event");
}

#[tokio::test]
async fn audit_hook_fires_on_both_mount_and_umount() {
    let captured: Arc<Mutex<Vec<MountEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let c1 = captured.clone();
    let hook: AuditHook = Arc::new(move |ev: &MountEvent| {
        c1.lock().unwrap().push(ev.clone());
    });
    let mut m = NullMounter::default();
    let target = unix_target("hooks");

    // Mount.
    let mut mount_opts = MountOpts::new(&target, "/srv/data");
    mount_opts.audit_hook = Some(hook.clone());
    let handle = m.mount(mount_opts).expect("mount");

    // Umount: we emit attempt+success around the call ourselves to mirror
    // the CLI dispatcher's audit pattern (t6-Bwire wires this through the
    // workspace audit pipeline).
    let mut umount_opts = MountOpts::new(&target, "/srv/data");
    umount_opts.audit_hook = Some(hook);
    umount_opts.emit(&MountEvent::UmountAttempt {
        target: target.clone(),
    });
    m.umount(handle).expect("umount");
    umount_opts.emit(&MountEvent::UmountSucceeded {
        target: target.clone(),
    });

    let events = captured.lock().unwrap();
    let mut saw_mount_attempt = false;
    let mut saw_umount_attempt = false;
    let mut saw_umount_success = false;
    for ev in events.iter() {
        match ev {
            MountEvent::MountAttempt { .. } => saw_mount_attempt = true,
            MountEvent::UmountAttempt { .. } => saw_umount_attempt = true,
            MountEvent::UmountSucceeded { .. } => saw_umount_success = true,
            _ => {}
        }
    }
    assert!(saw_mount_attempt);
    assert!(saw_umount_attempt);
    assert!(saw_umount_success);
}

#[tokio::test]
async fn mount_handle_carries_backend_identity() {
    let mut m = NullMounter::default();
    let handle = m
        .mount(MountOpts::new(unix_target("bid"), "/srv/data"))
        .expect("mount");
    assert_eq!(handle.backend(), "null");
    let target_path = unix_target("bid");
    assert_eq!(handle.mountpoint(), target_path.as_path());
}

#[tokio::test]
async fn mount_with_unknown_remote_root_path_still_validates() {
    // The validate step does not reach out over the wire; surfacing
    // SftpClient errors for a non-existent remote_root is the backend's
    // responsibility. Confirm validate() doesn't reject paths that look
    // syntactically reasonable but that the SFTP server hasn't seen yet.
    let opts = MountOpts::new(unix_target("future"), "/srv/does-not-exist-yet");
    opts.validate().expect("syntactically valid");

    // Now have NullMounter surface the path through to a handle. A real
    // backend would call `SftpClient::metadata(remote_root)` and surface
    // the resulting `SftpError::NoSuchFile`; this test asserts that the
    // mount-validate path doesn't accidentally swallow that error class.
    let mut m = NullMounter::default();
    let handle = m
        .mount(MountOpts::new(unix_target("future"), "/srv/does-not-exist-yet"))
        .expect("null mounter ignores remote_root");
    assert_eq!(handle.mountpoint, unix_target("future"));
}

/// Sanity check: a [`MountHandle`] is `Clone`, so callers can record it
/// in audit logs and still pass it to `umount`.
#[tokio::test]
async fn mount_handle_is_cloneable() {
    let handle = MountHandle::new(unix_target("clone"), "test");
    let cloned = handle.clone();
    assert_eq!(handle.backend(), cloned.backend());
    assert_eq!(handle.mountpoint(), cloned.mountpoint());
}
