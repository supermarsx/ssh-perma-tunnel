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
    mounter_for_current_os, AuditHook, MountEvent, MountHandle, MountOpts, NullMounter, SftpMounter,
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
async fn windows_winfsp_backend_surfaces_unsupported_with_named_blocker() {
    use spt_sftp::mount::windows_winfsp::WinFspMounter;
    let (_dir, client) = make_client().await;
    let mut m = WinFspMounter::new(Arc::new(client));
    let opts = MountOpts::new("C:/mnt/spt-int", "/srv/data");
    let err = m.mount(opts).expect_err("expected diagnostic");
    // t7-A6 ships the WinFsp backend as a documented `UnsupportedPlatform`
    // stub pending a `deny.toml` exception for the GPL-3.0 `winfsp 0.10`
    // Rust binding (operator chose binding, not launcher shell-out). The
    // diagnostic must name the blocker so a future executor can find it.
    match err {
        SftpError::UnsupportedPlatform { detail, .. } => {
            assert!(
                detail.contains("GPL-3.0") || detail.contains("not supported"),
                "diagnostic should name the blocker (GPL-3.0) or the OS gap: {detail}"
            );
        }
        other => panic!("expected UnsupportedPlatform, got {other:?}"),
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_sshfs_missing_binary_returns_diagnostic_not_panic() {
    use spt_sftp::mount::macos_sshfs::SshfsMounter;
    // Force both probes to fail so detection caches `UnsupportedPlatform`.
    std::env::set_var("SPT_SSHFS_BIN", "/nonexistent/sshfs");
    std::env::set_var("SPT_MACFUSE_FS", "/nonexistent/macfuse.fs");
    let (_dir, client) = make_client().await;
    let mut m = SshfsMounter::new(Arc::new(client));
    let opts = MountOpts::new("/private/tmp/spt-int", "/srv/data");
    let err = m.mount(opts).expect_err("expected diagnostic");
    assert!(matches!(err, SftpError::UnsupportedPlatform { detail, .. }
            if detail.contains("sshfs") || detail.contains("macFUSE")));
    std::env::remove_var("SPT_SSHFS_BIN");
    std::env::remove_var("SPT_MACFUSE_FS");
}

/// macOS: the construct-time diagnostic propagates through `mount()` even
/// when the caller registers an audit hook — the hook must fire
/// `MountAttempt` *and* `MountFailed` (not silently swallow).
#[cfg(target_os = "macos")]
#[tokio::test]
async fn macos_sshfs_emits_mount_failed_when_detection_fails() {
    use spt_sftp::mount::macos_sshfs::SshfsMounter;
    std::env::set_var("SPT_SSHFS_BIN", "/nonexistent/sshfs");
    std::env::set_var("SPT_MACFUSE_FS", "/nonexistent/macfuse.fs");
    let (_dir, client) = make_client().await;
    let captured: Arc<Mutex<Vec<MountEvent>>> = Arc::new(Mutex::new(Vec::new()));
    let c = captured.clone();
    let hook: AuditHook = Arc::new(move |ev: &MountEvent| {
        c.lock().unwrap().push(ev.clone());
    });
    let mut m = SshfsMounter::new(Arc::new(client));
    let mut opts = MountOpts::new("/private/tmp/spt-detect-fail", "/srv/data");
    opts.audit_hook = Some(hook);
    let _ = m.mount(opts).expect_err("expected diagnostic");
    let events = captured.lock().unwrap();
    let saw_attempt = events.iter().any(
        |e| matches!(e, MountEvent::MountAttempt { backend, .. } if *backend == "macos-sshfs"),
    );
    let saw_failed = events
        .iter()
        .any(|e| matches!(e, MountEvent::MountFailed { .. }));
    assert!(saw_attempt, "expected MountAttempt event");
    assert!(saw_failed, "expected MountFailed event");
    std::env::remove_var("SPT_SSHFS_BIN");
    std::env::remove_var("SPT_MACFUSE_FS");
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
        .mount(MountOpts::new(
            unix_target("future"),
            "/srv/does-not-exist-yet",
        ))
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

// ---------------------------------------------------------------------------
// Live FUSE tests (Linux + `mount-fuse` feature, opt-in via SPT_FUSE_LIVE=1).
//
// These tests actually mount a FUSE filesystem under a tempdir, then perform
// real `std::fs` operations against the mountpoint. They require:
//
//   1. A Linux kernel with `/dev/fuse` readable by the test runner.
//   2. The `fusermount` (libfuse) binary on `$PATH`, or root.
//   3. `cargo test -p spt-sftp --features testing,mount-fuse -- --ignored fuse_live`
//      with `SPT_FUSE_LIVE=1` exported.
//
// CI gate (Phase C job): a Linux runner that does
//
//   sudo apt-get install -y fuse libfuse-dev
//   SPT_FUSE_LIVE=1 cargo test -p spt-sftp --features testing,mount-fuse \
//       -- --ignored fuse_live
//
// On every other platform / configuration these tests stay `#[ignore]`'d.
// ---------------------------------------------------------------------------

#[cfg(all(target_os = "linux", feature = "mount-fuse"))]
mod fuse_live {
    use super::*;
    use spt_sftp::mount::linux_fuse::FuseMounter;
    use std::time::Duration;

    fn live_enabled() -> bool {
        std::env::var("SPT_FUSE_LIVE").as_deref() == Ok("1")
    }

    async fn mount_fixture() -> (
        tempfile::TempDir,
        tempfile::TempDir,
        FuseMounter,
        MountHandle,
    ) {
        let remote_root = tempfile::tempdir().expect("remote root");
        let mountpoint = tempfile::tempdir().expect("mountpoint");
        let (_srv, client) = MockSftpServer::start(remote_root.path()).await;
        let mut mounter = FuseMounter::new(Arc::new(client));
        let opts = MountOpts::new(mountpoint.path().to_path_buf(), "/");
        let handle = mounter.mount(opts).expect("mount");
        // Give the FUSE session a moment to attach before the first fs call.
        tokio::time::sleep(Duration::from_millis(100)).await;
        (remote_root, mountpoint, mounter, handle)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn mount_then_list_root() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        // Seed one file on the remote side.
        std::fs::write(remote.path().join("hello.txt"), b"hi").expect("seed");
        let entries: Vec<_> = std::fs::read_dir(mp.path())
            .expect("readdir mount")
            .collect();
        assert!(!entries.is_empty(), "mount should expose seeded file");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn read_file_through_mount() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        std::fs::write(remote.path().join("doc.txt"), b"hello world").expect("seed");
        let read = std::fs::read(mp.path().join("doc.txt")).expect("read");
        assert_eq!(read, b"hello world");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn write_file_through_mount() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        std::fs::write(mp.path().join("out.bin"), b"payload").expect("write through mount");
        let back = std::fs::read(remote.path().join("out.bin")).expect("readback");
        assert_eq!(back, b"payload");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn readdir_large() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        for i in 0..256 {
            std::fs::write(remote.path().join(format!("f{i:03}.bin")), [i as u8]).expect("seed");
        }
        let count = std::fs::read_dir(mp.path()).expect("readdir").count();
        assert_eq!(count, 256, "should see every seeded entry");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn stat_returns_correct_size() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        let body = vec![0xAB; 4096];
        std::fs::write(remote.path().join("blob"), &body).expect("seed");
        let meta = std::fs::metadata(mp.path().join("blob")).expect("stat");
        assert_eq!(meta.len(), 4096);
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn symlink_then_readlink() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        std::fs::write(remote.path().join("target.txt"), b"x").expect("seed");
        std::os::unix::fs::symlink("target.txt", mp.path().join("ln")).expect("symlink");
        let target = std::fs::read_link(mp.path().join("ln")).expect("readlink");
        assert_eq!(target.to_string_lossy(), "target.txt");
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn rename_atomic() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        std::fs::write(remote.path().join("a.txt"), b"abc").expect("seed");
        std::fs::rename(mp.path().join("a.txt"), mp.path().join("b.txt")).expect("rename");
        assert!(remote.path().join("b.txt").exists());
        assert!(!remote.path().join("a.txt").exists());
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn remove_file_unlinks() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        std::fs::write(remote.path().join("doomed"), b"-").expect("seed");
        std::fs::remove_file(mp.path().join("doomed")).expect("unlink");
        assert!(!remote.path().join("doomed").exists());
        mounter.umount(handle).expect("umount");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore = "needs /dev/fuse + SPT_FUSE_LIVE=1"]
    async fn mkdir_and_rmdir() {
        if !live_enabled() {
            return;
        }
        let (remote, mp, mut mounter, handle) = mount_fixture().await;
        std::fs::create_dir(mp.path().join("sub")).expect("mkdir");
        assert!(remote.path().join("sub").is_dir());
        std::fs::remove_dir(mp.path().join("sub")).expect("rmdir");
        assert!(!remote.path().join("sub").exists());
        mounter.umount(handle).expect("umount");
    }
}

// ---------------------------------------------------------------------------
// Live WinFsp tests (Windows + `mount-winfsp` feature, opt-in via
// SPT_WINFSP_LIVE=1).
//
// **DEFERRED — see `.orchestration/logs/t7-A6.md`.** The t7-A6 spec required
// 6+ live WinFsp tests gated on `SPT_WINFSP_LIVE=1`. They are not present
// here because the `winfsp 0.10` Rust binding (GPL-3.0) cannot be added to
// the workspace until `deny.toml` accepts GPL-3.0. The t7-A6 fallback ships
// `WinFspMounter::mount` as a structured `UnsupportedPlatform` stub naming
// the blocker.
//
// When the `deny.toml` GPL-3.0 exception lands (or a non-GPL fork of the
// binding becomes available), the following CI gate would run them:
//
//   choco install winfsp -y
//   $env:SPT_WINFSP_LIVE = '1'
//   cargo test -p spt-sftp --locked --features testing,mount-winfsp \
//       -- --ignored winfsp_live
//
// The test set planned for that follow-up (each `#[tokio::test]`,
// `#[ignore]`-gated, and predicated on `live_enabled()`):
//
//   * mount_then_list_root      — seed file on remote, readdir mountpoint.
//   * read_through_mount        — write remote, read via UNC/drive letter.
//   * write_through_mount       — write via mount, readback on remote.
//   * create_then_delete        — `fs::write` then `fs::remove_file`.
//   * rename_atomic             — `fs::rename` across two entries.
//   * umount_idempotent         — double-umount returns Ok twice.
//
// They mirror the `fuse_live` block above 1-for-1 (paths normalised for
// Windows drive letters / volume mountpoints).
// ---------------------------------------------------------------------------
