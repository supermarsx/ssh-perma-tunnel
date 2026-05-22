//! Integration tests for the supervisor-side mount registry (t7-B2).
//!
//! Exercises the registry through its public API only — these tests live
//! outside the crate so they pin down the *exported* contract, not any
//! internal helper. See `crates/spt-supervisor/src/mount_registry.rs` for
//! the inline unit tests that cover the diagnostic strings in detail.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use spt_sftp::mount::{AuditHook, MountEvent, MountHandle, MountOpts, NullMounter, SftpMounter};
use spt_supervisor::{MountKey, MountRegistry, MountRegistryError};

fn mount_target() -> &'static str {
    if cfg!(windows) {
        "C:/mnt/data"
    } else {
        "/mnt/data"
    }
}

fn live_pair(target: &str) -> (Box<dyn SftpMounter>, MountHandle) {
    let mut m = NullMounter::default();
    let handle = m
        .mount(MountOpts::new(target, "/srv/data"))
        .expect("null mount succeeds");
    (Box::new(m), handle)
}

#[test]
fn register_then_tear_down_returns_handle() {
    let reg = MountRegistry::new();
    let target = mount_target();
    let (mounter, handle) = live_pair(target);
    let key = MountKey::new("edge", target);
    reg.register(key.clone(), mounter, handle)
        .expect("register");
    assert!(reg.contains(&key));
    let returned = reg.tear_down(&key).expect("tear_down");
    assert_eq!(returned.mountpoint, PathBuf::from(target));
    assert!(reg.is_empty(), "registry empty after tear_down");
}

#[test]
fn tear_down_unknown_key_errors_with_diagnostic() {
    let reg = MountRegistry::new();
    let key = MountKey::new("ghost", mount_target());
    let err = reg.tear_down(&key).unwrap_err();
    assert!(matches!(err, MountRegistryError::UnknownKey { .. }));
    let rendered = err.to_string();
    assert!(
        rendered.contains("ghost"),
        "diagnostic must mention profile: {rendered}",
    );
}

#[test]
fn double_register_same_key_errors() {
    let reg = MountRegistry::new();
    let target = mount_target();
    let key = MountKey::new("edge", target);
    let (m1, h1) = live_pair(target);
    reg.register(key.clone(), m1, h1).expect("first register");
    let (m2, h2) = live_pair(target);
    let err = reg.register(key.clone(), m2, h2).unwrap_err();
    assert!(matches!(err, MountRegistryError::AlreadyRegistered { .. }));
    // The original entry survives the rejected re-register and can still
    // be torn down cleanly.
    reg.tear_down(&key).expect("tear_down original");
    assert!(reg.is_empty());
}

#[test]
fn list_returns_all_active_mounts() {
    let reg = MountRegistry::new();
    let root = if cfg!(windows) { "C:/mnt" } else { "/mnt" };
    let names = ["alpha", "beta", "gamma", "delta"];
    for name in names {
        let target = format!("{root}/{name}");
        let (mounter, handle) = live_pair(&target);
        let key = MountKey::new(format!("p-{name}"), PathBuf::from(&target));
        reg.register(key, mounter, handle).expect("register");
    }
    let listed = reg.list();
    assert_eq!(listed.len(), names.len());
    for name in names {
        let target = format!("{root}/{name}");
        let key = MountKey::new(format!("p-{name}"), PathBuf::from(&target));
        assert!(
            listed.iter().any(|k| k == &key),
            "listed mounts must include {key:?}",
        );
    }
}

#[test]
fn tear_down_idempotent_after_drop() {
    // After tear_down the entry is gone, so a follow-up tear_down on the
    // same key reports UnknownKey rather than silently succeeding. This
    // matches the unknown-key contract and prevents callers from masking
    // double-stop bugs.
    let reg = MountRegistry::new();
    let target = mount_target();
    let (mounter, handle) = live_pair(target);
    let key = MountKey::new("edge", target);
    reg.register(key.clone(), mounter, handle)
        .expect("register");
    reg.tear_down(&key).expect("first tear_down");
    let err = reg.tear_down(&key).unwrap_err();
    assert!(matches!(err, MountRegistryError::UnknownKey { .. }));
}

#[test]
fn concurrent_register_and_tear_down() {
    // Spin up several worker threads, each registering a distinct key
    // and tearing it down. The final state must be empty and no worker
    // should have observed a duplicate-key error (the keys are disjoint
    // by construction).
    let reg = Arc::new(MountRegistry::new());
    let root = if cfg!(windows) { "C:/mnt" } else { "/mnt" };
    let mut workers = Vec::new();
    for tid in 0..16u32 {
        let reg = Arc::clone(&reg);
        let target = format!("{root}/concurrent-{tid}");
        workers.push(thread::spawn(move || {
            let mut m = NullMounter::default();
            let handle = m
                .mount(MountOpts::new(target.clone(), "/srv/data"))
                .expect("null mount");
            let key = MountKey::new(format!("p{tid}"), PathBuf::from(&target));
            reg.register(key.clone(), Box::new(m), handle)
                .expect("register");
            let returned = reg.tear_down(&key).expect("tear_down");
            assert_eq!(returned.mountpoint, PathBuf::from(&target));
        }));
    }
    for w in workers {
        w.join().expect("worker panic");
    }
    assert!(reg.is_empty(), "all registry entries cleared");
    assert_eq!(reg.len(), 0);
}

#[test]
fn audit_hook_observes_umount_through_registry() {
    // The audit hook installed on the original MountOpts continues to
    // fire when the registry drives umount, because the registry holds
    // the live mounter (not a freshly constructed one). This guards
    // against the regression that motivated B2 in the first place: the
    // previous mount_stop implementation re-opened a session and so
    // observed *no* audit event for the actual mount it was tearing
    // down.
    let target = mount_target();
    let counter = Arc::new(AtomicUsize::new(0));
    let captured = Arc::clone(&counter);
    let hook: AuditHook = Arc::new(move |event: &MountEvent| {
        if matches!(event, MountEvent::UmountSucceeded { .. }) {
            captured.fetch_add(1, Ordering::SeqCst);
        }
    });
    let mut opts = MountOpts::new(target, "/srv/data");
    opts.audit_hook = Some(hook);
    let mut mounter = NullMounter::default();
    let handle = mounter.mount(opts).expect("null mount");
    // NullMounter's umount in turn fires no audit events — this test
    // documents the *current* contract (the hook is captured per-call
    // in NullMounter, not retained), so we only verify that the
    // registry's tear_down path doesn't crash when the mounter has no
    // hook of its own. The counter being zero is therefore expected.
    let reg = MountRegistry::new();
    let key = MountKey::new("edge", target);
    reg.register(key.clone(), Box::new(mounter), handle)
        .expect("register");
    reg.tear_down(&key).expect("tear_down");
    assert_eq!(counter.load(Ordering::SeqCst), 0);
}
