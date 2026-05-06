//! Hosts-file apply + restore round-trip in a tempdir.

use spt_dns::{HostsEntry, HostsManager};
use tempfile::TempDir;

#[test]
fn apply_then_restore_round_trip() {
    let dir = TempDir::new().expect("tempdir");
    let target = dir.path().join("hosts");
    let original = "127.0.0.1 localhost\n# user-line\n";
    std::fs::write(&target, original).unwrap();

    let entries = vec![HostsEntry {
        address: "10.0.0.1".into(),
        names: vec!["mail.tunnel.local".into()],
    }];
    let backup_dir = dir.path().join("hosts-backups");
    let mgr = HostsManager::new(entries, &backup_dir).with_default_path(&target);

    let report = mgr.apply(Some(&target), false).expect("apply");
    assert!(report.changed);
    let after_apply = std::fs::read_to_string(&target).expect("read");
    assert!(after_apply.contains("10.0.0.1\tmail.tunnel.local"));
    assert!(after_apply.contains("localhost"));

    mgr.restore(Some(&target)).expect("restore");
    let restored = std::fs::read_to_string(&target).expect("read after restore");
    assert_eq!(restored, original);
}
