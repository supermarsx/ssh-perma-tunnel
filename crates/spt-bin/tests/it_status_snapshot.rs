//! `StatusWriter` writes a well-formed `status.json` after `flush()`.

use spt_state::{paths, StatusWriter, StatusWriterConfig};
use std::time::Duration;
use tempfile::TempDir;

#[tokio::test]
async fn flush_writes_well_formed_status_json() {
    let dir = TempDir::new().expect("tempdir");
    let cfg = StatusWriterConfig {
        interval: Duration::from_millis(50),
        ring_size: 0,
    };
    let w = StatusWriter::new(dir.path().to_path_buf(), cfg);
    w.update(|s| {
        s.pid = std::process::id();
        s.version = "test-0".into();
        s.config_fingerprint_sha256 =
            "0000000000000000000000000000000000000000000000000000000000000000".into();
    })
    .await;
    w.flush().await.expect("flush");

    let path = paths::status_path(dir.path());
    let raw = std::fs::read_to_string(&path).expect("read status");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
    assert!(v.get("pid").is_some());
    assert_eq!(v["version"], "test-0");
    assert!(v.get("config_fingerprint_sha256").is_some());
    assert!(v.get("profiles").is_some());
}
