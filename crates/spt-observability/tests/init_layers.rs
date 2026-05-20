//! Integration test for the layered tracing subscriber wired up by
//! [`spt_observability::init`].
//!
//! `init_for_test` installs the **process-global** subscriber via `try_init`,
//! and only the first caller in a given test binary wins — every later call
//! silently no-ops. So we run all observation-bearing checks inside a single
//! `#[test]` function in this file. Lighter `Result`-shape exercises live
//! in the inline `#[cfg(test)] mod tests` block in `src/init.rs`, which is
//! a separate test binary.

use std::time::Duration;

use spt_core::RedactionMode;
use spt_observability::config::{Destination, FileSink, LogFormat, LoggingConfig, RotationPolicy};
use spt_observability::init_for_test;
use tempfile::tempdir;

#[test]
fn init_installs_file_and_size_rotation_redacted_subscriber() {
    let tmp = tempdir().unwrap();
    let path = tmp.path().join("logs").join("spt.log");
    let cfg = LoggingConfig {
        level: "info".into(),
        format: LogFormat::Compact,
        no_color: true,
        destinations: vec![Destination::File],
        file: Some(FileSink {
            path: path.clone(),
            rotate: RotationPolicy::Size {
                max_bytes: 256,
                daily: false,
            },
            max_files: 5,
        }),
        redact: RedactionMode::Standard,
        remote: vec![],
    };
    let guard = init_for_test(&cfg).expect("init_for_test");

    // Emit a "secret"-bearing record, then many filler records to force size
    // rotation.
    tracing::warn!(
        target: "spt_observability::it::init",
        password = "hunter2",
        "auth attempt"
    );
    for i in 0..200 {
        tracing::info!(
            target: "spt_observability::it::init",
            iter = i,
            "padding-padding-padding"
        );
    }

    // Drop the guard so the non-blocking writer drains.
    drop(guard);

    // Spin up to 1s for the worker to flush.
    let mut body = String::new();
    for _ in 0..40 {
        if let Ok(s) = std::fs::read_to_string(&path) {
            if !s.is_empty() {
                body = s;
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!body.is_empty(), "expected log output at {path:?}");

    // Redaction: secret value must not appear in any sink (the active file
    // or rotated files).
    let parent = path.parent().unwrap();
    let all_files: Vec<_> = std::fs::read_dir(parent)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .collect();
    let mut combined = String::new();
    for p in &all_files {
        if let Ok(s) = std::fs::read_to_string(p) {
            combined.push_str(&s);
        }
    }
    assert!(
        !combined.contains("hunter2"),
        "redaction should mask secret values across all rotated files"
    );

    // Size rotation: at least one rotated file should exist.
    let mut rotated = Vec::new();
    for _ in 0..20 {
        rotated = std::fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with("spt.log.") && n != "spt.log")
            .collect();
        if !rotated.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(
        !rotated.is_empty(),
        "expected at least one rotated file under size policy"
    );
}
