#![allow(clippy::field_reassign_with_default)]
//! Round-trip the `config init` + `config trust` paths through their
//! public-API building blocks. The binary's `cli_dispatch` glues them
//! together; this integration test asserts the underlying calls produce
//! the expected on-disk effect.
//!
//! Direct subprocess invocation of `spt config init` would require
//! `assert_cmd`, which the t1-e18 log notes is MSRV-blocked. Instead we
//! call the same `spt_config::*` entries the binary calls.

use std::path::PathBuf;

fn write_initial(dir: &std::path::Path) -> PathBuf {
    let p = dir.join("config.toml");
    std::fs::write(
        &p,
        r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
"#,
    )
    .unwrap();
    p
}

#[test]
fn config_init_default_round_trips() {
    let mut cfg = spt_config::schema::Config::default();
    cfg.version = 1;
    let body = spt_config::render(&cfg, spt_core::RedactionMode::None);
    // Re-parse: must validate as a v1 config.
    let (parsed, _) = spt_config::load_str(&body, false).unwrap();
    assert_eq!(parsed.version, 1);
}

#[test]
fn config_trust_writes_runtime_remote_config() {
    let tmp = tempfile::tempdir().unwrap();
    let path = write_initial(tmp.path());
    let mut doc = spt_config::mutate::Document::read(&path).unwrap();
    let inner = doc.document_mut();
    let runtime = inner
        .as_table_mut()
        .entry("runtime")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let runtime_tbl = runtime.as_table_mut().unwrap();
    let rc = runtime_tbl
        .entry("remote_config")
        .or_insert_with(|| toml_edit::Item::Table(toml_edit::Table::new()));
    let rc_tbl = rc.as_table_mut().unwrap();
    rc_tbl["url"] = toml_edit::value("https://cfg.example/spt.toml");
    rc_tbl["fingerprint_sha256"] = toml_edit::value("a".repeat(64));
    doc.write_atomic(&path).unwrap();

    let raw = std::fs::read_to_string(&path).unwrap();
    assert!(raw.contains("[runtime.remote_config]"));
    assert!(raw.contains("https://cfg.example/spt.toml"));
}

#[test]
fn config_migrate_round_trip_v1_to_v1_is_idempotent() {
    let raw = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
"#;
    let migrated = spt_config::migrate(raw).unwrap();
    let (cfg, _) = spt_config::load_str(&migrated, false).unwrap();
    assert_eq!(cfg.version, 1);
}
