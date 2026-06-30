//! Diagnose bundle includes config text routed through the strict redactor.
//!
//! This is a security regression test: a diagnostic bundle must NEVER ship a
//! plaintext secret. The test seeds known secret sentinels into the bundled
//! `effective-config.toml`, then decompresses the produced gzip'd tar archive
//! and asserts the sentinels are ABSENT and the `[REDACTED]` marker is PRESENT.
//! If the strict redactor were bypassed/removed, the sentinel bytes would
//! survive into the archive and these assertions would fail.

use std::io::Read;

use flate2::read::GzDecoder;
use spt_diagnostics::{build_bundle, BundleConfig, BundleInputs};
use tempfile::TempDir;

/// Distinctive sentinels that the strict redactor must mask. Each is the VALUE
/// side of a `key = "..."` pair the redactor recognises (`password`, `token`),
/// plus a bearer token (matched by the `bearer` anchor).
const PASSWORD_SENTINEL: &str = "S3cretPlaintextPW_do_not_leak_9f1c";
const TOKEN_SENTINEL: &str = "tok_live_do_not_leak_44b2e7c9";
const BEARER_SENTINEL: &str = "eyJhbGciOiJIUzI1NiJ9.do_not_leak.sig";

/// Decompress the gzip'd tar bundle and return its entries as (name, bytes).
fn read_archive_entries(archive: &std::path::Path) -> Vec<(String, Vec<u8>)> {
    let f = std::fs::File::open(archive).expect("open bundle");
    let gz = GzDecoder::new(f);
    let mut tar = tar::Archive::new(gz);
    let mut out = Vec::new();
    for entry in tar.entries().expect("tar entries") {
        let mut entry = entry.expect("tar entry");
        let name = entry
            .path()
            .expect("entry path")
            .to_string_lossy()
            .into_owned();
        let mut buf = Vec::new();
        entry.read_to_end(&mut buf).expect("read entry");
        out.push((name, buf));
    }
    out
}

#[test]
fn bundle_redacts_inline_secrets_in_config_text() {
    let tmp = TempDir::new().unwrap();
    // Seed three distinct secrets into the config text the bundle archives.
    let cfg_text = format!(
        r#"
version = 1
[secrets]
backend = "vault"
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "password"
password = "{PASSWORD_SENTINEL}"
token = "{TOKEN_SENTINEL}"
authorization = "Bearer {BEARER_SENTINEL}"
"#
    );
    let inputs = BundleInputs {
        effective_config: Some(cfg_text.clone()),
        ..Default::default()
    };
    let cfg = BundleConfig::default();
    assert!(
        matches!(cfg.redaction, spt_core::redaction::RedactionMode::Strict),
        "bundle default must be strict redaction"
    );

    let path = build_bundle(tmp.path(), "test-1", &inputs, &cfg).expect("bundle build");
    assert!(path.exists(), "{} missing", path.display());

    let entries = read_archive_entries(&path);
    let (_, body) = entries
        .iter()
        .find(|(n, _)| n == "effective-config.toml")
        .expect("bundle must contain effective-config.toml");
    let body = std::str::from_utf8(body).expect("config entry is utf-8");

    // Every seeded secret value must be ABSENT from the archived config.
    for sentinel in [PASSWORD_SENTINEL, TOKEN_SENTINEL, BEARER_SENTINEL] {
        assert!(
            !body.contains(sentinel),
            "secret `{sentinel}` leaked into diagnostic bundle:\n{body}"
        );
    }
    // The redaction marker must be present, proving the redactor ran and
    // substituted (not merely dropped) the secrets.
    assert!(
        body.contains("[REDACTED]"),
        "expected [REDACTED] marker in redacted config, got:\n{body}"
    );

    // Sanity: the non-secret structure survives (the redactor is targeted, not
    // a blanket wipe).
    assert!(
        body.contains("protocol = \"ssh2\""),
        "non-secret config content should be preserved, got:\n{body}"
    );
}
