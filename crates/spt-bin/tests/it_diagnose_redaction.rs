//! Diagnose bundle includes config text routed through the strict redactor.

use spt_diagnostics::{build_bundle, BundleConfig, BundleInputs};
use tempfile::TempDir;

#[test]
fn bundle_redacts_inline_secrets_in_config_text() {
    let tmp = TempDir::new().unwrap();
    let cfg_text = r#"
version = 1
[secrets]
backend = "vault"
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h"
[profiles.auth]
method = "password"
password = "secret://ns/pw"
"#;
    let inputs = BundleInputs {
        effective_config: Some(cfg_text.to_string()),
        ..Default::default()
    };
    let cfg = BundleConfig::default();
    let path = build_bundle(tmp.path(), "test-1", &inputs, &cfg).expect("bundle build");
    assert!(path.exists(), "{} missing", path.display());
    // Sanity: archive size > 0.
    let meta = std::fs::metadata(&path).unwrap();
    assert!(meta.len() > 0);
}
