//! Integration test for the GPO policy overlay binding table.
//!
//! Exercises the public `spt_config::PolicyOverlay` API end-to-end with
//! synthetic [`PolicyBundle`]s. The Windows-specific registry round-trip lives
//! as a `#[cfg(windows)] #[test]` inside `crates/spt-bin/src/policy/registry.rs`
//! and runs once `t2-wire` registers `mod policy;` in `main.rs`.

use spt_config::{Config, PolicyBundle, PolicyOverlay, PolicyValue};

fn key(section: &str, name: &str) -> String {
    format!("{section}\\{name}")
}

#[test]
fn enforced_machine_policy_overrides_loaded_config() {
    let raw = r#"
version = 1
[logging]
level = "info"
"#;
    let (mut cfg, _warns): (Config, Vec<String>) =
        spt_config::load_str(raw, false).expect("load_str");

    let mut bundle = PolicyBundle::empty();
    let k = key("Logging", "Level");
    bundle
        .machine
        .insert(k.clone(), PolicyValue::String("error".into()));
    bundle.enforced.insert(k.clone());

    let report = PolicyOverlay::apply(&mut cfg, &bundle);
    assert_eq!(
        cfg.logging.as_ref().unwrap().level.as_deref(),
        Some("error")
    );
    assert!(report.locked.contains(&k));
    assert!(report.applied.contains(&k));
}

#[test]
fn advisory_policy_fills_unset_field_only() {
    let raw = r#"
version = 1
[secrets]
backend = "vault"
"#;
    let (mut cfg, _warns): (Config, Vec<String>) =
        spt_config::load_str(raw, false).expect("load_str");

    let mut bundle = PolicyBundle::empty();
    bundle.machine.insert(
        key("Secrets", "Backend"),
        PolicyValue::String("keychain".into()),
    );
    // Memory protection is unset, so it should be filled.
    bundle.machine.insert(
        key("Secrets", "MemoryProtection"),
        PolicyValue::String("strict".into()),
    );

    PolicyOverlay::apply(&mut cfg, &bundle);
    assert_eq!(
        cfg.secrets.as_ref().unwrap().backend.as_deref(),
        Some("vault"),
        "advisory must not override existing config"
    );
    assert_eq!(
        cfg.secrets.as_ref().unwrap().memory_protection.as_deref(),
        Some("strict"),
        "advisory must fill unset field"
    );
}

#[test]
fn enforced_allowlist_intersects_with_config() {
    let raw = r#"
version = 1
[logging]
destinations = ["stderr", "file", "remote"]
"#;
    let (mut cfg, _warns): (Config, Vec<String>) =
        spt_config::load_str(raw, false).expect("load_str");

    let mut bundle = PolicyBundle::empty();
    let k = key("Logging", "AllowedDestinations");
    bundle.machine.insert(
        k.clone(),
        PolicyValue::MultiString(vec!["file".into(), "syslog".into()]),
    );
    bundle.enforced.insert(k);

    PolicyOverlay::apply(&mut cfg, &bundle);
    let dests = cfg.logging.as_ref().unwrap().destinations.as_ref().unwrap();
    // intersection: only "file" appears in both — order from config side preserved.
    assert_eq!(dests, &vec!["file".to_string()]);
}

#[test]
fn user_hive_value_is_advisory_only() {
    let mut cfg = Config::default();
    let mut bundle = PolicyBundle::empty();
    bundle.user.insert(
        key("Mcp", "Enabled"), // unknown — bound list doesn't include this
        PolicyValue::Bool(true),
    );
    let r = PolicyOverlay::apply(&mut cfg, &bundle);
    assert!(r.unknown.iter().any(|u| u == "Mcp\\Enabled"));
}

#[test]
fn empty_bundle_leaves_config_untouched() {
    let raw = r#"
version = 1
[runtime]
state_dir = "/var/lib/spt"
"#;
    let (mut cfg, _warns): (Config, Vec<String>) =
        spt_config::load_str(raw, false).expect("load_str");
    let before = cfg.clone();

    let report = PolicyOverlay::apply(&mut cfg, &PolicyBundle::empty());
    assert!(report.applied.is_empty());
    assert!(report.locked.is_empty());
    assert_eq!(cfg, before);
}
