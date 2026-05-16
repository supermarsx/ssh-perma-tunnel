//! Public-API integration tests for `spt_config::policy`.
//!
//! These tests exercise only items re-exported from the crate root and the
//! `policy` module to make sure the binding table + overlay driver work for
//! external consumers (the OS-side reader lives in `spt-bin`).

#![allow(clippy::field_reassign_with_default)]

use spt_config::policy::{
    find_binding, ApplyMode, Binding, BindingKind, OverlayReport, PolicyBundle, PolicyOverlay,
    PolicyValue, BINDINGS,
};
use spt_config::schema::{Config, Firewall, Logging, Mcp, Network, NetworkInterface, Secrets};

fn k(section: &str, name: &str) -> String {
    format!("{section}\\{name}")
}

#[test]
fn binding_kind_as_str_is_stable() {
    assert_eq!(BindingKind::String.as_str(), "string");
    assert_eq!(BindingKind::Bool.as_str(), "bool");
    assert_eq!(BindingKind::U32.as_str(), "u32");
    assert_eq!(BindingKind::Allowlist.as_str(), "multi_string");
}

#[test]
fn binding_key_uses_canonical_section_backslash_name() {
    let b = find_binding("Logging", "Level").expect("Logging\\Level is a known binding");
    assert_eq!(b.key(), "Logging\\Level");
    let b = find_binding("Firewall", "ApplyRules").expect("Firewall\\ApplyRules is known");
    assert_eq!(b.key(), "Firewall\\ApplyRules");
    let b = find_binding("Logging", "AllowedDestinations").expect("known");
    assert_eq!(b.kind, BindingKind::Allowlist);
}

#[test]
fn find_binding_is_case_insensitive() {
    let bindings: Vec<&Binding> = ["LOGGING", "logging", "Logging", "LoGgInG"]
        .iter()
        .map(|s| find_binding(s, "level").expect("case-insensitive match"))
        .collect();
    // All four lookups must return the *same* table row.
    let first_ptr = std::ptr::addr_of!(*bindings[0]);
    for b in &bindings[1..] {
        assert!(std::ptr::eq(std::ptr::addr_of!(**b), first_ptr));
    }
}

#[test]
fn find_binding_misses_return_none() {
    assert!(find_binding("NoSuchSection", "level").is_none());
    assert!(find_binding("Logging", "NoSuchName").is_none());
    assert!(find_binding("", "").is_none());
}

#[test]
fn bindings_table_is_non_empty_and_every_row_has_unique_key() {
    assert!(!BINDINGS.is_empty(), "BINDINGS must contain rows");
    let mut keys: Vec<String> = BINDINGS.iter().map(|b| b.key()).collect();
    let original = keys.len();
    keys.sort();
    keys.dedup();
    // Some bindings are intentional aliases (e.g. Secrets\Backend and
    // Security\SecretBackend). The key form is still unique because the
    // section differs, so the count must match.
    assert_eq!(keys.len(), original, "binding keys must be unique");
}

#[test]
fn policy_bundle_default_is_empty_and_not_enforced() {
    let b = PolicyBundle::default();
    assert!(b.is_empty());
    assert!(!b.is_enforced("Logging\\Level"));

    let b2 = PolicyBundle::empty();
    assert_eq!(b, b2);
}

#[test]
fn policy_bundle_is_empty_flips_on_machine_or_user_insertion() {
    let mut b = PolicyBundle::empty();
    b.machine.insert(
        k("Logging", "Level"),
        PolicyValue::String("info".into()),
    );
    assert!(!b.is_empty());

    let mut b2 = PolicyBundle::empty();
    b2.user.insert(
        k("Logging", "Level"),
        PolicyValue::String("info".into()),
    );
    assert!(!b2.is_empty());
}

#[test]
fn policy_bundle_is_enforced_only_for_inserted_keys() {
    let mut b = PolicyBundle::empty();
    b.enforced.insert(k("Logging", "Level"));
    assert!(b.is_enforced("Logging\\Level"));
    assert!(!b.is_enforced("Logging\\Format"));
}

#[test]
fn apply_mode_distinguishes_enforced_from_advisory() {
    let mut cfg = Config::default();
    cfg.logging = Some(Logging {
        level: Some("info".into()),
        ..Default::default()
    });
    let mut b = PolicyBundle::empty();
    b.machine.insert(
        k("Logging", "Level"),
        PolicyValue::String("debug".into()),
    );
    // Advisory: existing value wins.
    let r = PolicyOverlay::apply(&mut cfg, &b);
    assert!(r.applied.is_empty());
    assert_eq!(cfg.logging.as_ref().unwrap().level.as_deref(), Some("info"));

    // Enforced: policy wins, key recorded as locked.
    b.enforced.insert(k("Logging", "Level"));
    let r = PolicyOverlay::apply(&mut cfg, &b);
    assert_eq!(r.applied, vec![k("Logging", "Level")]);
    assert_eq!(r.locked, vec![k("Logging", "Level")]);
    assert_eq!(
        cfg.logging.as_ref().unwrap().level.as_deref(),
        Some("debug")
    );
}

#[test]
fn reg_multi_sz_shape_drives_allowlist_intersection() {
    let mut cfg = Config::default();
    cfg.network = Some(Network {
        interface: Some(NetworkInterface {
            allowed_interfaces: Some(vec!["eth0".into(), "eth1".into(), "wlan0".into()]),
            ..Default::default()
        }),
        ..Default::default()
    });
    let mut b = PolicyBundle::empty();
    let key = k("Network", "AllowedInterfaces");
    b.machine.insert(
        key.clone(),
        PolicyValue::MultiString(vec!["eth1".into(), "wlan0".into(), "ppp0".into()]),
    );
    b.enforced.insert(key);
    PolicyOverlay::apply(&mut cfg, &b);

    let got = cfg
        .network
        .as_ref()
        .unwrap()
        .interface
        .as_ref()
        .unwrap()
        .allowed_interfaces
        .clone()
        .unwrap();
    // Intersection preserves config-side ordering: "eth1","wlan0".
    assert_eq!(got, vec!["eth1".to_string(), "wlan0".to_string()]);
}

#[test]
fn enforced_wins_over_advisory_user_and_machine() {
    let mut cfg = Config::default();
    cfg.secrets = Some(Secrets {
        backend: Some("file".into()),
        ..Default::default()
    });
    let mut b = PolicyBundle::empty();
    let key = k("Secrets", "Backend");
    b.machine
        .insert(key.clone(), PolicyValue::String("keychain".into()));
    b.user
        .insert(key.clone(), PolicyValue::String("vault".into()));
    b.enforced.insert(key.clone());
    let r = PolicyOverlay::apply(&mut cfg, &b);

    assert_eq!(r.applied, vec![key.clone()]);
    assert_eq!(r.locked, vec![key]);
    assert_eq!(
        cfg.secrets.as_ref().unwrap().backend.as_deref(),
        Some("keychain")
    );
}

#[test]
fn type_mismatch_records_key_and_does_not_apply() {
    let mut cfg = Config::default();
    let mut b = PolicyBundle::empty();
    // U32 binding fed a String value.
    b.machine.insert(
        k("Logging", "MaxFiles"),
        PolicyValue::String("seven".into()),
    );
    // Bool binding fed a String value.
    b.machine.insert(
        k("Firewall", "ApplyRules"),
        PolicyValue::String("yes".into()),
    );
    let r: OverlayReport = PolicyOverlay::apply(&mut cfg, &b);
    assert!(r.applied.is_empty());
    assert!(r
        .type_mismatch
        .iter()
        .any(|s| s == "Logging\\MaxFiles"));
    assert!(r
        .type_mismatch
        .iter()
        .any(|s| s == "Firewall\\ApplyRules"));
}

#[test]
fn unknown_keys_appear_in_overlay_report() {
    let mut cfg = Config::default();
    let mut b = PolicyBundle::empty();
    b.machine.insert(
        "Phantom\\Field".into(),
        PolicyValue::String("ignored".into()),
    );
    b.user.insert(
        "AnotherGhost\\Field".into(),
        PolicyValue::Integer(42),
    );
    let r = PolicyOverlay::apply(&mut cfg, &b);
    assert!(r.unknown.iter().any(|s| s == "Phantom\\Field"));
    assert!(r.unknown.iter().any(|s| s == "AnotherGhost\\Field"));
    assert!(r.applied.is_empty());
}

#[test]
fn enforced_apply_runs_even_when_value_unchanged() {
    let mut cfg = Config::default();
    cfg.firewall = Some(Firewall {
        apply_rules: Some(true),
        ..Default::default()
    });
    let mut b = PolicyBundle::empty();
    let key = k("Firewall", "ApplyRules");
    b.machine.insert(key.clone(), PolicyValue::Bool(true));
    b.enforced.insert(key.clone());
    let r = PolicyOverlay::apply(&mut cfg, &b);
    assert_eq!(r.applied, vec![key.clone()]);
    assert_eq!(r.locked, vec![key]);
}

#[test]
fn mcp_binding_creates_table_on_demand() {
    let mut cfg = Config::default();
    assert!(cfg.mcp.is_none());
    let mut b = PolicyBundle::empty();
    b.machine.insert(
        k("Network", "McpEnabled"),
        PolicyValue::Bool(true),
    );
    b.machine.insert(
        k("Network", "McpListen"),
        PolicyValue::String("127.0.0.1:8443".into()),
    );
    PolicyOverlay::apply(&mut cfg, &b);
    let mcp: &Mcp = cfg.mcp.as_ref().expect("Mcp table created by apply");
    assert_eq!(mcp.enabled, Some(true));
    assert_eq!(mcp.listen.as_deref(), Some("127.0.0.1:8443"));
}

#[test]
fn advisory_user_only_when_machine_silent() {
    let mut cfg = Config::default();
    let mut b = PolicyBundle::empty();
    // Machine has Logging\Level set, user has Logging\Format set —
    // both should land because they target different fields.
    b.machine.insert(
        k("Logging", "Level"),
        PolicyValue::String("warn".into()),
    );
    b.user.insert(
        k("Logging", "Format"),
        PolicyValue::String("json".into()),
    );
    let r = PolicyOverlay::apply(&mut cfg, &b);
    assert!(r.applied.contains(&k("Logging", "Level")));
    assert!(r.applied.contains(&k("Logging", "Format")));
    let logging = cfg.logging.as_ref().unwrap();
    assert_eq!(logging.level.as_deref(), Some("warn"));
    assert_eq!(logging.format.as_deref(), Some("json"));
}

#[test]
fn apply_mode_enum_traits() {
    // Trait-impl smoke test: ApplyMode must be Copy + Eq + Debug.
    let a = ApplyMode::Enforced;
    let b = a;
    assert_eq!(a, b);
    assert_ne!(ApplyMode::Enforced, ApplyMode::Advisory);
    let dbg = format!("{:?}", ApplyMode::Advisory);
    assert!(dbg.contains("Advisory"));
}
