//! Integration coverage for the contracts that `cli::firewall_ops` consumes.
//!
//! `cli::firewall_ops` lives inside the `spt` binary crate and is not
//! externally importable, so this file black-box tests the cross-crate
//! contract surface — the same `spt_config::BINDINGS` table, `find_binding`
//! lookup, `BindingKind::as_str` rendering, `PolicyOverlay::apply` reporting
//! and `spt_firewall::FirewallPlanner` shape — that the binary's
//! `firewall_ops.rs` calls when servicing `spt firewall policy/bind-preview`.
//!
//! Inline `#[cfg(test)] mod tests` in `firewall_ops.rs` covers the binary-
//! internal helpers; this file exercises the public ABIs they depend on so
//! that a future refactor that breaks the contract trips a test here too.

use spt_config::{
    find_binding, schema::Config, BindingKind, PolicyBundle, PolicyOverlay, PolicyValue, BINDINGS,
};
use spt_firewall::{
    linux::NftPlanner, Action, Direction, FirewallPlanner, Manager, Protocol, Rule,
};

fn key(section: &str, name: &str) -> String {
    format!("{section}\\{name}")
}

/// `firewall_ops::policy_list` JSON output mirrors the `BINDINGS` slice and
/// uses `binding.key()` + `binding.kind.as_str()` for stable string
/// surfaces. Lock those names down.
#[test]
fn bindings_table_exposes_stable_kind_names() {
    assert!(!BINDINGS.is_empty(), "binding table must be non-empty");
    let kinds: std::collections::HashSet<&'static str> =
        BINDINGS.iter().map(|b| b.kind.as_str()).collect();
    // The CLI surface in policy_list JSON uses these literal strings:
    for expected in &["string", "bool", "u32", "multi_string"] {
        assert!(
            kinds.contains(expected),
            "no binding declares kind `{expected}` — CLI policy_list will hide it"
        );
    }
}

#[test]
fn bindings_keys_use_backslash_separator() {
    for binding in BINDINGS {
        let k = binding.key();
        assert!(
            k.contains('\\'),
            "binding key `{k}` must use `Section\\Name` form for CLI parser parity"
        );
    }
}

/// `firewall_ops::policy_set` resolves the user-provided key via
/// `spt_config::find_binding` case-insensitively; cover the path here.
#[test]
fn find_binding_is_case_insensitive_for_cli_input() {
    let lowered = find_binding("logging", "level").expect("Logging.Level binds");
    let upper = find_binding("LOGGING", "LEVEL").expect("uppercase binds too");
    assert_eq!(lowered.key(), upper.key());
    assert_eq!(lowered.kind.as_str(), "string");
}

#[test]
fn find_binding_returns_none_for_unknown_section() {
    assert!(find_binding("BogusSection", "AnythingHere").is_none());
}

/// `BindingKind::as_str` powers the kind column in `policy list --json`.
#[test]
fn binding_kind_as_str_is_stable() {
    assert_eq!(BindingKind::String.as_str(), "string");
    assert_eq!(BindingKind::Bool.as_str(), "bool");
    assert_eq!(BindingKind::U32.as_str(), "u32");
    assert_eq!(BindingKind::Allowlist.as_str(), "multi_string");
}

/// `firewall_ops::policy_show` calls `PolicyOverlay::apply` and renders the
/// `applied`, `locked`, `unknown`, and `type_mismatch` lists. Cover the
/// type-mismatch + unknown pair.
#[test]
fn policy_overlay_records_unknown_and_type_mismatch() {
    let mut cfg = Config::default();
    let mut bundle = PolicyBundle::empty();
    bundle.machine.insert(
        key("Logging", "MaxFiles"),
        PolicyValue::String("not-a-number".into()),
    );
    bundle
        .machine
        .insert(key("Mystery", "Foo"), PolicyValue::String("bar".into()));
    let r = PolicyOverlay::apply(&mut cfg, &bundle);
    assert!(r.type_mismatch.contains(&key("Logging", "MaxFiles")));
    assert!(r.unknown.contains(&"Mystery\\Foo".to_string()));
    assert!(r.applied.is_empty());
}

/// `gateway_show` reads `cfg.network` and `cfg.firewall`; assert the
/// toml-edit round-trip used by `gateway_set` preserves comments and
/// re-parses to populated tables.
#[test]
fn gateway_toml_round_trip_via_document() {
    let raw = r#"# header
version = 1
[network]
[network.interface]
default_interface = "eth0"

[network.gateway]
default_gateway = "192.0.2.1"
"#;
    let mut doc = spt_config::mutate::Document::parse(raw).expect("parse");
    // Re-render and re-parse: shape stable.
    let rendered = doc.document_mut().to_string();
    assert!(rendered.contains("# header"));
    let (cfg, _) = spt_config::load_str(&rendered, false).expect("reparse");
    let network = cfg.network.expect("network");
    assert_eq!(
        network
            .interface
            .as_ref()
            .and_then(|i| i.default_interface.as_deref()),
        Some("eth0")
    );
    assert_eq!(
        network
            .gateway
            .as_ref()
            .and_then(|g| g.default_gateway.as_deref()),
        Some("192.0.2.1")
    );
}

/// `firewall_ops::bind_preview` renders rules into the per-OS planner's
/// `plan()` and then emits the resulting `script` / `manager` / `tag_prefix`.
/// Assert the contract every per-OS planner upholds for that surface.
#[test]
fn nft_planner_renders_stable_envelope_for_preview() {
    let rules = vec![Rule {
        id: "edge-db-1".into(),
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        source_cidr: None,
        source_port: None,
        dest_cidr: Some("127.0.0.1/32".into()),
        dest_port: Some(5432),
        interface: None,
    }];
    let plan = NftPlanner::new().plan(&rules);
    assert_eq!(plan.manager, Manager::Nftables);
    assert_eq!(plan.tag_prefix, "spt:");
    assert_eq!(plan.rule_count, 1);
    // The rendered script embeds the rule id as comment / tag — used by
    // `firewall_ops` bind-preview text mode.
    assert!(plan.script.contains("edge-db-1"));
}

/// Empty rule set produces a deterministic empty plan envelope; this is the
/// path `firewall_ops::emit_status` uses to read manager + `tag_prefix` when
/// there are no live rules to report.
#[test]
fn planner_empty_plan_envelope_is_stable() {
    let plan = NftPlanner::new().plan(&[]);
    assert_eq!(plan.manager, Manager::Nftables);
    assert_eq!(plan.tag_prefix, "spt:");
    assert_eq!(plan.rule_count, 0);
}
