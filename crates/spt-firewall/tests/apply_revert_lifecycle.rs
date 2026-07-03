//! Firewall APPLY -> REVERT lifecycle, exercised end-to-end via a fake host
//! firewall executor (no root, no shell-out).
//!
//! ## Why this exists
//!
//! The real per-OS backends (`nft -f -`, `pfctl`, `netsh`) are `cfg`-gated and
//! require root, so `cargo test` only ever drives the plan-only / dry-run path
//! (`applied = false`). That means a backend that silently stops *applying*
//! (leaving the host open) or stops *reverting* (leaking rules) would still
//! pass CI. These tests close that gap at the highest level reachable without
//! root: the **plan -> command translation** plus a fake executor that models
//! the live rule set the exact way the production `query_active_rules`
//! parsers do (by scanning the rendered `spt:<id>` tags).
//!
//! ## Seam note
//!
//! `spt-firewall` has NO injectable executor seam: `NftPlanner::apply`/`remove`
//! call the private `run_native` free function directly, so a real-backend
//! apply/revert test cannot substitute a fake process runner without a
//! production change (abstract `run_native` behind a trait / inject a
//! `CommandRunner`). This test therefore asserts the translation + lifecycle
//! contract against the rendered plan, which is the invariant a regressed
//! backend would break. See `.orchestration/logs/tw-fwsec.md`.

use std::collections::BTreeSet;

use spt_firewall::linux::{IptablesPlanner, NftPlanner};
use spt_firewall::{
    validate_rules, Action, Direction, FirewallPlan, FirewallPlanner, Protocol, Rule,
};

/// Extract every `<prefix><id>` tag from a rendered firewall script.
///
/// Mirrors the crate's own `parse_comment_ids` / `parse_netsh_rule_ids` /
/// `parse_label_ids` scanners: reads the id characters that follow each
/// `prefix` occurrence using the same `[A-Za-z0-9._-]` allowlist the renderers
/// enforce on rule ids. Works across the nft (`comment "spt:<id>"`), iptables
/// (`--comment "spt:<id>"`), pf (`label "spt:<id>"`) and netsh
/// (`name="spt:<id>"`) renderings because they all embed the same tag.
fn tags_in_script(script: &str, prefix: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut idx = 0usize;
    while let Some(rel) = script[idx..].find(prefix) {
        let start = idx + rel + prefix.len();
        let id: String = script[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            .collect();
        if !id.is_empty() {
            out.insert(id.clone());
        }
        // Always make progress (ids are ASCII, so `id.len()` is a char
        // boundary; `max(1)` handles a bare prefix with no following id).
        idx = start + id.len().max(1);
    }
    out
}

/// A fake host firewall. Models the live managed rule set as a set of active
/// rule IDs and records what it applied / removed. `apply` installs exactly the
/// tags rendered into the plan (flush-then-add semantics: the managed set
/// becomes exactly the plan's tags, so a repeated apply converges rather than
/// duplicating). `revert` removes exactly the plan's tags — the property a
/// leaking backend would break.
#[derive(Default)]
struct FakeFirewall {
    active: BTreeSet<String>,
    applied_log: Vec<String>,
    removed_log: Vec<String>,
    /// When set, `apply` fails *before* mutating any state (fail-closed).
    fail_apply: bool,
}

impl FakeFirewall {
    fn apply(&mut self, plan: &FirewallPlan) -> Result<(), String> {
        if self.fail_apply {
            // Fail-closed: a rejected apply must NOT partially install rules,
            // so the host is never left in a half-open state.
            return Err("simulated apply failure".to_string());
        }
        let ids = tags_in_script(&plan.script, &plan.tag_prefix);
        for id in ids {
            self.applied_log.push(id.clone());
            self.active.insert(id);
        }
        Ok(())
    }

    fn revert(&mut self, plan: &FirewallPlan) {
        let ids = tags_in_script(&plan.script, &plan.tag_prefix);
        for id in ids {
            if self.active.remove(&id) {
                self.removed_log.push(id);
            }
        }
    }

    fn active_ids(&self) -> Vec<String> {
        self.active.iter().cloned().collect()
    }
}

/// Three well-formed rules spanning in/out and TCP/UDP.
fn valid_rules() -> Vec<Rule> {
    vec![
        Rule {
            id: "smtp-in".into(),
            direction: Direction::In,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            source_cidr: Some("10.0.0.0/8".into()),
            source_port: None,
            dest_cidr: None,
            dest_port: Some(2525),
            interface: Some("eth0".into()),
        },
        Rule {
            id: "dns-out".into(),
            direction: Direction::Out,
            action: Action::Allow,
            protocol: Protocol::Udp,
            source_cidr: None,
            source_port: None,
            dest_cidr: None,
            dest_port: Some(53),
            interface: None,
        },
        Rule {
            id: "block-ssh".into(),
            direction: Direction::In,
            action: Action::Deny,
            protocol: Protocol::Tcp,
            source_cidr: None,
            source_port: None,
            dest_cidr: None,
            dest_port: Some(22),
            interface: None,
        },
    ]
}

fn sorted(ids: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = ids.iter().map(ToString::to_string).collect();
    v.sort();
    v
}

#[test]
fn apply_installs_normalized_rules_then_revert_removes_exactly_them() {
    let rules = valid_rules();
    let plan = NftPlanner::new().plan(&rules);
    assert_eq!(plan.rule_count, 3, "all three valid rules should plan");

    let mut fw = FakeFirewall::default();
    fw.apply(&plan).expect("apply must succeed");

    // The backend received exactly the normalized rule set.
    assert_eq!(
        fw.active_ids(),
        sorted(&["block-ssh", "dns-out", "smtp-in"]),
        "apply must install exactly the planned rules"
    );

    // Revert removes exactly what was applied — no leaked rules.
    fw.revert(&plan);
    assert!(
        fw.active_ids().is_empty(),
        "revert leaked rules: {:?}",
        fw.active_ids()
    );

    let mut removed = fw.removed_log.clone();
    removed.sort();
    let mut applied = fw.applied_log.clone();
    applied.sort();
    assert_eq!(
        removed, applied,
        "revert must remove exactly what apply added"
    );
}

#[test]
fn fail_closed_normalize_drops_invalid_rules_before_apply() {
    // Two rules that MUST be rejected by the fail-closed normalizer: a
    // space-bearing id and a CIDR field carrying a shell-injection payload.
    let mut rules = valid_rules();
    rules.push(Rule {
        id: "bad id".into(), // space -> IdBadChar
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        source_cidr: None,
        source_port: None,
        dest_cidr: None,
        dest_port: Some(80),
        interface: None,
    });
    rules.push(Rule {
        id: "inject-me".into(),
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        source_cidr: Some("9.9.9.9; rm -rf /".into()), // BadCidr
        source_port: None,
        dest_cidr: None,
        dest_port: Some(81),
        interface: None,
    });

    // Confirm the up-front validator agrees these are invalid (documents intent).
    assert!(validate_rules(&rules).is_err());

    let plan = NftPlanner::new().plan(&rules);
    // The two invalid rules are DROPPED; only the three valid ones survive.
    assert_eq!(
        plan.rule_count, 3,
        "invalid rules must be dropped by the fail-closed normalizer"
    );
    assert!(
        !plan.script.contains("bad id"),
        "space-bearing id leaked into the rendered script"
    );
    assert!(
        !plan.script.contains("inject-me"),
        "bad-CIDR rule id leaked into the rendered script"
    );
    assert!(
        !plan.script.contains("rm -rf"),
        "injection payload leaked into the rendered script"
    );

    // And the fake backend never sees the dropped rules.
    let mut fw = FakeFirewall::default();
    fw.apply(&plan).expect("apply");
    assert_eq!(
        fw.active_ids(),
        sorted(&["block-ssh", "dns-out", "smtp-in"])
    );
}

#[test]
fn apply_is_idempotent_and_converges() {
    let plan = NftPlanner::new().plan(&valid_rules());
    let mut fw = FakeFirewall::default();
    fw.apply(&plan).expect("first apply");
    let after_first = fw.active_ids();
    fw.apply(&plan).expect("second apply");
    assert_eq!(
        fw.active_ids(),
        after_first,
        "repeated apply must converge, not duplicate"
    );
    assert_eq!(fw.active_ids().len(), plan.rule_count);
}

#[test]
fn apply_failure_does_not_strand_and_shutdown_revert_is_clean() {
    let plan = NftPlanner::new().plan(&valid_rules());

    // A failing apply must leave nothing behind (no stranded / half-open set).
    let mut fw = FakeFirewall {
        fail_apply: true,
        ..FakeFirewall::default()
    };
    let err = fw.apply(&plan).expect_err("apply must fail");
    assert!(err.contains("failure"));
    assert!(
        fw.active_ids().is_empty(),
        "failed apply stranded rules: {:?}",
        fw.active_ids()
    );

    // Recover: a subsequent successful apply then a shutdown-time revert must
    // leave the host clean (revert-on-shutdown).
    fw.fail_apply = false;
    fw.apply(&plan).expect("recovery apply");
    assert_eq!(fw.active_ids().len(), plan.rule_count);
    fw.revert(&plan);
    assert!(
        fw.active_ids().is_empty(),
        "shutdown revert leaked rules: {:?}",
        fw.active_ids()
    );
}

#[test]
fn lifecycle_holds_for_iptables_rendering_too() {
    // The tag-translation contract is renderer-agnostic: iptables embeds the
    // same `spt:<id>` comment, so apply -> revert must round-trip identically.
    let plan = IptablesPlanner::new().plan(&valid_rules());
    let mut fw = FakeFirewall::default();
    fw.apply(&plan).expect("apply");
    assert_eq!(
        fw.active_ids(),
        sorted(&["block-ssh", "dns-out", "smtp-in"])
    );
    fw.revert(&plan);
    assert!(fw.active_ids().is_empty());
}
