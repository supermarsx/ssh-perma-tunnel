//! macOS pf planner.
//!
//! Renders rules into the `com.spt` anchor. Apply with
//! `pfctl -a com.spt -f -` (gated, never invoked in tests).

use std::fmt::Write;

#[cfg(target_os = "macos")]
use spt_core::error::Result;

use crate::{normalize, Action, FirewallPlan, FirewallPlanner, Manager, Rule};

/// Anchor name owned by spt under `pf`.
pub const ANCHOR: &str = "com.spt";
/// Tag prefix matching the linux planner.
pub const TAG_PREFIX: &str = "spt:";

/// pf planner for macOS.
#[derive(Debug, Default, Clone, Copy)]
pub struct PfPlanner;

impl PfPlanner {
    /// Construct a planner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FirewallPlanner for PfPlanner {
    fn plan(&self, rules: &[Rule]) -> FirewallPlan {
        let sorted = normalize(rules);
        let mut s = String::new();
        writeln!(&mut s, "# spt-firewall: pf anchor {ANCHOR}").unwrap();
        for r in &sorted {
            writeln!(&mut s, "{}", render_pf_rule(r)).unwrap();
        }
        FirewallPlan {
            manager: Manager::Pf,
            script: s,
            tag_prefix: TAG_PREFIX.to_string(),
            rule_count: sorted.len(),
        }
    }

    /// Load the plan into the `com.spt` pf anchor via `pfctl -a com.spt -f -`.
    /// Loading an anchor replaces its prior contents, so apply is idempotent.
    ///
    /// Live shell-out requires root; exercised only by `#[ignore]`-gated tests.
    #[cfg(target_os = "macos")]
    fn apply(&self, plan: &FirewallPlan, dry_run: bool) -> Result<()> {
        if dry_run {
            tracing::info!(rules = plan.rule_count, "spt-firewall pf dry-run");
            tracing::debug!("\n{}", plan.script);
            return Ok(());
        }
        crate::run_native("pfctl", &["-a", ANCHOR, "-f", "-"], Some(&plan.script))?;
        Ok(())
    }

    /// Flush the `com.spt` anchor (`pfctl -a com.spt -F all`). Idempotent.
    #[cfg(target_os = "macos")]
    fn remove(&self, _plan: &FirewallPlan) -> Result<()> {
        crate::run_native("pfctl", &["-a", ANCHOR, "-F", "all"], None)?;
        Ok(())
    }

    /// List spt-managed rule ids by parsing `pfctl -a com.spt -s rules` for the
    /// `label "spt:<id>"` tokens.
    #[cfg(target_os = "macos")]
    fn query_active_rules(&self) -> Result<Vec<String>> {
        let listing = crate::run_native("pfctl", &["-a", ANCHOR, "-s", "rules"], None)?;
        Ok(parse_label_ids(&listing, TAG_PREFIX))
    }
}

/// Extract spt rule ids from `pfctl -s rules` output by scanning for the
/// `label "<prefix><id>"` tokens.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_label_ids(listing: &str, prefix: &str) -> Vec<String> {
    let needle = format!("label \"{prefix}");
    let mut ids = Vec::new();
    for line in listing.lines() {
        if let Some(start) = line.find(&needle) {
            let rest = &line[start + needle.len()..];
            if let Some(end) = rest.find('"') {
                ids.push(rest[..end].to_string());
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids
}

fn render_pf_rule(r: &Rule) -> String {
    let action = match r.action {
        Action::Allow => "pass",
        Action::Deny => "block drop",
        Action::Reject => "block return",
    };
    let dir = match r.direction {
        crate::Direction::In => "in",
        crate::Direction::Out => "out",
    };
    let mut parts = vec![format!("{action} {dir} quick")];
    if let Some(iface) = &r.interface {
        parts.push(format!("on {iface}"));
    }
    parts.push(format!("proto {}", r.protocol));
    let from = match (&r.source_cidr, r.source_port) {
        (Some(c), Some(p)) => format!("from {c} port {p}"),
        (Some(c), None) => format!("from {c}"),
        (None, Some(p)) => format!("from any port {p}"),
        (None, None) => "from any".to_string(),
    };
    parts.push(from);
    let to = match (&r.dest_cidr, r.dest_port) {
        (Some(c), Some(p)) => format!("to {c} port {p}"),
        (Some(c), None) => format!("to {c}"),
        (None, Some(p)) => format!("to any port {p}"),
        (None, None) => "to any".to_string(),
    };
    parts.push(to);
    parts.push(format!("label \"{TAG_PREFIX}{}\"", r.id));
    parts.join(" ")
}
