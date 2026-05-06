//! macOS pf planner.
//!
//! Renders rules into the `com.spt` anchor. Apply with
//! `pfctl -a com.spt -f -` (gated, never invoked in tests).

use std::fmt::Write;

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
