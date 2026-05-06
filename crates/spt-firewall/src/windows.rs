//! Windows Firewall planner — renders `netsh advfirewall firewall` commands.
//!
//! All managed rules share `group="spt"` so a future `remove()` can call
//! `netsh advfirewall firewall delete rule group=spt`. Per-rule `name=spt:<id>`
//! also survives `netsh show rule`. Apply is gated; tests exercise only `plan()`.

use std::fmt::Write;

use crate::{normalize, Action, FirewallPlan, FirewallPlanner, Manager, Rule};

/// Group that all spt-managed Windows Firewall rules belong to.
pub const GROUP: &str = "spt";
/// Tag prefix used in the per-rule `name=` attribute.
pub const TAG_PREFIX: &str = "spt:";

/// Windows Firewall planner.
#[derive(Debug, Default, Clone, Copy)]
pub struct NetshPlanner;

impl NetshPlanner {
    /// Construct a planner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FirewallPlanner for NetshPlanner {
    fn plan(&self, rules: &[Rule]) -> FirewallPlan {
        let sorted = normalize(rules);
        let mut s = String::new();
        s.push_str("rem spt-firewall: Windows Firewall plan\r\n");
        for r in &sorted {
            writeln!(&mut s, "{}\r", render_netsh_rule(r)).unwrap();
        }
        FirewallPlan {
            manager: Manager::WindowsFirewall,
            script: s,
            tag_prefix: TAG_PREFIX.to_string(),
            rule_count: sorted.len(),
        }
    }
}

fn render_netsh_rule(r: &Rule) -> String {
    let dir = match r.direction {
        crate::Direction::In => "in",
        crate::Direction::Out => "out",
    };
    let action = match r.action {
        Action::Allow => "allow",
        Action::Deny | Action::Reject => "block",
    };
    let mut parts = vec![
        "netsh advfirewall firewall add rule".to_string(),
        format!("name=\"{TAG_PREFIX}{}\"", r.id),
        format!("group=\"{GROUP}\""),
        format!("dir={dir}"),
        format!("action={action}"),
        format!("protocol={}", r.protocol),
    ];
    if let Some(p) = r.dest_port {
        parts.push(format!("localport={p}"));
    }
    if let Some(p) = r.source_port {
        parts.push(format!("remoteport={p}"));
    }
    if let Some(c) = &r.dest_cidr {
        parts.push(format!("localip={c}"));
    }
    if let Some(c) = &r.source_cidr {
        parts.push(format!("remoteip={c}"));
    }
    if let Some(iface) = &r.interface {
        parts.push(format!("interface=\"{iface}\""));
    }
    parts.push("enable=yes".to_string());
    parts.join(" ")
}
