//! Linux firewall planners — nftables (preferred) and iptables (fallback).
//!
//! Both planners implement [`crate::FirewallPlanner`]. They render plain
//! text scripts; **nothing in this module shells out** unless a
//! non-dry-run `apply` is explicitly invoked at runtime.

use std::fmt::Write;

use crate::{normalize, Action, FirewallPlan, FirewallPlanner, Manager, Rule};

/// Comment tag used in rendered nft / iptables rules so a future `remove()`
/// can identify and delete only spt-managed entries.
pub const TAG_PREFIX: &str = "spt:";

/// nftables planner — emits a single `add table inet spt` declaration plus
/// per-rule `add rule` lines tagged with `comment "spt:<id>"`. Output is
/// suitable for `nft -f -` and is idempotent: callers should run a
/// `flush table inet spt` before piping in the new script.
#[derive(Debug, Default, Clone, Copy)]
pub struct NftPlanner;

impl NftPlanner {
    /// Construct a planner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FirewallPlanner for NftPlanner {
    fn plan(&self, rules: &[Rule]) -> FirewallPlan {
        let sorted = normalize(rules);
        let mut s = String::new();
        s.push_str("# spt-firewall: nftables plan\n");
        s.push_str("table inet spt {\n");
        s.push_str("    chain input {\n");
        s.push_str("        type filter hook input priority 0; policy accept;\n");
        for r in &sorted {
            if r.direction == crate::Direction::In {
                writeln!(&mut s, "        {}", render_nft_rule(r)).unwrap();
            }
        }
        s.push_str("    }\n");
        s.push_str("    chain output {\n");
        s.push_str("        type filter hook output priority 0; policy accept;\n");
        for r in &sorted {
            if r.direction == crate::Direction::Out {
                writeln!(&mut s, "        {}", render_nft_rule(r)).unwrap();
            }
        }
        s.push_str("    }\n");
        s.push_str("}\n");

        FirewallPlan {
            manager: Manager::Nftables,
            script: s,
            tag_prefix: TAG_PREFIX.to_string(),
            rule_count: sorted.len(),
        }
    }
}

fn render_nft_rule(r: &Rule) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(iface) = &r.interface {
        parts.push(if r.direction == crate::Direction::In {
            format!("iif \"{iface}\"")
        } else {
            format!("oif \"{iface}\"")
        });
    }
    parts.push(format!("{} dport {}", r.protocol, port_or_any(r.dest_port)));
    if let Some(p) = r.source_port {
        parts.push(format!("{} sport {p}", r.protocol));
    }
    if let Some(cidr) = &r.source_cidr {
        parts.push(format!("ip saddr {cidr}"));
    }
    if let Some(cidr) = &r.dest_cidr {
        parts.push(format!("ip daddr {cidr}"));
    }
    parts.push(nft_verdict(r.action).to_string());
    parts.push(format!("comment \"{TAG_PREFIX}{}\"", r.id));
    parts.join(" ")
}

const fn nft_verdict(a: Action) -> &'static str {
    match a {
        Action::Allow => "accept",
        Action::Deny => "drop",
        Action::Reject => "reject",
    }
}

fn port_or_any(p: Option<u16>) -> String {
    p.map_or_else(|| "0-65535".to_string(), |v| v.to_string())
}

/// Legacy iptables fallback. Emits a sequence of `iptables -A INPUT ...` /
/// `iptables -A OUTPUT ...` lines tagged via `-m comment --comment`.
#[derive(Debug, Default, Clone, Copy)]
pub struct IptablesPlanner;

impl IptablesPlanner {
    /// Construct a planner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl FirewallPlanner for IptablesPlanner {
    fn plan(&self, rules: &[Rule]) -> FirewallPlan {
        let sorted = normalize(rules);
        let mut s = String::new();
        s.push_str("# spt-firewall: iptables plan\n");
        for r in &sorted {
            writeln!(&mut s, "{}", render_iptables_rule(r)).unwrap();
        }
        FirewallPlan {
            manager: Manager::Iptables,
            script: s,
            tag_prefix: TAG_PREFIX.to_string(),
            rule_count: sorted.len(),
        }
    }
}

fn render_iptables_rule(r: &Rule) -> String {
    let chain = match r.direction {
        crate::Direction::In => "INPUT",
        crate::Direction::Out => "OUTPUT",
    };
    let target = match r.action {
        Action::Allow => "ACCEPT",
        Action::Deny => "DROP",
        Action::Reject => "REJECT",
    };
    let mut parts = vec![format!("iptables -A {chain}")];
    if let Some(iface) = &r.interface {
        parts.push(format!(
            "-{} {iface}",
            if r.direction == crate::Direction::In {
                "i"
            } else {
                "o"
            }
        ));
    }
    parts.push(format!("-p {}", r.protocol));
    if let Some(cidr) = &r.source_cidr {
        parts.push(format!("-s {cidr}"));
    }
    if let Some(cidr) = &r.dest_cidr {
        parts.push(format!("-d {cidr}"));
    }
    if let Some(p) = r.source_port {
        parts.push(format!("--sport {p}"));
    }
    if let Some(p) = r.dest_port {
        parts.push(format!("--dport {p}"));
    }
    parts.push(format!(
        "-m comment --comment \"{TAG_PREFIX}{}\"",
        r.id
    ));
    parts.push(format!("-j {target}"));
    parts.join(" ")
}
