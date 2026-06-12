//! Linux firewall planners — nftables (preferred) and iptables (fallback).
//!
//! Both planners implement [`crate::FirewallPlanner`]. They render plain
//! text scripts; **nothing in this module shells out** unless a
//! non-dry-run `apply` is explicitly invoked at runtime.

use std::fmt::Write;

#[cfg(target_os = "linux")]
use spt_core::error::Result;

use crate::{normalize, Action, FirewallPlan, FirewallPlanner, Manager, Rule};

/// Comment tag used in rendered nft / iptables rules so a future `remove()`
/// can identify and delete only spt-managed entries.
pub const TAG_PREFIX: &str = "spt:";

/// nftables planner — emits a `flush table inet spt` followed by a single
/// `table inet spt` declaration plus per-rule lines tagged with
/// `comment "spt:<id>"`. The leading flush makes the script idempotent:
/// piping it through `nft -f -` repeatedly converges to the same ruleset
/// instead of accumulating duplicate rules.
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
        // Idempotency: ensure the table exists, then flush it before re-adding
        // the managed rules. `add table` is a no-op when the table is already
        // present, and the subsequent flush clears any rules from a prior apply
        // so repeated `nft -f -` runs converge rather than duplicate.
        s.push_str("add table inet spt\n");
        s.push_str("flush table inet spt\n");
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

    /// Apply the plan by piping its script through `nft -f -`. The script is
    /// self-idempotent (it begins with `add table` + `flush table`), so a
    /// repeated apply converges instead of duplicating rules.
    ///
    /// Live shell-out requires root and is exercised only by `#[ignore]`-gated
    /// tests; unit tests use the default dry-run path on the trait.
    #[cfg(target_os = "linux")]
    fn apply(&self, plan: &FirewallPlan, dry_run: bool) -> Result<()> {
        if dry_run {
            tracing::info!(rules = plan.rule_count, "spt-firewall nft dry-run");
            tracing::debug!("\n{}", plan.script);
            return Ok(());
        }
        crate::run_native("nft", &["-f", "-"], Some(&plan.script))?;
        Ok(())
    }

    /// Remove all spt-managed rules by deleting the whole `inet spt` table.
    /// Idempotent: a missing table is treated as success.
    #[cfg(target_os = "linux")]
    fn remove(&self, _plan: &FirewallPlan) -> Result<()> {
        match crate::run_native("nft", &["delete", "table", "inet", "spt"], None) {
            Ok(_) => Ok(()),
            // `No such file or directory` / `does not exist` => already gone.
            Err(e) if e.to_string().to_lowercase().contains("does not exist") => Ok(()),
            Err(e) if e.to_string().to_lowercase().contains("no such") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// List the spt-managed rule ids currently installed by parsing
    /// `nft list table inet spt` for `comment "spt:<id>"` tags.
    #[cfg(target_os = "linux")]
    fn query_active_rules(&self) -> Result<Vec<String>> {
        let listing = match crate::run_native("nft", &["list", "table", "inet", "spt"], None) {
            Ok(out) => out,
            Err(e)
                if e.to_string().to_lowercase().contains("does not exist")
                    || e.to_string().to_lowercase().contains("no such") =>
            {
                return Ok(Vec::new());
            }
            Err(e) => return Err(e),
        };
        Ok(parse_comment_ids(&listing, TAG_PREFIX))
    }
}

/// Extract spt rule ids from native rule output by scanning for the
/// `comment "<prefix><id>"` tokens. Shared by the nft query parser and tests.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_comment_ids(listing: &str, prefix: &str) -> Vec<String> {
    let needle = format!("comment \"{prefix}");
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
        // In a `table inet` (dual-stack) family, `ip saddr` only matches IPv4;
        // an IPv6 CIDR must use the `ip6` selector or `nft` rejects the rule.
        parts.push(format!("{} saddr {cidr}", nft_addr_family(cidr)));
    }
    if let Some(cidr) = &r.dest_cidr {
        parts.push(format!("{} daddr {cidr}", nft_addr_family(cidr)));
    }
    parts.push(nft_verdict(r.action).to_string());
    parts.push(format!("comment \"{TAG_PREFIX}{}\"", r.id));
    parts.join(" ")
}

/// Pick the nftables address selector family (`ip` vs `ip6`) for a CIDR.
///
/// Inside a `table inet`, the `ip` selector only matches IPv4 packets; IPv6
/// CIDRs must use `ip6`. We parse the CIDR; if it is an IPv6 network (or a
/// bare-looking IPv6 literal containing `:`) we emit `ip6`, otherwise `ip`.
fn nft_addr_family(cidr: &str) -> &'static str {
    if let Ok(net) = cidr.parse::<ipnet::IpNet>() {
        return match net {
            ipnet::IpNet::V4(_) => "ip",
            ipnet::IpNet::V6(_) => "ip6",
        };
    }
    // Fall back to a cheap heuristic for inputs that aren't strict CIDRs
    // (e.g. a bare address without a prefix length): a colon means IPv6.
    if cidr.contains(':') {
        "ip6"
    } else {
        "ip"
    }
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
    parts.push(format!("-m comment --comment \"{TAG_PREFIX}{}\"", r.id));
    parts.push(format!("-j {target}"));
    parts.join(" ")
}
