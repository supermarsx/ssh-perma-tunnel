//! Cross-platform firewall planners for spt.
//!
//! This crate is **config-agnostic**: callers (typically the `spt-bin`
//! dispatcher) translate `spt_config::Firewall` and forward bind information
//! into a flat `Vec<Rule>` and pass it to a [`FirewallPlanner`]. The planner
//! renders an idempotent native rule script (nft / pf / netsh) and offers a
//! dry-run mode that only returns the rendered text — tests use exclusively
//! that path; **real shell-out is gated behind `apply()` and is never
//! exercised by `cargo test`** per spec §13.6.
//!
//! Public surface:
//! - [`Rule`], [`Direction`], [`Action`], [`Protocol`] — config-free rule IR.
//! - [`FirewallPlan`] — rendered script + tagging metadata for cleanup.
//! - [`FirewallPlanner`] — trait with `plan` / `apply` / `remove` (object-safe).
//! - [`new_planner`] — picks the right impl for the current OS.
//! - [`linux::NftPlanner`], [`macos::PfPlanner`], [`windows::NetshPlanner`] —
//!   per-OS implementations, each available on every host (so golden tests
//!   compile cross-platform).

#![warn(missing_docs)]

use std::fmt;

use serde::{Deserialize, Serialize};
use spt_core::error::{Error, Result};

pub mod linux;
pub mod macos;
pub mod windows;

/// Rule direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Inbound traffic.
    In,
    /// Outbound traffic.
    Out,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::In => "in",
            Self::Out => "out",
        })
    }
}

/// Rule action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Accept the packet.
    Allow,
    /// Drop silently.
    Deny,
    /// Reject with ICMP / RST.
    Reject,
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Reject => "reject",
        })
    }
}

/// Layer-4 protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        })
    }
}

/// A single firewall rule. Config-agnostic; callers in `spt-bin` translate
/// `[firewall]` + bind addresses into a `Vec<Rule>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rule {
    /// Stable identifier — embedded into the native rule via the
    /// `spt:<id>` comment / group / name so that subsequent `remove()` calls
    /// can match on it for idempotent cleanup.
    pub id: String,
    /// Direction (in/out).
    pub direction: Direction,
    /// Verdict.
    pub action: Action,
    /// Layer-4 protocol.
    pub protocol: Protocol,
    /// Optional source CIDR (e.g. `10.0.0.0/8`). When `None` matches `any`.
    pub source_cidr: Option<String>,
    /// Optional source port. When `None` matches `any`.
    pub source_port: Option<u16>,
    /// Optional destination CIDR.
    pub dest_cidr: Option<String>,
    /// Optional destination port.
    pub dest_port: Option<u16>,
    /// Optional interface name. nftables uses `iif`/`oif`; pf uses `on`;
    /// netsh uses `interfacetype` / explicit interface alias.
    pub interface: Option<String>,
}

/// A rendered firewall plan, ready to be `apply()`d or printed in dry-run.
///
/// The plan is captured as a single multi-line string so tests can snapshot
/// it directly with `insta::assert_snapshot!`. The `manager` discriminator
/// lets `apply()` decide which native command (`nft -f -`, `pfctl -a`,
/// `netsh advfirewall ...`) to invoke.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirewallPlan {
    /// Native rule manager that should consume `script`.
    pub manager: Manager,
    /// The rendered native rule script.
    pub script: String,
    /// Tag prefix used for managed rules — always `"spt:"` followed by the
    /// rule id. Exposed for use in `remove()` and audit output.
    pub tag_prefix: String,
    /// Number of managed rules in the plan (for logging).
    pub rule_count: usize,
}

/// Native firewall manager that produced a plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Manager {
    /// nftables (`nft -f -`).
    Nftables,
    /// iptables (legacy fallback).
    Iptables,
    /// macOS pf (`pfctl -a com.spt -f -`).
    Pf,
    /// Windows Firewall (`netsh advfirewall firewall ...`).
    WindowsFirewall,
}

/// Per-OS firewall planner trait.
///
/// `&self` everywhere so `Box<dyn FirewallPlanner>` works for the dispatcher.
pub trait FirewallPlanner: Send + Sync {
    /// Build a [`FirewallPlan`] from a slice of rules. **Pure**: must not
    /// touch the filesystem, network, or shell. Idempotent — same input
    /// always renders the same output.
    fn plan(&self, rules: &[Rule]) -> FirewallPlan;

    /// Apply a plan. When `dry_run = true` this MUST be a no-op that only
    /// logs the rendered script and returns `Ok(())`. The default
    /// implementation does exactly that, which is what tests rely on.
    /// Per-OS overrides perform the real shell-out.
    fn apply(&self, plan: &FirewallPlan, dry_run: bool) -> Result<()> {
        if dry_run {
            tracing::info!(
                manager = ?plan.manager,
                rules = plan.rule_count,
                "spt-firewall dry-run: rendered plan only, no shell-out"
            );
            tracing::debug!("\n{}", plan.script);
            return Ok(());
        }
        Err(Error::UnsupportedPlatform(format!(
            "real apply for {:?} requires the per-OS planner; default impl refuses to shell out",
            plan.manager
        )))
    }

    /// Remove all rules tagged with `plan.tag_prefix`. Default implementation
    /// returns `UnsupportedPlatform` so unit tests never accidentally execute
    /// real removal commands.
    fn remove(&self, _plan: &FirewallPlan) -> Result<()> {
        Err(Error::UnsupportedPlatform(
            "real remove requires the per-OS planner".to_string(),
        ))
    }
}

/// Pick the planner appropriate to the current platform.
#[allow(clippy::unnecessary_wraps)] // some target_os arms return Err
pub fn new_planner() -> Result<Box<dyn FirewallPlanner>> {
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::NftPlanner::new()))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(macos::PfPlanner::new()))
    }
    #[cfg(target_os = "windows")]
    {
        Ok(Box::new(windows::NetshPlanner::new()))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(Error::UnsupportedPlatform(format!(
            "no firewall planner for target {}",
            std::env::consts::OS
        )))
    }
}

/// Sort + dedupe rules so plans are deterministic regardless of caller order.
pub(crate) fn normalize(rules: &[Rule]) -> Vec<&Rule> {
    let mut out: Vec<&Rule> = rules.iter().collect();
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out.dedup_by(|a, b| a.id == b.id);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "smtp-in".to_string(),
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_cidr: Some("10.0.0.0/8".to_string()),
                source_port: None,
                dest_cidr: None,
                dest_port: Some(2525),
                interface: Some("eth0".to_string()),
            },
            Rule {
                id: "dns-udp".to_string(),
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_cidr: None,
                source_port: None,
                dest_cidr: Some("127.0.0.1/32".to_string()),
                dest_port: Some(5353),
                interface: None,
            },
        ]
    }

    #[test]
    fn nft_plan_is_deterministic() {
        let p = linux::NftPlanner::new();
        let a = p.plan(&sample_rules());
        let mut s = sample_rules();
        s.reverse();
        let b = p.plan(&s);
        assert_eq!(a, b);
    }

    #[test]
    fn pf_plan_is_deterministic() {
        let p = macos::PfPlanner::new();
        let a = p.plan(&sample_rules());
        let mut s = sample_rules();
        s.reverse();
        let b = p.plan(&s);
        assert_eq!(a, b);
    }

    #[test]
    fn netsh_plan_is_deterministic() {
        let p = windows::NetshPlanner::new();
        let a = p.plan(&sample_rules());
        let mut s = sample_rules();
        s.reverse();
        let b = p.plan(&s);
        assert_eq!(a, b);
    }

    #[test]
    fn dry_run_default_is_ok() {
        let p = linux::NftPlanner::new();
        let plan = p.plan(&sample_rules());
        p.apply(&plan, true).expect("dry-run must succeed");
    }

    #[test]
    fn nft_snapshot() {
        let p = linux::NftPlanner::new();
        let plan = p.plan(&sample_rules());
        insta::assert_snapshot!("nft_plan", plan.script);
    }

    #[test]
    fn pf_snapshot() {
        let p = macos::PfPlanner::new();
        let plan = p.plan(&sample_rules());
        insta::assert_snapshot!("pf_plan", plan.script);
    }

    #[test]
    fn netsh_snapshot() {
        let p = windows::NetshPlanner::new();
        let plan = p.plan(&sample_rules());
        insta::assert_snapshot!("netsh_plan", plan.script);
    }

    #[test]
    fn iptables_snapshot() {
        let p = linux::IptablesPlanner::new();
        let plan = p.plan(&sample_rules());
        insta::assert_snapshot!("iptables_plan", plan.script);
    }

    #[test]
    fn empty_plan_is_well_formed() {
        let p = linux::NftPlanner::new();
        let plan = p.plan(&[]);
        assert_eq!(plan.rule_count, 0);
        assert!(plan.script.contains("table"));
    }

    #[test]
    fn duplicate_ids_collapse() {
        let mut rules = sample_rules();
        rules.push(rules[0].clone());
        let p = linux::NftPlanner::new();
        let plan = p.plan(&rules);
        assert_eq!(plan.rule_count, 2, "duplicates by id must be collapsed");
    }
}
