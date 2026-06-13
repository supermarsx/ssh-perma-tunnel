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
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use spt_core::error::{Error, Result};

pub mod linux;
pub mod macos;
pub mod windows;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

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

/// File name (under the state dir) used to persist the last-applied plan so a
/// crashed supervisor can still locate and remove its orphaned rules.
pub const PERSISTED_PLAN_FILE: &str = "firewall-plan.json";

impl FirewallPlan {
    /// Persist this plan as JSON under `state_dir/`[`PERSISTED_PLAN_FILE`] so a
    /// later run (e.g. after a crash) can load it and remove the orphaned
    /// rules. The directory is created if missing.
    ///
    /// # Errors
    /// Returns [`Error::StateLockFailed`] if the directory cannot be created or
    /// the file cannot be written/serialized.
    pub fn persist(&self, state_dir: &Path) -> Result<PathBuf> {
        std::fs::create_dir_all(state_dir).map_err(|e| Error::StateLockFailed {
            path: state_dir.to_path_buf(),
            reason: format!("create state dir for firewall plan: {e}"),
        })?;
        let path = state_dir.join(PERSISTED_PLAN_FILE);
        let json = serde_json::to_string_pretty(self).map_err(|e| Error::StateLockFailed {
            path: path.clone(),
            reason: format!("serialize firewall plan: {e}"),
        })?;
        std::fs::write(&path, json).map_err(|e| Error::StateLockFailed {
            path: path.clone(),
            reason: format!("write firewall plan: {e}"),
        })?;
        Ok(path)
    }

    /// Load a previously [`persist`](Self::persist)ed plan from `state_dir`, if
    /// one exists. Returns `Ok(None)` when no plan file is present (the common
    /// "nothing to clean up" case).
    ///
    /// # Errors
    /// Returns [`Error::StateLockFailed`] if the file exists but cannot be read
    /// or deserialized.
    pub fn load_persisted(state_dir: &Path) -> Result<Option<Self>> {
        let path = state_dir.join(PERSISTED_PLAN_FILE);
        match std::fs::read_to_string(&path) {
            Ok(s) => {
                let plan = serde_json::from_str(&s).map_err(|e| Error::StateLockFailed {
                    path: path.clone(),
                    reason: format!("parse persisted firewall plan: {e}"),
                })?;
                Ok(Some(plan))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::StateLockFailed {
                path,
                reason: format!("read persisted firewall plan: {e}"),
            }),
        }
    }

    /// Delete the persisted-plan file under `state_dir`. Idempotent: a missing
    /// file is treated as success.
    ///
    /// # Errors
    /// Returns [`Error::StateLockFailed`] if an existing file cannot be removed.
    pub fn clear_persisted(state_dir: &Path) -> Result<()> {
        let path = state_dir.join(PERSISTED_PLAN_FILE);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::StateLockFailed {
                path,
                reason: format!("remove persisted firewall plan: {e}"),
            }),
        }
    }
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

    /// Query the currently-applied set of spt-managed rules from the live
    /// firewall (e.g. by parsing `nft list ruleset`, `pfctl -s rules -a com.spt`,
    /// or `netsh advfirewall firewall show rule name="spt:*"`).
    ///
    /// Returns the list of rule IDs (the suffix after `tag_prefix`) currently
    /// installed and tagged as ours. Never shells out from unit tests.
    ///
    /// The default implementation returns `UnsupportedPlatform` so existing
    /// per-OS planners that have not yet implemented live querying continue to
    /// compile without modification. CLI consumers are expected to surface
    /// this as a graceful "no permission / not implemented" message rather
    /// than panicking.
    fn query_active_rules(&self) -> Result<Vec<String>> {
        Err(Error::UnsupportedPlatform(
            "live firewall rule query is not implemented for this platform".to_string(),
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

/// Run a native firewall command, feeding `stdin` (when `Some`) and returning
/// captured stdout on success. Used by the per-OS planners' real apply/remove/
/// query paths. Never invoked by unit tests (which only call `plan()` and the
/// dry-run `apply`); live paths that call this are `#[ignore]`-gated since they
/// require administrator/root privileges.
///
/// # Errors
/// Returns [`Error::RuntimeFailure`] if the process cannot be spawned or exits
/// non-zero (stderr is included in the message).
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) fn run_native(program: &str, args: &[&str], stdin: Option<&str>) -> Result<String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| Error::RuntimeFailure(format!("spawn firewall command `{program}`: {e}")))?;

    if let Some(input) = stdin {
        let mut handle = child
            .stdin
            .take()
            .ok_or_else(|| Error::RuntimeFailure("firewall command stdin unavailable".into()))?;
        handle
            .write_all(input.as_bytes())
            .map_err(|e| Error::RuntimeFailure(format!("write firewall command stdin: {e}")))?;
        // Drop closes stdin so the child can proceed.
        drop(handle);
    }

    let out = child
        .wait_with_output()
        .map_err(|e| Error::RuntimeFailure(format!("await firewall command `{program}`: {e}")))?;

    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        Err(Error::RuntimeFailure(format!(
            "firewall command `{program}` failed (status {}): {}",
            out.status,
            stderr.trim()
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

    /// Rule set with an IPv6 source and destination CIDR — exercises the
    /// `ip6 saddr` / `ip6 daddr` selector dispatch in the nft renderer.
    fn ipv6_rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "v6-in".to_string(),
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_cidr: Some("2001:db8::/32".to_string()),
                source_port: None,
                dest_cidr: Some("::1/128".to_string()),
                dest_port: Some(443),
                interface: None,
            },
            Rule {
                id: "v4-in".to_string(),
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_cidr: Some("10.0.0.0/8".to_string()),
                source_port: None,
                dest_cidr: Some("127.0.0.1/32".to_string()),
                dest_port: Some(80),
                interface: None,
            },
        ]
    }

    #[test]
    fn nft_ipv6_uses_ip6_selector() {
        let p = linux::NftPlanner::new();
        let plan = p.plan(&ipv6_rules());
        // IPv6 CIDRs must use the ip6 selector, not the IPv4-only `ip`.
        assert!(plan.script.contains("ip6 saddr 2001:db8::/32"));
        assert!(plan.script.contains("ip6 daddr ::1/128"));
        // IPv4 rule in the same table still uses `ip`.
        assert!(plan.script.contains("ip saddr 10.0.0.0/8"));
        assert!(plan.script.contains("ip daddr 127.0.0.1/32"));
        // No bare `ip saddr` applied to a v6 literal.
        assert!(!plan.script.contains("ip saddr 2001:db8"));
    }

    #[test]
    fn nft_ipv6_snapshot() {
        let p = linux::NftPlanner::new();
        let plan = p.plan(&ipv6_rules());
        insta::assert_snapshot!("nft_ipv6_plan", plan.script);
    }

    #[test]
    fn nft_prepends_flush_for_idempotency() {
        let p = linux::NftPlanner::new();
        let plan = p.plan(&sample_rules());
        // `add table` then `flush table` must precede the table body so that a
        // repeated `nft -f -` converges instead of duplicating rules.
        let add_pos = plan.script.find("add table inet spt").expect("add table");
        let flush_pos = plan
            .script
            .find("flush table inet spt")
            .expect("flush table");
        let body_pos = plan.script.find("table inet spt {").expect("table body");
        assert!(add_pos < flush_pos, "add must precede flush");
        assert!(flush_pos < body_pos, "flush must precede the table body");
    }

    #[test]
    fn netsh_omits_invalid_params() {
        let p = windows::NetshPlanner::new();
        let plan = p.plan(&sample_rules());
        // `group=` and `interface=` are not valid on `netsh ... add rule`.
        assert!(
            !plan.script.contains("group="),
            "group= must not be emitted: {}",
            plan.script
        );
        assert!(
            !plan.script.contains("interface="),
            "interface= must not be emitted: {}",
            plan.script
        );
        // The rule id is still carried by name=.
        assert!(plan.script.contains("name=\"spt:smtp-in\""));
    }

    #[test]
    fn persist_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = linux::NftPlanner::new();
        let plan = p.plan(&sample_rules());

        assert!(
            FirewallPlan::load_persisted(dir.path())
                .expect("load")
                .is_none(),
            "no plan persisted yet"
        );

        let path = plan.persist(dir.path()).expect("persist");
        assert!(path.exists());

        let loaded = FirewallPlan::load_persisted(dir.path())
            .expect("load")
            .expect("some plan");
        assert_eq!(loaded, plan);

        FirewallPlan::clear_persisted(dir.path()).expect("clear");
        assert!(
            FirewallPlan::load_persisted(dir.path())
                .expect("load")
                .is_none(),
            "plan cleared"
        );
        // Clearing again is a no-op.
        FirewallPlan::clear_persisted(dir.path()).expect("idempotent clear");
    }

    #[test]
    fn nft_parse_comment_ids_extracts_tags() {
        let listing = "
            table inet spt {
                chain input {
                    tcp dport 2525 accept comment \"spt:smtp-in\"
                    udp dport 5353 accept comment \"spt:dns-udp\"
                    tcp dport 80 accept comment \"other:thing\"
                }
            }";
        let ids = linux::parse_comment_ids(listing, "spt:");
        assert_eq!(ids, vec!["dns-udp".to_string(), "smtp-in".to_string()]);
    }

    #[test]
    fn netsh_command_extraction_helpers() {
        let p = windows::NetshPlanner::new();
        let plan = p.plan(&sample_rules());
        let cmds = windows::netsh_add_commands(&plan.script);
        assert_eq!(cmds.len(), plan.rule_count);
        assert!(cmds.iter().all(|c| c.starts_with("netsh")));
        let name = windows::parse_rule_name(&cmds[0]).expect("name");
        assert!(name.starts_with("spt:"));
    }

    #[test]
    fn netsh_parse_rule_ids_extracts_names() {
        let listing = "\
Rule Name:                            spt:smtp-in
----------------------------------------------------------------------
Rule Name:                            spt:dns-udp
----------------------------------------------------------------------
Rule Name:                            SomeOtherRule
";
        let ids = windows::parse_netsh_rule_ids(listing, "spt:");
        assert_eq!(ids, vec!["dns-udp".to_string(), "smtp-in".to_string()]);
    }

    #[test]
    fn pf_parse_label_ids_extracts_labels() {
        let listing = "\
pass in quick proto tcp from any to any port 2525 label \"spt:smtp-in\"
pass in quick proto udp from any to any port 5353 label \"spt:dns-udp\"
pass in quick proto tcp from any to any port 80 label \"unmanaged\"
";
        let ids = macos::parse_label_ids(listing, "spt:");
        assert_eq!(ids, vec!["dns-udp".to_string(), "smtp-in".to_string()]);
    }
}
