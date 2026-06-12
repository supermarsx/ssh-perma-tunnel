//! Windows Firewall planner — renders `netsh advfirewall firewall` commands.
//!
//! Every managed rule carries `name="spt:<id>"`; that name (which survives
//! `netsh advfirewall firewall show rule`) is what `remove()` matches on for
//! idempotent cleanup. We deliberately do **not** emit `group=` on `add rule`
//! (netsh rejects it — `group=` is only valid on `set rule`) nor any
//! `interface=` parameter (no such parameter exists on `add rule`; the only
//! interface filter netsh accepts is `interfacetype=wired|wireless|ras`, which
//! does not take an adapter name). Apply is gated; tests exercise only `plan()`.

use std::fmt::Write;

#[cfg(target_os = "windows")]
use spt_core::error::Result;

use crate::{normalize, Action, FirewallPlan, FirewallPlanner, Manager, Rule};

/// Logical group name for spt-managed Windows Firewall rules. Reserved for use
/// with `netsh advfirewall firewall set rule group="spt"` (group is **not** a
/// valid parameter on `add rule`, so it is not emitted by the renderer).
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

    /// Apply the plan by replaying each rendered `netsh add rule` line. To stay
    /// idempotent (netsh would otherwise create duplicate rules with the same
    /// name), each rule is deleted by name first, then re-added.
    ///
    /// Live shell-out requires an elevated token; exercised only by
    /// `#[ignore]`-gated tests.
    #[cfg(target_os = "windows")]
    fn apply(&self, plan: &FirewallPlan, dry_run: bool) -> Result<()> {
        if dry_run {
            tracing::info!(rules = plan.rule_count, "spt-firewall netsh dry-run");
            tracing::debug!("\n{}", plan.script);
            return Ok(());
        }
        for cmd in netsh_add_commands(&plan.script) {
            if let Some(name) = parse_rule_name(&cmd) {
                // Best-effort delete of any prior rule with this name; ignore
                // "No rules match" so a first-time apply is not an error.
                let _ = crate::run_native(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name=\"{name}\""),
                    ],
                    None,
                );
            }
            let args: Vec<&str> = cmd.split_whitespace().skip(1).collect();
            crate::run_native("netsh", &args, None)?;
        }
        Ok(())
    }

    /// Remove every spt-managed rule by deleting each `name="spt:<id>"` parsed
    /// from the plan script. Idempotent: missing rules are not an error.
    #[cfg(target_os = "windows")]
    fn remove(&self, plan: &FirewallPlan) -> Result<()> {
        for cmd in netsh_add_commands(&plan.script) {
            if let Some(name) = parse_rule_name(&cmd) {
                let _ = crate::run_native(
                    "netsh",
                    &[
                        "advfirewall",
                        "firewall",
                        "delete",
                        "rule",
                        &format!("name=\"{name}\""),
                    ],
                    None,
                );
            }
        }
        Ok(())
    }

    /// List spt-managed rule ids by parsing
    /// `netsh advfirewall firewall show rule name=all` for `Rule Name:` lines
    /// whose value starts with the `spt:` tag prefix.
    #[cfg(target_os = "windows")]
    fn query_active_rules(&self) -> Result<Vec<String>> {
        let listing = crate::run_native(
            "netsh",
            &["advfirewall", "firewall", "show", "rule", "name=all"],
            None,
        )?;
        Ok(parse_netsh_rule_ids(&listing, TAG_PREFIX))
    }
}

/// Yield the `netsh ... add rule ...` command lines from a rendered plan
/// script, skipping `rem` comments and blank lines.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn netsh_add_commands(script: &str) -> Vec<String> {
    script
        .lines()
        .map(|l| l.trim_end_matches('\r').trim())
        .filter(|l| l.starts_with("netsh"))
        .map(ToString::to_string)
        .collect()
}

/// Extract the `name="..."` value from a rendered netsh command line.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_rule_name(cmd: &str) -> Option<String> {
    let start = cmd.find("name=\"")? + "name=\"".len();
    let rest = &cmd[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// Parse `netsh advfirewall firewall show rule` output, returning the spt rule
/// ids (the suffix after `tag_prefix`) of every `Rule Name:` line that carries
/// our tag. Handles both the English `Rule Name:` label and the bare value by
/// matching the prefix anywhere on the line.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn parse_netsh_rule_ids(listing: &str, prefix: &str) -> Vec<String> {
    let mut ids = Vec::new();
    for line in listing.lines() {
        // Locate the tag prefix; the id runs to end-of-line (netsh prints the
        // rule name as the trailing value of the `Rule Name:` row).
        if let Some(pos) = line.find(prefix) {
            let id = line[pos + prefix.len()..].trim();
            if !id.is_empty() {
                ids.push(id.to_string());
            }
        }
    }
    ids.sort();
    ids.dedup();
    ids
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
    // NOTE: `group=` is not a valid parameter on `netsh advfirewall firewall
    // add rule` (only on `set rule`), and there is no `interface=` parameter at
    // all — emitting either makes netsh reject the whole command. The rule id
    // is carried entirely by `name="spt:<id>"`, which is sufficient for
    // `show rule` / `delete rule name=...` based cleanup.
    let mut parts = vec![
        "netsh advfirewall firewall add rule".to_string(),
        format!("name=\"{TAG_PREFIX}{}\"", r.id),
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
    parts.push("enable=yes".to_string());
    parts.join(" ")
}
