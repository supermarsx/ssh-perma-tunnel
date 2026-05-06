//! Firewall present-rule check.
//!
//! Plans the configured rules via the injected [`FirewallPlanner`] and
//! best-effort verifies the OS-level rule table contains rules tagged with
//! `spt:`. The check is **read-only** — never invokes `apply()` or modifies
//! the firewall.
//!
//! Per spec §13.6 + §13.12, `cargo test` MUST NOT shell out to `nft` /
//! `pfctl` / `netsh`. The actual `Command` invocation is therefore guarded
//! and any non-zero exit / missing binary maps to `Status::Skipped`, never
//! `Status::Fail`. Tests cover the framework wiring + the no-handle skip
//! path; live verification is exercised by integration tests in
//! `spt-bin`.

use async_trait::async_trait;
use std::process::Command;

use spt_firewall::{FirewallPlan, Manager};

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Firewall diagnostic.
#[derive(Default, Debug)]
pub struct FirewallDiagnostic {
    /// When true, attempt to query the live firewall. Defaults to false so
    /// `cargo test` never shells out.
    pub probe_live_rules: bool,
}

#[async_trait]
impl Diagnostic for FirewallDiagnostic {
    fn group(&self) -> &str {
        "firewall"
    }
    async fn run(&self, ctx: &DiagnosticContext) -> Vec<Check> {
        let Some(planner) = ctx.firewall_planner.as_ref() else {
            return vec![Check::new(
                "firewall.planner",
                Severity::Medium,
                Status::Skipped,
            )
            .with_evidence("no FirewallPlanner supplied via DiagnosticContext")];
        };
        if ctx.firewall_rules.is_empty() {
            return vec![Check::new("firewall.rules", Severity::Info, Status::Skipped)
                .with_evidence("no firewall rules configured for this profile")];
        }

        let plan = planner.plan(&ctx.firewall_rules);
        let mut out = vec![
            Check::new("firewall.plan", Severity::Info, Status::Pass)
                .with_evidence(format!(
                    "planned {} rules under tag `{}` for {:?}",
                    plan.rule_count, plan.tag_prefix, plan.manager,
                )),
        ];

        if self.probe_live_rules {
            out.push(query_live_rules(&plan));
        } else {
            out.push(
                Check::new("firewall.live_rules", Severity::Info, Status::Skipped)
                    .with_evidence(
                        "live-rules probe disabled (set FirewallDiagnostic.probe_live_rules to enable)",
                    ),
            );
        }

        out
    }
}

fn query_live_rules(plan: &FirewallPlan) -> Check {
    let (cmd, args, needle): (&str, Vec<&str>, String) = match plan.manager {
        Manager::Nftables | Manager::Iptables => {
            ("nft", vec!["list", "ruleset"], plan.tag_prefix.clone())
        }
        Manager::Pf => (
            "pfctl",
            vec!["-a", "com.spt", "-s", "rules"],
            plan.tag_prefix.clone(),
        ),
        Manager::WindowsFirewall => (
            "netsh",
            vec!["advfirewall", "firewall", "show", "rule", "name=all"],
            plan.tag_prefix.clone(),
        ),
    };

    match Command::new(cmd).args(&args).output() {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let present = stdout.contains(&needle);
            if present {
                Check::new("firewall.live_rules", Severity::Info, Status::Pass)
                    .with_evidence(format!("rules tagged `{needle}` present in `{cmd}` output"))
            } else {
                Check::new("firewall.live_rules", Severity::Medium, Status::Warn)
                    .with_evidence(format!(
                        "no rules tagged `{needle}` found in `{cmd}` output ({} bytes)",
                        stdout.len()
                    ))
                    .with_remediation("run `spt firewall apply` to install the planned rules")
            }
        }
        Ok(o) => {
            // Non-zero — likely missing privileges. Skip, not fail.
            Check::new("firewall.live_rules", Severity::Low, Status::Skipped)
                .with_evidence(format!(
                    "`{cmd}` exited {:?}; likely missing privileges",
                    o.status.code()
                ))
                .with_remediation("rerun `spt diagnose` as root / Administrator for live verification")
        }
        Err(e) => Check::new("firewall.live_rules", Severity::Low, Status::Skipped)
            .with_evidence(format!("could not invoke `{cmd}`: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_firewall::{Action, Direction, FirewallPlanner, Protocol, Rule};
    use std::sync::Arc;

    fn sample_rule() -> Rule {
        Rule {
            id: "smtp-in".into(),
            direction: Direction::In,
            action: Action::Allow,
            protocol: Protocol::Tcp,
            source_cidr: None,
            source_port: None,
            dest_cidr: None,
            dest_port: Some(2525),
            interface: None,
        }
    }

    #[tokio::test]
    async fn skipped_without_planner() {
        let r = FirewallDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn skipped_with_planner_but_no_rules() {
        let planner: Arc<dyn FirewallPlanner> = Arc::new(spt_firewall::linux::NftPlanner::new());
        let ctx = DiagnosticContext {
            firewall_planner: Some(planner),
            ..Default::default()
        };
        let r = FirewallDiagnostic::default().run(&ctx).await;
        assert_eq!(r[0].id, "firewall.rules");
        assert_eq!(r[0].status, Status::Skipped);
    }

    #[tokio::test]
    async fn plan_passes_when_rules_supplied() {
        let planner: Arc<dyn FirewallPlanner> = Arc::new(spt_firewall::linux::NftPlanner::new());
        let ctx = DiagnosticContext {
            firewall_planner: Some(planner),
            firewall_rules: vec![sample_rule()],
            ..Default::default()
        };
        let r = FirewallDiagnostic::default().run(&ctx).await;
        assert!(r.iter().any(|c| c.id == "firewall.plan" && c.status == Status::Pass));
        assert!(r
            .iter()
            .any(|c| c.id == "firewall.live_rules" && c.status == Status::Skipped));
    }
}
