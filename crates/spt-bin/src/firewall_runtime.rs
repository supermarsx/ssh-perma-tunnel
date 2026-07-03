//! Wave 6: runtime application of the `[firewall]` config table.
//!
//! Before this wave `[firewall]` was structurally dead — `enabled` / `manager`
//! / `apply_rules` were parsed and validated but never applied to the host
//! firewall. The `spt-firewall` crate already held the full mechanism (per-OS
//! `FirewallPlanner` with real `apply`/`remove`/`query` on Linux/macOS/Windows)
//! and `firewall_ops::compute_rules` already translated the config into a
//! `Vec<Rule>`; only the wiring at `tunnel run` startup was missing.
//!
//! This module bridges that gap: at startup [`maybe_apply`] computes the rules
//! from `[firewall]` + the forward binds, renders a plan, applies it (or
//! plan-only when `apply_rules` is unset), persists it for crash-recovery, and
//! returns a [`FirewallRuntime`] the daemon reverts on shutdown.
//!
//! ## Safety
//!
//! The computed rule set contains ONLY `allow` inbound rules for the configured
//! forward listen ports, and the rendered nft/pf/netsh scripts keep a default
//! `accept` policy. There is therefore NO default-deny that could lock the
//! operator (or the control plane) out — application is fail-safe. A failed
//! apply is likewise non-fatal (WARN + continue): the allow-only rules are not
//! load-bearing for reachability, so the tunnel keeps running without them.

use std::path::{Path, PathBuf};

use spt_config::schema::{Config, Firewall};
use spt_firewall::{new_planner, FirewallPlan, FirewallPlanner};

/// Live handle for an applied firewall plan. Held for the daemon lifetime; on
/// shutdown [`FirewallRuntime::revert`] removes the managed rules and clears the
/// persisted plan artifact.
pub struct FirewallRuntime {
    planner: Box<dyn FirewallPlanner>,
    plan: FirewallPlan,
    state_dir: PathBuf,
    /// True when a real (non-dry-run) apply shelled out; only then does
    /// `revert` attempt a live remove.
    applied: bool,
}

impl FirewallRuntime {
    /// Revert the applied rules on shutdown. Best-effort: logs on failure but
    /// never propagates (teardown must proceed regardless).
    ///
    /// The `planner.remove` shell-out (nft/pf/netsh) runs on a
    /// [`tokio::task::spawn_blocking`] thread so a hung firewall backend cannot
    /// wedge a runtime worker during shutdown (HC3 LOW finding).
    pub async fn revert(self) {
        let FirewallRuntime {
            planner,
            plan,
            state_dir,
            applied,
        } = self;
        if !applied {
            // Plan-only: nothing was installed on the host. Still clear any
            // persisted artifact so a later run won't try to remove phantoms.
            let _ = FirewallPlan::clear_persisted(&state_dir);
            return;
        }
        // Move planner + plan onto a blocking thread for the shell-out, then
        // hand `plan` back for the logging fields.
        let (plan, remove_res) = tokio::task::spawn_blocking(move || {
            let res = planner.remove(&plan);
            (plan, res)
        })
        .await
        .expect("firewall revert blocking task panicked");
        match remove_res {
            Ok(()) => tracing::info!(
                rules = plan.rule_count,
                "[firewall] reverted managed rules on shutdown"
            ),
            Err(e) => tracing::warn!(
                error = %e,
                rules = plan.rule_count,
                "[firewall] failed to revert managed rules on shutdown — they may need \
                 manual cleanup (see `spt firewall status`)"
            ),
        }
        let _ = FirewallPlan::clear_persisted(&state_dir);
    }
}

/// The startup decision, factored out of the I/O so it is unit-testable —
/// including the unsupported-platform branch, which cannot otherwise be reached
/// on a host that DOES have a firewall backend.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// `[firewall]` absent or `enabled != true`.
    Disabled,
    /// `enabled = true` but `manager = "none"` — explicit opt-out.
    ManagerNone,
    /// `enabled = true` but no backend for this platform.
    Unsupported(String),
    /// Apply — `live = true` performs a real host mutation; `false` is
    /// plan-only (dry-run).
    Plan { live: bool },
}

/// Pure decision: what should startup do given the config, whether a backend is
/// available (`Ok`) or not (`Err(reason)`), and the global `--dry-run` flag.
fn decide(fw: &Firewall, backend_available: Result<(), String>, global_dry_run: bool) -> Decision {
    if fw.enabled != Some(true) {
        return Decision::Disabled;
    }
    if fw.manager.as_deref() == Some("none") {
        return Decision::ManagerNone;
    }
    if let Err(reason) = backend_available {
        return Decision::Unsupported(reason);
    }
    // `apply_rules` gates real mutation. Default (unset) or false = plan-only,
    // a safe default so merely enabling `[firewall]` never unexpectedly mutates
    // the host firewall. The global `--dry-run` also forces plan-only.
    Decision::Plan {
        live: fw.apply_rules == Some(true) && !global_dry_run,
    }
}

/// Apply `[firewall]` rules at `tunnel run` startup.
///
/// Returns `Some(FirewallRuntime)` when a plan was (dry-)applied so the caller
/// can revert on shutdown; `None` when firewall is disabled, opted out
/// (`manager = "none"`), unsupported on this platform, or the apply failed. In
/// every non-apply case the reason is logged (INFO for intentional skips, WARN
/// for unsupported/failed) — never a silent no-op.
pub async fn maybe_apply(
    cfg: &Config,
    state_dir: &Path,
    global_dry_run: bool,
) -> Option<FirewallRuntime> {
    let fw = cfg.firewall.as_ref()?;

    let planner_res = new_planner();
    let backend = planner_res
        .as_ref()
        .map(|_| ())
        .map_err(ToString::to_string);

    match decide(fw, backend, global_dry_run) {
        Decision::Disabled => None,
        Decision::ManagerNone => {
            tracing::info!("[firewall] enabled but manager = \"none\" — no rules applied");
            None
        }
        Decision::Unsupported(reason) => {
            tracing::warn!(
                reason = %reason,
                "[firewall] enabled but no firewall backend for this platform — no rules \
                 applied (unsupported platform)"
            );
            None
        }
        Decision::Plan { live } => {
            // `decide` only returns `Plan` when the backend is available.
            let planner = planner_res.expect("backend available when Decision::Plan");
            apply_plan(planner, cfg, state_dir, live).await
        }
    }
}

/// Compute rules, render, persist, and (dry-)apply. Split out so the decision
/// above stays pure.
///
/// The `plan.persist` write and the `planner.apply` shell-out (nft/pf/netsh)
/// run on a [`tokio::task::spawn_blocking`] thread so a hung firewall backend
/// cannot wedge a runtime worker at startup (HC3 LOW finding). Rule computation
/// and rendering are pure/cheap and stay on the async path.
async fn apply_plan(
    planner: Box<dyn FirewallPlanner>,
    cfg: &Config,
    state_dir: &Path,
    live: bool,
) -> Option<FirewallRuntime> {
    let rules = match crate::cli::firewall_ops::compute_rules(cfg, None, None) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                error = %e,
                "[firewall] could not compute rules from config — no rules applied"
            );
            return None;
        }
    };
    let plan = planner.plan(&rules);

    // Move planner + plan onto a blocking thread for the persist + shell-out,
    // then hand them back for the result / logging fields.
    let state_dir_buf = state_dir.to_path_buf();
    let sd = state_dir_buf.clone();
    let (planner, plan, apply_res) = tokio::task::spawn_blocking(move || {
        // Persist BEFORE applying so a crash mid-apply still leaves a record the
        // next run can use for orphan cleanup.
        if live {
            if let Err(e) = plan.persist(&sd) {
                tracing::warn!(error = %e, "[firewall] failed to persist plan for crash-recovery");
            }
        }
        let res = planner.apply(&plan, !live);
        (planner, plan, res)
    })
    .await
    .expect("firewall apply blocking task panicked");

    match apply_res {
        Ok(()) => {
            if live {
                tracing::info!(
                    rules = plan.rule_count,
                    manager = ?plan.manager,
                    "[firewall] applied managed rules"
                );
            } else {
                tracing::info!(
                    rules = plan.rule_count,
                    manager = ?plan.manager,
                    "[firewall] enabled, apply_rules not set — plan-only (dry-run), no host \
                     mutation"
                );
            }
            Some(FirewallRuntime {
                planner,
                plan,
                state_dir: state_dir_buf,
                applied: live,
            })
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                rules = plan.rule_count,
                "[firewall] failed to apply managed rules — continuing without them \
                 (allow-only rules are not load-bearing; forwards still work)"
            );
            let _ = FirewallPlan::clear_persisted(&state_dir_buf);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fw(enabled: Option<bool>, manager: Option<&str>, apply_rules: Option<bool>) -> Firewall {
        Firewall {
            enabled,
            manager: manager.map(str::to_string),
            apply_rules,
            ..Firewall::default()
        }
    }

    #[test]
    fn decide_disabled_when_absent_or_false() {
        assert_eq!(
            decide(&fw(None, None, None), Ok(()), false),
            Decision::Disabled
        );
        assert_eq!(
            decide(&fw(Some(false), None, Some(true)), Ok(()), false),
            Decision::Disabled
        );
    }

    #[test]
    fn decide_manager_none_is_explicit_optout() {
        assert_eq!(
            decide(&fw(Some(true), Some("none"), Some(true)), Ok(()), false),
            Decision::ManagerNone
        );
    }

    // The unsupported-platform branch must NOT be a silent no-op: with no
    // backend available it must produce a distinct `Unsupported` outcome (which
    // `maybe_apply` logs at WARN), never `Disabled`/plan-nothing.
    #[test]
    fn decide_unsupported_when_no_backend() {
        let d = decide(
            &fw(Some(true), None, Some(true)),
            Err("no firewall planner for target xyz".to_string()),
            false,
        );
        assert_eq!(
            d,
            Decision::Unsupported("no firewall planner for target xyz".to_string())
        );
    }

    #[test]
    fn decide_plan_only_by_default() {
        // enabled but apply_rules unset → plan-only (safe default), not live.
        assert_eq!(
            decide(&fw(Some(true), None, None), Ok(()), false),
            Decision::Plan { live: false }
        );
    }

    #[test]
    fn decide_live_only_when_apply_rules_and_not_dry_run() {
        assert_eq!(
            decide(&fw(Some(true), None, Some(true)), Ok(()), false),
            Decision::Plan { live: true }
        );
        // global --dry-run downgrades a live apply to plan-only.
        assert_eq!(
            decide(&fw(Some(true), None, Some(true)), Ok(()), true),
            Decision::Plan { live: false }
        );
    }

    // Integration (no shell-out): enabling firewall in plan-only mode must feed
    // the config-derived forward rules into the planner. Pre-fix there was NO
    // application path at all, so this fails against the dead state.
    #[tokio::test]
    async fn maybe_apply_plan_only_feeds_rules_to_planner() {
        let s = "\
version = 1
[firewall]
enabled = true
# apply_rules unset → plan-only, no host mutation, safe on any test host.

[[profiles]]
name = \"edge\"
protocol = \"ssh2\"
host = \"example.com\"
port = 22

[[profiles.forwards]]
name = \"db\"
type = \"local\"
transport = \"tcp\"
listen = \"127.0.0.1:5432\"
target = \"internal:5432\"

[[profiles.forwards]]
name = \"web\"
type = \"local\"
transport = \"tcp\"
listen = \"127.0.0.1:8080\"
target = \"internal:80\"
";
        let (cfg, _) = spt_config::load_str(s, false).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let rt = maybe_apply(&cfg, dir.path(), false)
            .await
            .expect("plan-only apply returns a runtime");
        // The engine received both forward-derived allow rules.
        assert_eq!(rt.plan.rule_count, 2);
        assert!(
            !rt.applied,
            "apply_rules unset ⇒ plan-only, nothing installed"
        );
        // Plan-only revert must not error and must clear no persisted plan.
        rt.revert().await;
    }

    #[tokio::test]
    async fn maybe_apply_returns_none_when_disabled() {
        let s = "\
version = 1
[firewall]
enabled = false
";
        let (cfg, _) = spt_config::load_str(s, false).unwrap();
        let dir = tempfile::tempdir().unwrap();
        assert!(maybe_apply(&cfg, dir.path(), false).await.is_none());
    }
}
