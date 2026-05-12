//! Public test facilities for `spt-firewall` (gated behind `feature = "testing"`).
//!
//! This module is intentionally additive: it re-uses the production
//! [`crate::FirewallPlanner`] trait and the [`crate::Rule`] / [`crate::FirewallPlan`]
//! IR. Sibling crates and downstream tests can use these helpers to exercise
//! firewall code paths without touching real `nft` / `pf` / `netsh` binaries.

use std::collections::HashSet;

use parking_lot::Mutex;
use spt_core::error::Result;

use crate::{Action, Direction, FirewallPlan, FirewallPlanner, Manager, Protocol, Rule};

/// One observed call against a [`RecordingPlanner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlannerCall {
    /// `plan(rules)` — the cloned input rules.
    Plan(Vec<Rule>),
    /// `apply(plan, dry_run)`.
    Apply {
        /// The plan that was applied.
        plan: FirewallPlan,
        /// Whether the call requested a dry-run.
        dry_run: bool,
    },
    /// `remove(plan)`.
    Remove(FirewallPlan),
}

/// A [`FirewallPlanner`] that records every call and returns a canned plan.
///
/// ```
/// use spt_firewall::testing::{RecordingPlanner, fixtures};
/// use spt_firewall::FirewallPlanner;
///
/// let p = RecordingPlanner::with_canned_plan_for(&fixtures::sample_rules());
/// let plan = p.plan(&fixtures::sample_rules());
/// assert!(plan.rule_count > 0);
/// assert_eq!(p.calls().len(), 1);
/// ```
#[derive(Debug)]
pub struct RecordingPlanner {
    calls: Mutex<Vec<PlannerCall>>,
    plan: FirewallPlan,
}

impl Default for RecordingPlanner {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingPlanner {
    /// New planner with an empty default canned plan.
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            plan: FirewallPlan {
                manager: Manager::Nftables,
                script: String::new(),
                tag_prefix: "spt:".to_string(),
                rule_count: 0,
            },
        }
    }

    /// New planner that returns `plan` from every `plan()` call.
    #[must_use]
    pub fn with_canned_plan(plan: FirewallPlan) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            plan,
        }
    }

    /// New planner whose canned plan is rendered by the linux nft planner from
    /// `rules`. Convenience for tests that just want a non-empty fixture.
    #[must_use]
    pub fn with_canned_plan_for(rules: &[Rule]) -> Self {
        let plan = crate::linux::NftPlanner::new().plan(rules);
        Self::with_canned_plan(plan)
    }

    /// Snapshot of every call observed so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<PlannerCall> {
        self.calls.lock().clone()
    }

    /// Number of recorded calls of any kind.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().len()
    }
}

impl FirewallPlanner for RecordingPlanner {
    fn plan(&self, rules: &[Rule]) -> FirewallPlan {
        self.calls.lock().push(PlannerCall::Plan(rules.to_vec()));
        self.plan.clone()
    }

    fn apply(&self, plan: &FirewallPlan, dry_run: bool) -> Result<()> {
        self.calls.lock().push(PlannerCall::Apply {
            plan: plan.clone(),
            dry_run,
        });
        Ok(())
    }

    fn remove(&self, plan: &FirewallPlan) -> Result<()> {
        self.calls.lock().push(PlannerCall::Remove(plan.clone()));
        Ok(())
    }
}

/// In-memory store tracking which rule IDs are currently "active". Mirrors
/// apply / remove operations so tests can assert idempotency.
///
/// ```
/// use spt_firewall::testing::{InMemoryRuleStore, fixtures};
///
/// let store = InMemoryRuleStore::new();
/// let rules = fixtures::sample_rules();
/// store.apply_rules(&rules);
/// assert!(store.is_active(&rules[0].id));
/// store.apply_rules(&rules); // idempotent — same active set
/// assert_eq!(store.active_count(), rules.len());
/// store.remove_rules(&rules);
/// assert_eq!(store.active_count(), 0);
/// ```
#[derive(Debug, Default)]
pub struct InMemoryRuleStore {
    active: Mutex<HashSet<String>>,
}

impl InMemoryRuleStore {
    /// New empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark every rule id active. Idempotent — duplicate apply is a no-op.
    pub fn apply_rules(&self, rules: &[Rule]) {
        let mut a = self.active.lock();
        for r in rules {
            a.insert(r.id.clone());
        }
    }

    /// Remove every rule id from the active set. Idempotent.
    pub fn remove_rules(&self, rules: &[Rule]) {
        let mut a = self.active.lock();
        for r in rules {
            a.remove(&r.id);
        }
    }

    /// True if `id` is currently active.
    #[must_use]
    pub fn is_active(&self, id: &str) -> bool {
        self.active.lock().contains(id)
    }

    /// Number of currently-active rule ids.
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.lock().len()
    }

    /// Snapshot of currently-active rule ids (sorted).
    #[must_use]
    pub fn active_ids(&self) -> Vec<String> {
        let mut v: Vec<String> = self.active.lock().iter().cloned().collect();
        v.sort();
        v
    }
}

/// Canonical pre-built fixtures for tests.
pub mod fixtures {
    use super::{Action, Direction, Protocol, Rule};

    /// A representative rule set covering both directions and TCP+UDP, with
    /// a mix of allow and deny verdicts. Useful when a test needs "some
    /// realistic rules" without caring about the exact contents.
    ///
    /// Returned rules:
    /// - `smtp-in-allow` — inbound TCP allow (port 2525)
    /// - `smtp-out-allow` — outbound TCP allow
    /// - `dns-in-allow` — inbound UDP allow (port 5353)
    /// - `dns-out-allow` — outbound UDP allow
    /// - `block-ssh-in` — inbound TCP deny (port 22)
    /// - `block-quic-out` — outbound UDP deny (port 443)
    ///
    /// ```
    /// let rules = spt_firewall::testing::fixtures::sample_rules();
    /// assert!(!rules.is_empty());
    /// ```
    #[must_use]
    pub fn sample_rules() -> Vec<Rule> {
        vec![
            Rule {
                id: "smtp-in-allow".into(),
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_cidr: Some("10.0.0.0/8".into()),
                source_port: None,
                dest_cidr: None,
                dest_port: Some(2525),
                interface: Some("eth0".into()),
            },
            Rule {
                id: "smtp-out-allow".into(),
                direction: Direction::Out,
                action: Action::Allow,
                protocol: Protocol::Tcp,
                source_cidr: None,
                source_port: None,
                dest_cidr: Some("10.0.0.0/8".into()),
                dest_port: Some(25),
                interface: None,
            },
            Rule {
                id: "dns-in-allow".into(),
                direction: Direction::In,
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_cidr: None,
                source_port: None,
                dest_cidr: Some("127.0.0.1/32".into()),
                dest_port: Some(5353),
                interface: None,
            },
            Rule {
                id: "dns-out-allow".into(),
                direction: Direction::Out,
                action: Action::Allow,
                protocol: Protocol::Udp,
                source_cidr: None,
                source_port: None,
                dest_cidr: None,
                dest_port: Some(53),
                interface: None,
            },
            Rule {
                id: "block-ssh-in".into(),
                direction: Direction::In,
                action: Action::Deny,
                protocol: Protocol::Tcp,
                source_cidr: None,
                source_port: None,
                dest_cidr: None,
                dest_port: Some(22),
                interface: None,
            },
            Rule {
                id: "block-quic-out".into(),
                direction: Direction::Out,
                action: Action::Deny,
                protocol: Protocol::Udp,
                source_cidr: None,
                source_port: None,
                dest_cidr: None,
                dest_port: Some(443),
                interface: None,
            },
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recording_planner_records_plan_apply_remove() {
        let p = RecordingPlanner::with_canned_plan_for(&fixtures::sample_rules());
        let plan = p.plan(&fixtures::sample_rules());
        p.apply(&plan, true).unwrap();
        p.remove(&plan).unwrap();
        let calls = p.calls();
        assert_eq!(calls.len(), 3);
        assert!(matches!(calls[0], PlannerCall::Plan(_)));
        assert!(matches!(calls[1], PlannerCall::Apply { dry_run: true, .. }));
        assert!(matches!(calls[2], PlannerCall::Remove(_)));
    }

    #[test]
    fn rule_store_is_idempotent() {
        let store = InMemoryRuleStore::new();
        let rules = fixtures::sample_rules();
        store.apply_rules(&rules);
        let first = store.active_count();
        // Apply the same plan again — second apply doesn't change the active set.
        store.apply_rules(&rules);
        assert_eq!(store.active_count(), first);
        assert_eq!(store.active_count(), rules.len());
    }

    #[test]
    fn fixtures_cover_directions_and_protocols() {
        let rules = fixtures::sample_rules();
        assert!(rules
            .iter()
            .any(|r| r.direction == Direction::In && r.protocol == Protocol::Tcp));
        assert!(rules
            .iter()
            .any(|r| r.direction == Direction::Out && r.protocol == Protocol::Tcp));
        assert!(rules
            .iter()
            .any(|r| r.direction == Direction::In && r.protocol == Protocol::Udp));
        assert!(rules
            .iter()
            .any(|r| r.direction == Direction::Out && r.protocol == Protocol::Udp));
        assert!(rules.iter().any(|r| r.action == Action::Allow));
        assert!(rules.iter().any(|r| r.action == Action::Deny));
    }
}
