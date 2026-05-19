//! Endpoint selector per spec §11.5.
//!
//! Modes:
//! * `priority` — pick the lowest-priority endpoint that's not in cooldown.
//! * `weighted` — among the lowest-priority cohort, pick by weight.
//! * `manual`   — only return the manually-selected endpoint.
//!
//! ### Round-robin policy hook (t4-e4)
//!
//! When a [`crate::round_robin::EndpointSelector`] is attached via
//! [`EndpointSelector::set_policy_selector`], [`EndpointSelector::pick`]
//! defers to it (after honoring the manual override). This preserves the
//! legacy priority/weighted/manual behavior whenever the round-robin config
//! table is disabled.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex as PlMutex;
use rand::Rng;
use spt_protocol::Endpoint;
use thiserror::Error;
use tokio::time::Instant;

use crate::round_robin::{EndpointPick, EndpointSelector as PolicySelector};

/// Failover mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailoverMode {
    /// Strictly lowest priority among healthy endpoints.
    Priority,
    /// Weighted-random within the lowest-priority cohort.
    Weighted,
    /// Only ever return the manually-selected endpoint.
    Manual,
}

/// A manual override pointing at one endpoint by host:port (composite key).
#[derive(Debug, Clone)]
pub struct ManualOverride {
    /// Host of the endpoint to pin to.
    pub host: String,
    /// Port of the endpoint to pin to.
    pub port: u16,
}

/// Errors from the selector.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SelectorError {
    /// Selector has no endpoints configured.
    #[error("no endpoints configured")]
    Empty,
    /// All endpoints are in cooldown.
    #[error("no healthy endpoints (all in cooldown)")]
    AllCoolingDown,
    /// Manual override does not match any endpoint.
    #[error("manual override `{host}:{port}` not in endpoint list")]
    ManualUnknown {
        /// Host portion of the override.
        host: String,
        /// Port portion of the override.
        port: u16,
    },
}

#[derive(Debug, Clone)]
struct EndpointEntry {
    ep: Endpoint,
    cooldown_until: Option<Instant>,
    consecutive_failures: u32,
}

/// Endpoint selector.
#[derive(Clone)]
pub struct EndpointSelector {
    mode: FailoverMode,
    entries: Vec<EndpointEntry>,
    cooldown_secs_per_failure: u64,
    fail_after: u32,
    manual: Option<ManualOverride>,
    /// Optional round-robin / sticky / weighted policy selector (t4-e4).
    /// When `Some`, [`Self::pick`] delegates to it after honoring the
    /// manual override.
    policy_selector: Option<Arc<PlMutex<Box<dyn PolicySelector>>>>,
}

impl std::fmt::Debug for EndpointSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EndpointSelector")
            .field("mode", &self.mode)
            .field("entries", &self.entries)
            .field("cooldown_secs_per_failure", &self.cooldown_secs_per_failure)
            .field("fail_after", &self.fail_after)
            .field("manual", &self.manual)
            .field("policy_selector", &self.policy_selector.is_some())
            .finish()
    }
}

impl EndpointSelector {
    /// New selector.
    #[must_use]
    pub fn new(mode: FailoverMode, endpoints: Vec<Endpoint>) -> Self {
        Self {
            mode,
            entries: endpoints
                .into_iter()
                .map(|ep| EndpointEntry {
                    ep,
                    cooldown_until: None,
                    consecutive_failures: 0,
                })
                .collect(),
            cooldown_secs_per_failure: 5,
            fail_after: 1,
            manual: None,
            policy_selector: None,
        }
    }

    /// Attach a [`PolicySelector`] (t4-e4). When attached, [`Self::pick`]
    /// delegates to the policy after honoring any manual override; the
    /// caller is responsible for funneling success/failure events back into
    /// the policy via the [`Self::record_success`] / [`Self::record_failure`]
    /// path on this struct (those calls are mirrored into the inner policy).
    pub fn set_policy_selector(&mut self, ps: Option<Box<dyn PolicySelector>>) {
        self.policy_selector = ps.map(|p| Arc::new(PlMutex::new(p)));
    }

    /// Convenience builder mirror of [`Self::set_policy_selector`].
    #[must_use]
    pub fn with_policy_selector(mut self, ps: Option<Box<dyn PolicySelector>>) -> Self {
        self.set_policy_selector(ps);
        self
    }

    /// Returns `true` if a [`PolicySelector`] is currently attached.
    #[must_use]
    pub fn has_policy_selector(&self) -> bool {
        self.policy_selector.is_some()
    }

    /// Try the attached policy selector. Returns `None` if no selector is
    /// attached. Returns `Some(Err(SelectorError::AllCoolingDown))` if the
    /// policy yielded no healthy endpoint. Otherwise resolves to the
    /// matching [`Endpoint`] from this struct's `entries` list (mapping by
    /// `host:port`).
    fn pick_via_policy(&self) -> Option<Result<&Endpoint, SelectorError>> {
        let ps = self.policy_selector.as_ref()?;
        let pick: Option<EndpointPick> = ps.lock().next();
        Some(match pick {
            None => Err(SelectorError::AllCoolingDown),
            Some(pick) => self
                .entries
                .iter()
                .find(|e| format!("{}:{}", e.ep.host, e.ep.port) == pick.id)
                .map(|e| &e.ep)
                // Should not happen: the policy was constructed from the
                // same endpoint list. Surface as Empty rather than panic.
                .ok_or(SelectorError::Empty),
        })
    }

    /// Set per-failure cooldown unit (seconds). The actual cooldown is
    /// `consecutive_failures * cooldown_secs_per_failure` clamped to a minute.
    pub fn with_cooldown(mut self, secs: u64) -> Self {
        self.cooldown_secs_per_failure = secs;
        self
    }

    /// Number of consecutive failures required to enter cooldown.
    pub fn with_fail_after(mut self, n: u32) -> Self {
        self.fail_after = n;
        self
    }

    /// Apply a manual override.
    pub fn set_manual(&mut self, m: Option<ManualOverride>) {
        if let Some(ps) = &self.policy_selector {
            let id = m
                .as_ref()
                .map(|o| format!("{}:{}", o.host, o.port))
                .unwrap_or_default();
            ps.lock().manual_override(&id);
        }
        self.manual = m;
    }

    /// Currently-pinned manual override.
    #[must_use]
    pub fn manual(&self) -> Option<&ManualOverride> {
        self.manual.as_ref()
    }

    /// Number of endpoints not currently in cooldown at `now`.
    #[must_use]
    pub fn healthy_count(&self, now: Instant) -> usize {
        self.entries
            .iter()
            .filter(|e| e.cooldown_until.map(|t| t <= now).unwrap_or(true))
            .count()
    }

    /// Pick the next endpoint to try.
    pub fn pick<R: Rng + ?Sized>(
        &self,
        rng: &mut R,
        now: Instant,
    ) -> Result<&Endpoint, SelectorError> {
        if self.entries.is_empty() {
            return Err(SelectorError::Empty);
        }
        if let Some(m) = &self.manual {
            return self
                .entries
                .iter()
                .find(|e| e.ep.host == m.host && e.ep.port == m.port)
                .map(|e| &e.ep)
                .ok_or_else(|| SelectorError::ManualUnknown {
                    host: m.host.clone(),
                    port: m.port,
                });
        }
        // Delegate to round-robin policy when one is wired in.
        if let Some(result) = self.pick_via_policy() {
            return result;
        }
        if matches!(self.mode, FailoverMode::Manual) {
            return Err(SelectorError::Empty);
        }

        let healthy: Vec<&EndpointEntry> = self
            .entries
            .iter()
            .filter(|e| e.cooldown_until.map(|t| t <= now).unwrap_or(true))
            .collect();
        if healthy.is_empty() {
            return Err(SelectorError::AllCoolingDown);
        }
        // Pick the lowest priority cohort.
        let min_pri = healthy.iter().map(|e| e.ep.priority).min().unwrap();
        let cohort: Vec<&EndpointEntry> = healthy
            .into_iter()
            .filter(|e| e.ep.priority == min_pri)
            .collect();

        match self.mode {
            FailoverMode::Priority => Ok(&cohort[0].ep),
            FailoverMode::Weighted => {
                let total: u64 = cohort.iter().map(|e| e.ep.weight.max(1) as u64).sum();
                if total == 0 {
                    return Ok(&cohort[0].ep);
                }
                let roll: u64 = rng.gen_range(0..total);
                let mut acc = 0u64;
                for e in &cohort {
                    acc += e.ep.weight.max(1) as u64;
                    if roll < acc {
                        return Ok(&e.ep);
                    }
                }
                Ok(&cohort.last().unwrap().ep)
            }
            FailoverMode::Manual => Err(SelectorError::Empty),
        }
    }

    /// Record a successful connection — clears the failure counter.
    pub fn record_success(&mut self, host: &str, port: u16) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.ep.host == host && e.ep.port == port)
        {
            e.consecutive_failures = 0;
            e.cooldown_until = None;
        }
        if let Some(ps) = &self.policy_selector {
            ps.lock().record_success(&format!("{host}:{port}"));
        }
    }

    /// Record a failure, possibly entering cooldown.
    pub fn record_failure(&mut self, host: &str, port: u16, now: Instant) {
        if let Some(e) = self
            .entries
            .iter_mut()
            .find(|e| e.ep.host == host && e.ep.port == port)
        {
            e.consecutive_failures = e.consecutive_failures.saturating_add(1);
            if e.consecutive_failures >= self.fail_after {
                let secs =
                    (e.consecutive_failures as u64).saturating_mul(self.cooldown_secs_per_failure);
                let cap = secs.min(60);
                e.cooldown_until = Some(now + Duration::from_secs(cap));
            }
        }
        if let Some(ps) = &self.policy_selector {
            // Use a generic error since callers may not have an Error handy
            // (current spec keeps the policy err opaque).
            let err = spt_core::Error::NetworkUnreachable(format!("{host}:{port}"));
            ps.lock().record_failure(&format!("{host}:{port}"), &err);
        }
    }

    /// Snapshot of cooldown state per endpoint, keyed by `host:port`.
    pub fn cooldowns(&self) -> HashMap<String, Option<Instant>> {
        self.entries
            .iter()
            .map(|e| (format!("{}:{}", e.ep.host, e.ep.port), e.cooldown_until))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    fn ep(host: &str, port: u16, pri: u32, weight: u32) -> Endpoint {
        Endpoint {
            host: host.into(),
            port,
            address_family: None,
            priority: pri,
            weight,
        }
    }

    #[tokio::test]
    async fn priority_selects_lowest() {
        let mut rng = StdRng::seed_from_u64(0);
        let s = EndpointSelector::new(
            FailoverMode::Priority,
            vec![ep("a", 22, 10, 1), ep("b", 22, 0, 1), ep("c", 22, 5, 1)],
        );
        let pick = s.pick(&mut rng, Instant::now()).unwrap();
        assert_eq!(pick.host, "b");
    }

    #[tokio::test]
    async fn cooldown_blocks_endpoint() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut s = EndpointSelector::new(
            FailoverMode::Priority,
            vec![ep("a", 22, 0, 1), ep("b", 22, 1, 1)],
        )
        .with_fail_after(1)
        .with_cooldown(60);
        let now = Instant::now();
        s.record_failure("a", 22, now);
        let pick = s.pick(&mut rng, now).unwrap();
        assert_eq!(pick.host, "b");
        // After cooldown elapses, "a" returns.
        let later = now + Duration::from_secs(120);
        let pick2 = s.pick(&mut rng, later).unwrap();
        assert_eq!(pick2.host, "a");
    }

    #[tokio::test]
    async fn weighted_distribution_is_biased() {
        let mut rng = StdRng::seed_from_u64(7);
        let s = EndpointSelector::new(
            FailoverMode::Weighted,
            vec![ep("a", 22, 0, 1), ep("b", 22, 0, 9)],
        );
        let mut counts = std::collections::HashMap::new();
        for _ in 0..1000 {
            let p = s.pick(&mut rng, Instant::now()).unwrap();
            *counts.entry(p.host.clone()).or_insert(0u32) += 1;
        }
        let a = *counts.get("a").unwrap_or(&0);
        let b = *counts.get("b").unwrap_or(&0);
        assert!(b > a * 4, "weighted bias: a={a} b={b}");
    }

    #[tokio::test]
    async fn manual_override_pins() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut s = EndpointSelector::new(
            FailoverMode::Priority,
            vec![ep("a", 22, 0, 1), ep("b", 22, 1, 1)],
        );
        s.set_manual(Some(ManualOverride {
            host: "b".into(),
            port: 22,
        }));
        let p = s.pick(&mut rng, Instant::now()).unwrap();
        assert_eq!(p.host, "b");
    }

    #[tokio::test]
    async fn empty_selector_errors() {
        let mut rng = StdRng::seed_from_u64(0);
        let s = EndpointSelector::new(FailoverMode::Priority, vec![]);
        assert_eq!(
            s.pick(&mut rng, Instant::now()).err(),
            Some(SelectorError::Empty)
        );
    }

    #[tokio::test]
    async fn record_success_clears_cooldown() {
        let mut rng = StdRng::seed_from_u64(0);
        let mut s = EndpointSelector::new(FailoverMode::Priority, vec![ep("a", 22, 0, 1)])
            .with_fail_after(1);
        let now = Instant::now();
        s.record_failure("a", 22, now);
        assert!(s.pick(&mut rng, now).is_err());
        s.record_success("a", 22);
        assert!(s.pick(&mut rng, now).is_ok());
    }
}
