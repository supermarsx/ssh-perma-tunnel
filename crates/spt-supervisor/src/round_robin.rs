//! Round-robin / weighted / sticky / least-errors endpoint selection.
//!
//! Implements the t4-e4 selector layer described in
//! `.orchestration/plans/t4.md`. This module is decoupled from the legacy
//! priority/weighted selector in [`crate::failover`] — both can coexist. Phase
//! B will wire a chosen [`EndpointSelector`] into the
//! [`crate::failover::EndpointSelector`] struct via its new
//! `policy_selector` field.
//!
//! Public surface:
//!
//! * [`EndpointSelector`] — trait. Note the name clashes with the legacy
//!   struct re-exported at the crate root; access this trait via
//!   `spt_supervisor::round_robin::EndpointSelector` or the `PolicySelector`
//!   alias re-exported from `lib.rs`.
//! * [`EndpointPick`] — what the trait hands back.
//! * [`RoundRobinSelector`], [`RandomSelector`], [`WeightedSelector`],
//!   [`StickySelector`], [`LeastErrorsSelector`] — one impl per
//!   [`spt_config::round_robin::SelectionPolicy`] variant.
//! * [`DnsResolver`] trait + [`DnsRoundRobinResolver`] — DNS A/AAAA cycler
//!   with configurable refresh interval. Tests use [`FakeDnsResolver`].

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use spt_config::round_robin::{RoundRobinConfig, SelectionPolicy};
use spt_core::Error;
use spt_protocol::Endpoint;
use tokio::time::Instant;

/// Trait every selection-policy implementation satisfies.
///
/// All methods take `&mut self` because every impl tracks per-call state
/// (cursor, sticky pin, error counts, etc.).
pub trait EndpointSelector: Send + Sync {
    /// Pick the next endpoint to try. Returns `None` only when there are no
    /// healthy endpoints — i.e. all are in cooldown.
    fn next(&mut self) -> Option<EndpointPick>;

    /// Record that a connection to `id` succeeded — clears any cooldown.
    fn record_success(&mut self, id: &str);

    /// Record that a connection to `id` failed. The selector may put the
    /// endpoint in cooldown.
    fn record_failure(&mut self, id: &str, err: &Error);

    /// Pin to a specific endpoint id. Subsequent [`Self::next`] calls will
    /// always return that endpoint until the override is cleared with
    /// `manual_override("")` or a fresh selector replaces this one.
    fn manual_override(&mut self, id: &str);
}

/// What [`EndpointSelector::next`] yields.
///
/// The `addr` field is the post-resolution `SocketAddr` chosen for this
/// attempt — when DNS round-robin is enabled, two calls to `next()` for the
/// same endpoint id can return two different `addr`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointPick {
    /// Stable id (composite `host:port`) of the chosen endpoint.
    pub id: String,
    /// Resolved socket address used for this attempt.
    pub addr: SocketAddr,
    /// Weight of the endpoint (1 if unweighted).
    pub weight: u32,
}

/// Internal health state for one endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointHealth {
    Healthy,
    Cooldown(Instant),
    /// Failed permanently within this selector's lifetime — reserved for
    /// future policy that wants a "tombstoned" tier. Currently treated like
    /// a cooldown that never expires (selector will report `AllCoolingDown`).
    #[allow(dead_code)]
    Failed,
}

/// Stable id for an endpoint — `"host:port"`.
fn endpoint_id(ep: &Endpoint) -> String {
    format!("{}:{}", ep.host, ep.port)
}

/// Common state shared by every selector implementation.
#[derive(Debug, Clone)]
struct SelectorCore {
    /// Source endpoint list (insertion order is preserved for round-robin).
    endpoints: Vec<Endpoint>,
    /// Health map keyed by endpoint id.
    health: HashMap<String, EndpointHealth>,
    /// How long a failed endpoint stays in cooldown.
    cooldown: Duration,
    /// Pinned override id, if any.
    manual: Option<String>,
    /// Clock used to compute "now" — `Instant::now` by default; tests inject
    /// a fixed [`InstantClock`].
    clock: Arc<dyn InstantClock>,
}

/// Trivial clock abstraction so cooldown tests don't have to sleep.
pub trait InstantClock: Send + Sync + std::fmt::Debug {
    /// Current monotonic instant.
    fn now(&self) -> Instant;
}

/// Wall-clock implementation of [`InstantClock`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemInstantClock;

impl InstantClock for SystemInstantClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Settable test clock returning whatever instant was last `set`.
#[derive(Debug, Clone)]
pub struct FakeInstantClock {
    inner: Arc<Mutex<Instant>>,
}

impl FakeInstantClock {
    /// New fake clock pinned at `start`.
    #[must_use]
    pub fn new(start: Instant) -> Self {
        Self {
            inner: Arc::new(Mutex::new(start)),
        }
    }

    /// Advance the fake clock by `d`.
    pub fn advance(&self, d: Duration) {
        let mut g = self.inner.lock();
        *g += d;
    }

    /// Set the clock to `t`.
    pub fn set(&self, t: Instant) {
        *self.inner.lock() = t;
    }
}

impl InstantClock for FakeInstantClock {
    fn now(&self) -> Instant {
        *self.inner.lock()
    }
}

impl SelectorCore {
    fn new(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig) -> Self {
        let health = endpoints
            .iter()
            .map(|e| (endpoint_id(e), EndpointHealth::Healthy))
            .collect();
        Self {
            endpoints,
            health,
            cooldown: cfg.cooldown_after_failure,
            manual: None,
            clock: Arc::new(SystemInstantClock),
        }
    }

    fn with_clock(mut self, clock: Arc<dyn InstantClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Is endpoint `id` selectable right now?
    fn is_healthy(&self, id: &str) -> bool {
        match self.health.get(id) {
            Some(EndpointHealth::Healthy) => true,
            Some(EndpointHealth::Cooldown(until)) => self.clock.now() >= *until,
            Some(EndpointHealth::Failed) | None => false,
        }
    }

    /// Promote any cooldown-expired endpoint back to Healthy.
    fn refresh_health(&mut self) {
        let now = self.clock.now();
        for h in self.health.values_mut() {
            if let EndpointHealth::Cooldown(t) = *h {
                if now >= t {
                    *h = EndpointHealth::Healthy;
                }
            }
        }
    }

    fn record_success(&mut self, id: &str) {
        self.health.insert(id.to_owned(), EndpointHealth::Healthy);
    }

    fn record_failure(&mut self, id: &str, _err: &Error) {
        let until = self.clock.now() + self.cooldown;
        self.health
            .insert(id.to_owned(), EndpointHealth::Cooldown(until));
    }

    fn manual_override(&mut self, id: &str) {
        self.manual = if id.is_empty() {
            None
        } else {
            Some(id.to_owned())
        };
    }

    /// Resolve the manual pin, if any, into an [`EndpointPick`].
    ///
    /// F-R1: the pin is only honored while the pinned endpoint is currently
    /// SELECTABLE. If it is in cooldown / known-dead, this returns `None` so the
    /// caller's `next()` falls through to normal policy and picks a healthy
    /// sibling — mirroring the legacy selector's E1-F12 dead-pin protection
    /// (`failover.rs`). Returning the dead pin unconditionally (the pre-fix
    /// behavior) made a round-robin-policy profile retry a dead pinned endpoint
    /// forever, never failing over. The pin resumes automatically once the
    /// endpoint recovers: `next()` calls `refresh_health` before this, so an
    /// expired cooldown is promoted back to `Healthy` and the pin is honored
    /// again.
    fn manual_pick(&self) -> Option<EndpointPick> {
        let id = self.manual.as_ref()?;
        if !self.is_healthy(id) {
            return None;
        }
        self.endpoints
            .iter()
            .find(|e| endpoint_id(e) == *id)
            .map(make_pick)
    }
}

/// Synthesize a `SocketAddr` for an endpoint. When the host is an IP literal
/// we use it; otherwise we fall back to `0.0.0.0:port` and rely on the
/// downstream resolver to fill the real address. The supervisor's
/// connect path always re-resolves anyway.
fn make_pick(ep: &Endpoint) -> EndpointPick {
    let ip: IpAddr = ep.host.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    EndpointPick {
        id: endpoint_id(ep),
        addr: SocketAddr::new(ip, ep.port),
        weight: ep.weight,
    }
}

// ---------------------------------------------------------------------------
// RoundRobinSelector — cycles in declared order.
// ---------------------------------------------------------------------------

/// Pure round-robin: advances through `endpoints` in declared order, skipping
/// endpoints currently in cooldown.
#[derive(Debug)]
pub struct RoundRobinSelector {
    core: SelectorCore,
    cursor: usize,
}

impl RoundRobinSelector {
    /// New round-robin selector.
    #[must_use]
    pub fn new(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig) -> Self {
        Self {
            core: SelectorCore::new(endpoints, cfg),
            cursor: 0,
        }
    }

    /// Override the internal clock — only useful in tests.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn InstantClock>) -> Self {
        self.core = self.core.with_clock(clock);
        self
    }
}

impl EndpointSelector for RoundRobinSelector {
    fn next(&mut self) -> Option<EndpointPick> {
        self.core.refresh_health();
        if let Some(p) = self.core.manual_pick() {
            return Some(p);
        }
        let n = self.core.endpoints.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            let idx = self.cursor % n;
            self.cursor = self.cursor.wrapping_add(1);
            let ep = &self.core.endpoints[idx];
            if self.core.is_healthy(&endpoint_id(ep)) {
                return Some(make_pick(ep));
            }
        }
        None
    }

    fn record_success(&mut self, id: &str) {
        self.core.record_success(id);
    }
    fn record_failure(&mut self, id: &str, err: &Error) {
        self.core.record_failure(id, err);
    }
    fn manual_override(&mut self, id: &str) {
        self.core.manual_override(id);
    }
}

// ---------------------------------------------------------------------------
// RandomSelector — uniform random among healthy endpoints.
// ---------------------------------------------------------------------------

/// Uniformly-random selection across all healthy endpoints.
#[derive(Debug)]
pub struct RandomSelector {
    core: SelectorCore,
    rng: StdRng,
}

impl RandomSelector {
    /// New random selector seeded from entropy.
    #[must_use]
    pub fn new(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig) -> Self {
        Self {
            core: SelectorCore::new(endpoints, cfg),
            rng: StdRng::from_entropy(),
        }
    }

    /// New random selector with a deterministic seed.
    #[must_use]
    pub fn with_seed(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig, seed: u64) -> Self {
        Self {
            core: SelectorCore::new(endpoints, cfg),
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Override the internal clock — test-only helper.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn InstantClock>) -> Self {
        self.core = self.core.with_clock(clock);
        self
    }
}

impl EndpointSelector for RandomSelector {
    fn next(&mut self) -> Option<EndpointPick> {
        self.core.refresh_health();
        if let Some(p) = self.core.manual_pick() {
            return Some(p);
        }
        let healthy: Vec<&Endpoint> = self
            .core
            .endpoints
            .iter()
            .filter(|e| self.core.is_healthy(&endpoint_id(e)))
            .collect();
        if healthy.is_empty() {
            return None;
        }
        let idx = self.rng.gen_range(0..healthy.len());
        Some(make_pick(healthy[idx]))
    }
    fn record_success(&mut self, id: &str) {
        self.core.record_success(id);
    }
    fn record_failure(&mut self, id: &str, err: &Error) {
        self.core.record_failure(id, err);
    }
    fn manual_override(&mut self, id: &str) {
        self.core.manual_override(id);
    }
}

// ---------------------------------------------------------------------------
// WeightedSelector — weighted random by `Endpoint::weight`.
// ---------------------------------------------------------------------------

/// Weighted-random selection — each endpoint is chosen with probability
/// proportional to its [`Endpoint::weight`] (treating 0 as 1).
#[derive(Debug)]
pub struct WeightedSelector {
    core: SelectorCore,
    rng: StdRng,
}

impl WeightedSelector {
    /// New weighted selector seeded from entropy.
    #[must_use]
    pub fn new(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig) -> Self {
        Self {
            core: SelectorCore::new(endpoints, cfg),
            rng: StdRng::from_entropy(),
        }
    }

    /// New weighted selector with a deterministic RNG seed.
    #[must_use]
    pub fn with_seed(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig, seed: u64) -> Self {
        Self {
            core: SelectorCore::new(endpoints, cfg),
            rng: StdRng::seed_from_u64(seed),
        }
    }

    /// Override the internal clock — test-only helper.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn InstantClock>) -> Self {
        self.core = self.core.with_clock(clock);
        self
    }
}

impl EndpointSelector for WeightedSelector {
    fn next(&mut self) -> Option<EndpointPick> {
        self.core.refresh_health();
        if let Some(p) = self.core.manual_pick() {
            return Some(p);
        }
        let healthy: Vec<&Endpoint> = self
            .core
            .endpoints
            .iter()
            .filter(|e| self.core.is_healthy(&endpoint_id(e)))
            .collect();
        if healthy.is_empty() {
            return None;
        }
        let total: u64 = healthy.iter().map(|e| u64::from(e.weight.max(1))).sum();
        if total == 0 {
            return Some(make_pick(healthy[0]));
        }
        let roll: u64 = self.rng.gen_range(0..total);
        let mut acc = 0u64;
        for e in &healthy {
            acc += u64::from(e.weight.max(1));
            if roll < acc {
                return Some(make_pick(e));
            }
        }
        Some(make_pick(healthy.last().copied().unwrap()))
    }
    fn record_success(&mut self, id: &str) {
        self.core.record_success(id);
    }
    fn record_failure(&mut self, id: &str, err: &Error) {
        self.core.record_failure(id, err);
    }
    fn manual_override(&mut self, id: &str) {
        self.core.manual_override(id);
    }
}

// ---------------------------------------------------------------------------
// StickySelector — pin one endpoint for `sticky_session_ttl`.
// ---------------------------------------------------------------------------

/// Pins to the first healthy endpoint for `sticky_session_ttl`. When the TTL
/// expires (or the pinned endpoint becomes unhealthy) the selector advances
/// to the next healthy one and starts a fresh TTL.
#[derive(Debug)]
pub struct StickySelector {
    core: SelectorCore,
    ttl: Duration,
    pinned_id: Option<String>,
    pinned_until: Option<Instant>,
    /// Cursor used when the previous pin expires.
    cursor: usize,
}

impl StickySelector {
    /// New sticky selector.
    #[must_use]
    pub fn new(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig) -> Self {
        Self {
            core: SelectorCore::new(endpoints, cfg),
            ttl: cfg.sticky_session_ttl,
            pinned_id: None,
            pinned_until: None,
            cursor: 0,
        }
    }

    /// Override the internal clock — test-only helper.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn InstantClock>) -> Self {
        self.core = self.core.with_clock(clock);
        self
    }
}

impl EndpointSelector for StickySelector {
    fn next(&mut self) -> Option<EndpointPick> {
        self.core.refresh_health();
        if let Some(p) = self.core.manual_pick() {
            return Some(p);
        }

        let now = self.core.clock.now();

        // If we have a live pin and it's still healthy + TTL not elapsed, reuse.
        if let (Some(id), Some(until)) = (self.pinned_id.as_ref(), self.pinned_until) {
            if now < until && self.core.is_healthy(id) {
                let id_clone = id.clone();
                if let Some(ep) = self
                    .core
                    .endpoints
                    .iter()
                    .find(|e| endpoint_id(e) == id_clone)
                {
                    return Some(make_pick(ep));
                }
            }
        }

        // Otherwise advance: find next healthy starting at cursor.
        let n = self.core.endpoints.len();
        if n == 0 {
            return None;
        }
        for _ in 0..n {
            let idx = self.cursor % n;
            self.cursor = self.cursor.wrapping_add(1);
            let ep = &self.core.endpoints[idx];
            let id = endpoint_id(ep);
            if self.core.is_healthy(&id) {
                self.pinned_id = Some(id);
                self.pinned_until = Some(now + self.ttl);
                return Some(make_pick(ep));
            }
        }
        None
    }
    fn record_success(&mut self, id: &str) {
        self.core.record_success(id);
    }
    fn record_failure(&mut self, id: &str, err: &Error) {
        self.core.record_failure(id, err);
        // Drop the pin so a fresh pick lands on someone else.
        if self.pinned_id.as_deref() == Some(id) {
            self.pinned_id = None;
            self.pinned_until = None;
        }
    }
    fn manual_override(&mut self, id: &str) {
        self.core.manual_override(id);
    }
}

// ---------------------------------------------------------------------------
// LeastErrorsSelector — pick the endpoint with the fewest recorded failures.
// ---------------------------------------------------------------------------

/// Picks the healthy endpoint with the lowest recorded failure count. Ties
/// broken by declared order.
#[derive(Debug)]
pub struct LeastErrorsSelector {
    core: SelectorCore,
    errors: HashMap<String, u64>,
}

impl LeastErrorsSelector {
    /// New least-errors selector.
    #[must_use]
    pub fn new(endpoints: Vec<Endpoint>, cfg: &RoundRobinConfig) -> Self {
        let errors = endpoints.iter().map(|e| (endpoint_id(e), 0u64)).collect();
        Self {
            core: SelectorCore::new(endpoints, cfg),
            errors,
        }
    }

    /// Override the internal clock — test-only helper.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn InstantClock>) -> Self {
        self.core = self.core.with_clock(clock);
        self
    }
}

impl EndpointSelector for LeastErrorsSelector {
    fn next(&mut self) -> Option<EndpointPick> {
        self.core.refresh_health();
        if let Some(p) = self.core.manual_pick() {
            return Some(p);
        }
        let mut best: Option<(&Endpoint, u64)> = None;
        for e in &self.core.endpoints {
            let id = endpoint_id(e);
            if !self.core.is_healthy(&id) {
                continue;
            }
            let err_count = self.errors.get(&id).copied().unwrap_or(0);
            match best {
                None => best = Some((e, err_count)),
                Some((_, curb)) if err_count < curb => best = Some((e, err_count)),
                _ => {}
            }
        }
        best.map(|(e, _)| make_pick(e))
    }
    fn record_success(&mut self, id: &str) {
        self.core.record_success(id);
    }
    fn record_failure(&mut self, id: &str, err: &Error) {
        self.core.record_failure(id, err);
        *self.errors.entry(id.to_owned()).or_insert(0) += 1;
    }
    fn manual_override(&mut self, id: &str) {
        self.core.manual_override(id);
    }
}

// ---------------------------------------------------------------------------
// Factory: build a boxed selector from config + endpoints.
// ---------------------------------------------------------------------------

/// Construct a boxed selector matching `cfg.policy`. Returns `None` when
/// `cfg.enabled == false` — callers should fall back to the legacy
/// [`crate::failover::EndpointSelector`] in that case.
#[must_use]
pub fn make_selector(
    endpoints: Vec<Endpoint>,
    cfg: &RoundRobinConfig,
) -> Option<Box<dyn EndpointSelector>> {
    if !cfg.enabled {
        return None;
    }
    // F1 (w8): `[round_robin].dns_round_robin` + `dns_refresh_interval` are NOT
    // active on the production connect path. The [`DnsRoundRobinResolver`] type
    // exists and is unit-tested with a fake resolver, but there is no production
    // `DnsResolver` impl and — more fundamentally — the selector→connect seam
    // maps a policy pick back to its declared `Endpoint` by `host:port`
    // (`failover::EndpointSelector::pick_via_policy`), discarding any resolved
    // address, so per-IP rotation cannot reach `connect()`. Wiring it end-to-end
    // needs (a) a production resolver here, (b) `pick_via_policy` to carry the
    // resolved `addr` into the emitted endpoint, and (c) the spt-bin/spt-config
    // opt-in — all cross-crate (spt-config + spt-bin are peer-owned). Until then
    // this is warned rather than silently dead.
    if cfg.dns_round_robin {
        tracing::warn!(
            dns_refresh_interval_secs = cfg.dns_refresh_interval.as_secs(),
            "`round_robin.dns_round_robin` is configured but NOT active: DNS-based per-IP \
             rotation is not wired into the production connect path (endpoints rotate at the \
             host level only). Remove the setting or track wiring (spt-config/spt-bin)."
        );
    }
    Some(match cfg.policy {
        SelectionPolicy::RoundRobin => Box::new(RoundRobinSelector::new(endpoints, cfg)),
        SelectionPolicy::Random => Box::new(RandomSelector::new(endpoints, cfg)),
        SelectionPolicy::Weighted => Box::new(WeightedSelector::new(endpoints, cfg)),
        SelectionPolicy::Sticky => Box::new(StickySelector::new(endpoints, cfg)),
        SelectionPolicy::LeastErrors => Box::new(LeastErrorsSelector::new(endpoints, cfg)),
    })
}

// ---------------------------------------------------------------------------
// DNS round-robin resolver.
// ---------------------------------------------------------------------------

/// Pluggable DNS resolver — returns the A/AAAA addresses of one hostname.
pub trait DnsResolver: Send + Sync + std::fmt::Debug {
    /// Resolve `host` to its A/AAAA records.
    fn resolve(&self, host: &str) -> Vec<IpAddr>;
}

/// Test resolver backed by a static `HashMap<hostname, addresses>`.
#[derive(Debug, Default, Clone)]
pub struct FakeDnsResolver {
    inner: Arc<Mutex<HashMap<String, Vec<IpAddr>>>>,
}

impl FakeDnsResolver {
    /// New empty fake resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the resolution for `host`.
    pub fn set(&self, host: impl Into<String>, addrs: Vec<IpAddr>) {
        self.inner.lock().insert(host.into(), addrs);
    }
}

impl DnsResolver for FakeDnsResolver {
    fn resolve(&self, host: &str) -> Vec<IpAddr> {
        self.inner.lock().get(host).cloned().unwrap_or_default()
    }
}

/// Stateful "next address" round-robin over the A/AAAA records of a hostname.
///
/// The resolver is re-queried every `refresh_interval`; TTL from DNS is
/// ignored — `dns_refresh_interval` from config wins (per the t4-e4 spec).
#[derive(Debug)]
pub struct DnsRoundRobinResolver {
    inner: Arc<dyn DnsResolver>,
    refresh_interval: Duration,
    clock: Arc<dyn InstantClock>,
    state: Mutex<DnsState>,
}

#[derive(Debug)]
struct DnsState {
    host: String,
    cached: Vec<IpAddr>,
    last_refresh: Option<Instant>,
    cursor: usize,
}

impl DnsRoundRobinResolver {
    /// New resolver round-robining `host` via `inner`. Calls `inner.resolve()`
    /// lazily on the first [`Self::next_address`] and at most once per
    /// `refresh_interval` afterwards.
    #[must_use]
    pub fn new(
        host: impl Into<String>,
        inner: Arc<dyn DnsResolver>,
        cfg: &RoundRobinConfig,
    ) -> Self {
        Self {
            inner,
            refresh_interval: cfg.dns_refresh_interval,
            clock: Arc::new(SystemInstantClock),
            state: Mutex::new(DnsState {
                host: host.into(),
                cached: Vec::new(),
                last_refresh: None,
                cursor: 0,
            }),
        }
    }

    /// Override the internal clock — test-only helper.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn InstantClock>) -> Self {
        self.clock = clock;
        self
    }

    /// Yield the next IP for the hostname, refreshing the cache if
    /// `refresh_interval` has elapsed since the last refresh.
    pub fn next_address(&self) -> Option<IpAddr> {
        let now = self.clock.now();
        let mut st = self.state.lock();
        let needs_refresh = match st.last_refresh {
            None => true,
            Some(t) => now.saturating_duration_since(t) >= self.refresh_interval,
        };
        if needs_refresh {
            st.cached = self.inner.resolve(&st.host);
            st.last_refresh = Some(now);
            st.cursor = 0;
        }
        if st.cached.is_empty() {
            return None;
        }
        let idx = st.cursor % st.cached.len();
        st.cursor = st.cursor.wrapping_add(1);
        Some(st.cached[idx])
    }

    /// Force a re-resolution on the next [`Self::next_address`].
    pub fn invalidate(&self) {
        let mut st = self.state.lock();
        st.last_refresh = None;
        st.cached.clear();
        st.cursor = 0;
    }
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    fn ep(host: &str, port: u16, weight: u32) -> Endpoint {
        Endpoint {
            host: host.into(),
            port,
            address_family: None,
            priority: 0,
            weight,
        }
    }

    fn enabled_cfg(policy: SelectionPolicy) -> RoundRobinConfig {
        RoundRobinConfig {
            enabled: true,
            policy,
            ..Default::default()
        }
    }

    // ------- RoundRobinSelector -------

    #[test]
    fn round_robin_cycles_declared_order() {
        let cfg = enabled_cfg(SelectionPolicy::RoundRobin);
        let mut s =
            RoundRobinSelector::new(vec![ep("a", 22, 1), ep("b", 22, 1), ep("c", 22, 1)], &cfg);
        let p1 = s.next().unwrap().id;
        let p2 = s.next().unwrap().id;
        let p3 = s.next().unwrap().id;
        let p4 = s.next().unwrap().id;
        assert_eq!(p1, "a:22");
        assert_eq!(p2, "b:22");
        assert_eq!(p3, "c:22");
        assert_eq!(p4, "a:22");
    }

    #[test]
    fn round_robin_skips_cooldown_then_returns_after_expiry() {
        let clock = Arc::new(FakeInstantClock::new(Instant::now()));
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::RoundRobin,
            cooldown_after_failure: Duration::from_secs(30),
            ..Default::default()
        };
        let mut s = RoundRobinSelector::new(vec![ep("a", 22, 1), ep("b", 22, 1)], &cfg)
            .with_clock(clock.clone());

        s.record_failure("a:22", &Error::NetworkUnreachable("x".into()));

        // "a" is in cooldown — selector should jump straight to "b".
        let p = s.next().unwrap();
        assert_eq!(p.id, "b:22");
        let p = s.next().unwrap();
        assert_eq!(p.id, "b:22"); // still cooling down

        // Advance past cooldown.
        clock.advance(Duration::from_secs(31));
        // round-robin cursor may give either; consume up to 2 picks and check
        // that "a" returns at least once.
        let picks: Vec<String> = (0..2).map(|_| s.next().unwrap().id).collect();
        assert!(picks.iter().any(|p| p == "a:22"));
    }

    // ------- RandomSelector -------

    #[test]
    fn random_covers_all_over_1000_rolls() {
        let cfg = enabled_cfg(SelectionPolicy::Random);
        let mut s = RandomSelector::with_seed(
            vec![ep("a", 22, 1), ep("b", 22, 1), ep("c", 22, 1)],
            &cfg,
            42,
        );
        let mut counts: HashMap<String, u32> = HashMap::new();
        for _ in 0..1000 {
            let id = s.next().unwrap().id;
            *counts.entry(id).or_insert(0) += 1;
        }
        for id in ["a:22", "b:22", "c:22"] {
            assert!(*counts.get(id).unwrap_or(&0) > 0, "missed {id}");
        }
    }

    // ------- WeightedSelector -------

    #[test]
    fn weighted_respects_3_2_1_within_5pct() {
        // weights 3:2:1 over 6000 rolls -> expected 3000/2000/1000.
        let cfg = enabled_cfg(SelectionPolicy::Weighted);
        let mut sel = WeightedSelector::with_seed(
            vec![ep("a", 22, 3), ep("b", 22, 2), ep("c", 22, 1)],
            &cfg,
            // Seed picked empirically below — deterministic + within tolerance.
            12345,
        );
        let mut counts: HashMap<String, u32> = HashMap::new();
        let total: u32 = 6000;
        for _ in 0..total {
            let id = sel.next().unwrap().id;
            *counts.entry(id).or_insert(0) += 1;
        }
        let count_a = f64::from(*counts.get("a:22").unwrap_or(&0));
        let count_b = f64::from(*counts.get("b:22").unwrap_or(&0));
        let count_c = f64::from(*counts.get("c:22").unwrap_or(&0));
        let n = f64::from(total);
        let exp_a = n * 3.0 / 6.0;
        let exp_b = n * 2.0 / 6.0;
        let exp_c = n * 1.0 / 6.0;
        let tol = 0.05;
        assert!(
            ((count_a - exp_a) / exp_a).abs() < tol,
            "a={count_a} exp={exp_a} ratio={:.3}",
            (count_a - exp_a) / exp_a
        );
        assert!(
            ((count_b - exp_b) / exp_b).abs() < tol,
            "b={count_b} exp={exp_b} ratio={:.3}",
            (count_b - exp_b) / exp_b
        );
        assert!(
            ((count_c - exp_c) / exp_c).abs() < tol,
            "c={count_c} exp={exp_c} ratio={:.3}",
            (count_c - exp_c) / exp_c
        );
    }

    // ------- StickySelector -------

    #[test]
    fn sticky_holds_for_ttl_then_advances() {
        let clock = Arc::new(FakeInstantClock::new(Instant::now()));
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::Sticky,
            sticky_session_ttl: Duration::from_secs(60),
            ..Default::default()
        };
        let mut s = StickySelector::new(vec![ep("a", 22, 1), ep("b", 22, 1)], &cfg)
            .with_clock(clock.clone());

        let first = s.next().unwrap().id;
        for _ in 0..10 {
            assert_eq!(s.next().unwrap().id, first, "should stick");
        }
        clock.advance(Duration::from_secs(61));
        let second = s.next().unwrap().id;
        assert_ne!(first, second, "should advance after TTL");
    }

    // ------- LeastErrorsSelector -------

    #[test]
    fn least_errors_avoids_noisy_endpoint() {
        let clock = Arc::new(FakeInstantClock::new(Instant::now()));
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::LeastErrors,
            // Set cooldown short so the failed endpoint can come back into
            // contention quickly — the test asserts on error counts not
            // cooldown.
            cooldown_after_failure: Duration::from_millis(1),
            ..Default::default()
        };
        let mut s =
            LeastErrorsSelector::new(vec![ep("a", 22, 1), ep("b", 22, 1), ep("c", 22, 1)], &cfg)
                .with_clock(clock.clone());

        // Make "a" noisy.
        for _ in 0..5 {
            s.record_failure("a:22", &Error::NetworkUnreachable("flap".into()));
        }
        // Advance past cooldown.
        clock.advance(Duration::from_secs(1));

        // 20 picks — "a" should never win because its error count is highest.
        for _ in 0..20 {
            let id = s.next().unwrap().id;
            assert_ne!(id, "a:22", "least-errors picked the noisy one");
        }
    }

    // ------- Manual override -------

    #[test]
    fn manual_override_pins() {
        let cfg = enabled_cfg(SelectionPolicy::RoundRobin);
        let mut s = RoundRobinSelector::new(vec![ep("a", 22, 1), ep("b", 22, 1)], &cfg);
        s.manual_override("b:22");
        for _ in 0..5 {
            assert_eq!(s.next().unwrap().id, "b:22");
        }
        s.manual_override("");
        // Cleared — round-robin resumes.
        let _ = s.next();
    }

    // ------- F-R1: manual pin must not wedge on a dead endpoint -------

    #[test]
    fn manual_pin_falls_through_when_dead_and_resumes_on_recovery() {
        // F-R1: with a round-robin policy attached, an operator-pinned endpoint
        // that dies must NOT be retried forever — the selector falls through to
        // a healthy sibling while the pin is cooling, and resumes the pin once
        // the endpoint recovers (cooldown expiry). Pre-fix, `manual_pick`
        // returned the pin unconditionally so `next()` always yielded the dead
        // endpoint.
        let clock = Arc::new(FakeInstantClock::new(Instant::now()));
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::RoundRobin,
            cooldown_after_failure: Duration::from_secs(30),
            ..Default::default()
        };
        let mut s = RoundRobinSelector::new(vec![ep("a", 22, 1), ep("b", 22, 1)], &cfg)
            .with_clock(clock.clone());

        s.manual_override("a:22");
        // Pin healthy → honored.
        assert_eq!(s.next().unwrap().id, "a:22");

        // Pin dies → cooldown.
        s.record_failure("a:22", &Error::NetworkUnreachable("a down".into()));

        // Must fail over to the healthy sibling, not wedge on the dead pin.
        assert_eq!(s.next().unwrap().id, "b:22");
        assert_eq!(s.next().unwrap().id, "b:22");

        // Recovery: cooldown expires → the pin resumes.
        clock.advance(Duration::from_secs(31));
        assert_eq!(
            s.next().unwrap().id,
            "a:22",
            "pin must resume once the pinned endpoint recovers"
        );
    }

    #[test]
    fn legacy_selector_dead_manual_pin_fails_over_to_sibling() {
        // F-R1 (integration): the round-robin policy attached to the legacy
        // `failover::EndpointSelector`. A manually-pinned endpoint that is
        // cooling must fall through to a sibling instead of returning the dead
        // pin (the exact wedge E1-F12 was written to prevent, defeated by the
        // policy's unconditional `manual_pick`).
        use crate::failover::{EndpointSelector as LegacySelector, FailoverMode};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let endpoints = vec![ep("a", 22, 1), ep("b", 22, 1)];
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::RoundRobin,
            cooldown_after_failure: Duration::from_secs(60),
            ..Default::default()
        };
        let policy = make_selector(endpoints.clone(), &cfg).expect("enabled");
        let mut legacy = LegacySelector::new(FailoverMode::Priority, endpoints)
            .with_fail_after(1)
            .with_cooldown(60)
            .with_policy_selector(Some(policy));

        let mut rng = StdRng::seed_from_u64(0);
        let now = Instant::now();

        // Pin to "a", then "a" dies (cooling in both the legacy entries and the
        // mirrored policy health map).
        legacy.set_manual(Some(crate::failover::ManualOverride {
            host: "a".into(),
            port: 22,
        }));
        legacy.record_failure("a", 22, now);

        // The pin is cooling → legacy falls through to the policy, whose
        // `manual_pick` now also declines the dead pin → sibling "b".
        let pick = legacy.pick(&mut rng, now).unwrap();
        assert_eq!(
            pick.host, "b",
            "a dead manual pin must fail over to a healthy sibling, not wedge on the pin"
        );
    }

    // ------- Cooldown edge: all in cooldown -> None -------

    #[test]
    fn all_cooldown_returns_none() {
        let clock = Arc::new(FakeInstantClock::new(Instant::now()));
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::RoundRobin,
            cooldown_after_failure: Duration::from_secs(30),
            ..Default::default()
        };
        let mut s =
            RoundRobinSelector::new(vec![ep("a", 22, 1), ep("b", 22, 1)], &cfg).with_clock(clock);
        s.record_failure("a:22", &Error::NetworkUnreachable("x".into()));
        s.record_failure("b:22", &Error::NetworkUnreachable("x".into()));
        assert!(s.next().is_none());
    }

    // ------- DnsRoundRobinResolver -------

    #[test]
    fn dns_rr_distributes_evenly_over_four_a_records() {
        let fake = FakeDnsResolver::new();
        fake.set(
            "example.com",
            vec![
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)),
            ],
        );
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::RoundRobin,
            dns_round_robin: true,
            dns_refresh_interval: Duration::from_secs(3600),
            ..Default::default()
        };
        let resolver = DnsRoundRobinResolver::new("example.com", Arc::new(fake), &cfg);
        let mut counts: HashMap<IpAddr, u32> = HashMap::new();
        for _ in 0..100 {
            let ip = resolver.next_address().unwrap();
            *counts.entry(ip).or_insert(0) += 1;
        }
        // Even distribution: each gets exactly 25 (100 / 4 with pure round-robin).
        assert_eq!(counts.len(), 4);
        for (_, n) in counts {
            assert_eq!(n, 25);
        }
    }

    #[test]
    fn dns_rr_refreshes_after_interval() {
        let fake = FakeDnsResolver::new();
        fake.set("h", vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
        let clock = Arc::new(FakeInstantClock::new(Instant::now()));
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::RoundRobin,
            dns_round_robin: true,
            dns_refresh_interval: Duration::from_secs(10),
            ..Default::default()
        };
        let resolver =
            DnsRoundRobinResolver::new("h", Arc::new(fake.clone()), &cfg).with_clock(clock.clone());
        assert_eq!(
            resolver.next_address(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        // Change the fake — but don't advance clock; cached value stays.
        fake.set("h", vec![IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2))]);
        assert_eq!(
            resolver.next_address(),
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
        // Advance past refresh interval.
        clock.advance(Duration::from_secs(11));
        assert_eq!(
            resolver.next_address(),
            Some(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)))
        );
    }

    #[test]
    fn dns_rr_empty_resolution_returns_none() {
        let fake = FakeDnsResolver::new();
        let cfg = RoundRobinConfig {
            enabled: true,
            policy: SelectionPolicy::RoundRobin,
            dns_round_robin: true,
            ..Default::default()
        };
        let resolver = DnsRoundRobinResolver::new("nope", Arc::new(fake), &cfg);
        assert_eq!(resolver.next_address(), None);
    }

    // ------- make_selector factory -------

    #[test]
    fn make_selector_returns_none_when_disabled() {
        let cfg = RoundRobinConfig::default(); // enabled=false
        assert!(make_selector(vec![ep("a", 22, 1)], &cfg).is_none());
    }

    // ------- Integration with the legacy failover::EndpointSelector -------

    #[test]
    fn legacy_selector_delegates_to_attached_policy_after_two_failures() {
        // 3 endpoints, round-robin policy attached. Fail the first two and
        // verify the legacy selector's pick() ends up at the third within a
        // single cycle.
        use crate::failover::{EndpointSelector as LegacySelector, FailoverMode};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let endpoints = vec![ep("a", 22, 1), ep("b", 22, 1), ep("c", 22, 1)];
        let cfg = enabled_cfg(SelectionPolicy::RoundRobin);
        let policy = make_selector(endpoints.clone(), &cfg).expect("enabled");

        let mut legacy = LegacySelector::new(FailoverMode::Priority, endpoints)
            .with_policy_selector(Some(policy));

        let mut rng = StdRng::seed_from_u64(0);

        // First pick = "a" — record failure.
        let p1 = legacy.pick(&mut rng, Instant::now()).unwrap();
        assert_eq!(p1.host, "a");
        legacy.record_failure("a", 22, Instant::now());

        // Next pick = "b" — record failure.
        let p2 = legacy.pick(&mut rng, Instant::now()).unwrap();
        assert_eq!(p2.host, "b");
        legacy.record_failure("b", 22, Instant::now());

        // Next pick should be "c" — round-robin advances past cooldowns.
        let p3 = legacy.pick(&mut rng, Instant::now()).unwrap();
        assert_eq!(p3.host, "c");
    }

    #[test]
    fn legacy_selector_without_policy_keeps_old_behavior() {
        // Sanity: with no policy_selector attached, the legacy selector still
        // uses the priority cohort.
        use crate::failover::{EndpointSelector as LegacySelector, FailoverMode};
        use rand::rngs::StdRng;
        use rand::SeedableRng;

        let mut rng = StdRng::seed_from_u64(0);
        let s = LegacySelector::new(
            FailoverMode::Priority,
            vec![
                Endpoint {
                    host: "x".into(),
                    port: 22,
                    address_family: None,
                    priority: 5,
                    weight: 1,
                },
                Endpoint {
                    host: "y".into(),
                    port: 22,
                    address_family: None,
                    priority: 0,
                    weight: 1,
                },
            ],
        );
        assert!(!s.has_policy_selector());
        let p = s.pick(&mut rng, Instant::now()).unwrap();
        assert_eq!(p.host, "y"); // lowest priority wins
    }

    // ------- MockTunnelProtocol integration -------

    /// Verify the round-robin policy works end-to-end with a mock protocol
    /// driver: a profile with 3 endpoints, fail 2 → 3rd is selected.
    #[tokio::test]
    async fn mock_tunnel_protocol_three_endpoints_two_fail_third_selected() {
        use spt_auth::AuthConfig;
        use spt_forward::testing::MockTunnelProtocol;
        use spt_protocol::TunnelProtocol;
        use std::sync::Arc;

        let mock = Arc::new(MockTunnelProtocol::new());
        let endpoints = vec![ep("alpha", 22, 1), ep("beta", 22, 1), ep("gamma", 22, 1)];
        let cfg = enabled_cfg(SelectionPolicy::RoundRobin);
        let mut policy = make_selector(endpoints.clone(), &cfg).expect("enabled");
        let auth = AuthConfig::new("test", Vec::new());

        // First pick: alpha. Force failure → mark cooldown.
        mock.set_connect_fails(true);
        let p1 = policy.next().unwrap();
        assert_eq!(p1.id, "alpha:22");
        let r1 = (mock.connect(&endpoints[0], &auth)).await;
        assert!(r1.is_err(), "mock should fail");
        policy.record_failure(&p1.id, &spt_core::Error::NetworkUnreachable("alpha".into()));

        // Second pick: beta. Force failure.
        let p2 = policy.next().unwrap();
        assert_eq!(p2.id, "beta:22");
        let r2 = (mock.connect(&endpoints[1], &auth)).await;
        assert!(r2.is_err());
        policy.record_failure(&p2.id, &spt_core::Error::NetworkUnreachable("beta".into()));

        // Third pick: gamma. Stop failing and confirm a session is born.
        mock.set_connect_fails(false);
        let p3 = policy.next().unwrap();
        assert_eq!(p3.id, "gamma:22");
        let r3 = (mock.connect(&endpoints[2], &auth)).await;
        assert!(r3.is_ok(), "third connect should succeed");
        policy.record_success(&p3.id);
        assert_eq!(mock.connect_count(), 1);
    }

    // ------- w8 F1: dns_round_robin is warned, not silently dead -------

    #[test]
    fn dns_round_robin_config_warns_that_it_is_not_active() {
        let sub = crate::log_capture::CaptureSubscriber::new();
        tracing::subscriber::with_default(sub.clone(), || {
            let cfg = RoundRobinConfig {
                enabled: true,
                policy: SelectionPolicy::RoundRobin,
                dns_round_robin: true,
                dns_refresh_interval: Duration::from_secs(42),
                ..Default::default()
            };
            let _ = make_selector(vec![ep("a", 22, 1)], &cfg).expect("enabled");
        });
        let ev = sub
            .find("dns_round_robin")
            .expect("configuring dns_round_robin must emit a not-active WARN, never be silent");
        assert_eq!(ev.level, tracing::Level::WARN);
        assert_eq!(ev.field("dns_refresh_interval_secs"), Some("42"));
    }

    #[test]
    fn dns_round_robin_disabled_does_not_warn() {
        let sub = crate::log_capture::CaptureSubscriber::new();
        tracing::subscriber::with_default(sub.clone(), || {
            let cfg = RoundRobinConfig {
                enabled: true,
                policy: SelectionPolicy::RoundRobin,
                dns_round_robin: false,
                ..Default::default()
            };
            let _ = make_selector(vec![ep("a", 22, 1)], &cfg).expect("enabled");
        });
        assert!(
            sub.find("dns_round_robin").is_none(),
            "no WARN when dns_round_robin is off (behavior-preserving healthy path)"
        );
    }

    #[test]
    fn make_selector_builds_each_policy() {
        for p in [
            SelectionPolicy::RoundRobin,
            SelectionPolicy::Random,
            SelectionPolicy::Weighted,
            SelectionPolicy::Sticky,
            SelectionPolicy::LeastErrors,
        ] {
            let cfg = enabled_cfg(p);
            let mut s = make_selector(vec![ep("a", 22, 1), ep("b", 22, 1)], &cfg).unwrap();
            // Sanity: each selector should yield at least one pick.
            assert!(
                s.next().is_some(),
                "policy {p:?} returned None on first pick"
            );
        }
    }
}
