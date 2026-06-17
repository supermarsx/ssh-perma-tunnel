//! Top-level orchestrator (spec §17.2).
//!
//! Owns a map of [`ProfileSupervisor`]s keyed by profile name and exposes:
//!
//! * [`Orchestrator::start_profile`] / [`Orchestrator::stop_profile`] — base
//!   lifecycle (unchanged).
//! * [`Orchestrator::failover`] — manual / policy-driven endpoint switch.
//! * [`Orchestrator::session_list`] / [`Orchestrator::session_close`] /
//!   [`Orchestrator::session_drain`] — control-channel surfaces consumed by
//!   the CLI's `session` family.
//! * [`Orchestrator::stats_subscribe`] — broadcast of [`StatsTick`]s.
//! * [`Orchestrator::live_connector`] — adapter the bench drivers consume to
//!   open fresh streams over the live tunnel.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use spt_auth::AuthConfig;
use spt_config::schema::Profile;
use spt_core::{Error, Result, SessionId};
use spt_protocol::{Endpoint, TunnelProtocol};
use spt_stats::Ewma;
use tokio::sync::broadcast;
use tokio::task::JoinHandle;

use crate::control::DrainReport;
use crate::live_connector::{LiveConnector, UnavailableConnector};
use crate::profile::{ProfileSupervisor, ProfileSupervisorConfig};
use crate::reload::{ReloadAction, ReloadPlan};
use crate::session::{SessionRegistry, SessionRow};
use crate::stats::{
    flush_metrics, update_throughput_ewma, StatsTick, StatsTickConfig, SupervisorObservers,
};

/// Top-level orchestrator.
pub struct Orchestrator {
    profiles: Mutex<HashMap<String, Arc<ProfileSupervisor>>>,
    registry: SessionRegistry,
    /// Lazily-initialised broadcast handle for stats ticks.
    stats: Mutex<Option<StatsBroadcast>>,
    /// Optional override connector registered by tests / external integrators.
    /// Key: profile name → connector.
    live_overrides: Mutex<HashMap<String, Arc<dyn LiveConnector>>>,
    /// Cached config for the stats tick.
    stats_cfg: StatsTickConfig,
    /// Observability sinks injected by `p4-dispatch-wire` (event bus + standard
    /// metric handles). Threaded into every profile's
    /// [`ProfileSupervisorConfig`] at start, and consumed by the stats-tick task
    /// to populate byte/connection/state metrics. Empty by default (no-op).
    observers: Mutex<SupervisorObservers>,
}

struct StatsBroadcast {
    tx: broadcast::Sender<StatsTick>,
    task: JoinHandle<()>,
}

impl Drop for Orchestrator {
    fn drop(&mut self) {
        // E1-F19: the stats ticker loops unconditionally ("keep ticking — it's
        // cheap"); abort it on orchestrator drop so it doesn't outlive us.
        if let Some(b) = self.stats.lock().take() {
            b.task.abort();
        }
    }
}

impl std::fmt::Debug for Orchestrator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Orchestrator")
            .field("profiles", &self.profiles.lock().keys().collect::<Vec<_>>())
            .finish()
    }
}

impl Default for Orchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl Orchestrator {
    /// New empty orchestrator with default stats-tick config.
    #[must_use]
    pub fn new() -> Self {
        Self::with_stats_config(StatsTickConfig::default())
    }

    /// New orchestrator with a custom [`StatsTickConfig`].
    #[must_use]
    pub fn with_stats_config(stats_cfg: StatsTickConfig) -> Self {
        Self {
            profiles: Mutex::new(HashMap::new()),
            registry: SessionRegistry::new(),
            stats: Mutex::new(None),
            live_overrides: Mutex::new(HashMap::new()),
            stats_cfg,
            observers: Mutex::new(SupervisorObservers::default()),
        }
    }

    /// Inject the canonical [`spt_events::EventBus`] so every profile transition
    /// re-emits as a canonical [`spt_events::Event`] (E6-F1). The bus itself is
    /// constructed by `p4-dispatch-wire` in `cli_dispatch` and handed here.
    ///
    /// Takes effect for profiles started *after* this call (call it before
    /// `start_profile` / `apply`). Returns `self` for builder-style chaining.
    #[must_use]
    pub fn with_event_bus(self, bus: spt_events::EventBus) -> Self {
        self.observers.lock().event_bus = Some(bus);
        self
    }

    /// Inject the standard Prometheus metric handles (E1-F13 / E6-F4). The
    /// exporter is constructed by `p4-dispatch-wire`; pass
    /// `exporter.standard().clone()`. The supervisor increments `reconnects`
    /// and the stats-tick task populates `bytes_in/out`, `forward_active`, and
    /// `profile_state`.
    ///
    /// Takes effect for profiles started *after* this call. Returns `self`.
    #[must_use]
    pub fn with_metrics(self, metrics: spt_observability::metrics::StandardMetrics) -> Self {
        self.observers.lock().metrics = Some(metrics);
        self
    }

    /// Setter form of [`Self::with_event_bus`] for callers holding `&Orchestrator`.
    pub fn set_event_bus(&self, bus: spt_events::EventBus) {
        self.observers.lock().event_bus = Some(bus);
    }

    /// Setter form of [`Self::with_metrics`] for callers holding `&Orchestrator`.
    pub fn set_metrics(&self, metrics: spt_observability::metrics::StandardMetrics) {
        self.observers.lock().metrics = Some(metrics);
    }

    /// Snapshot of the currently-injected observers (used internally to thread
    /// them into each profile's config and the stats-tick task).
    #[must_use]
    fn observers(&self) -> SupervisorObservers {
        self.observers.lock().clone()
    }

    /// Number of profiles currently supervised.
    #[must_use]
    pub fn len(&self) -> usize {
        self.profiles.lock().len()
    }

    /// Whether no profiles are running.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.profiles.lock().is_empty()
    }

    /// Direct handle to a running profile's supervisor, if any. Used by
    /// callers that need to bind a [`crate::LiveReconnectTrigger`] or feed
    /// the supervisor directly into a backend adapter.
    #[must_use]
    pub fn profile_handle(&self, name: &str) -> Option<Arc<ProfileSupervisor>> {
        self.profiles.lock().get(name).cloned()
    }

    /// Shared session registry — exposed for advanced callers (tests + MCP).
    #[must_use]
    pub fn registry(&self) -> SessionRegistry {
        self.registry.clone()
    }

    /// Start a profile.
    ///
    /// E1-F5: if a supervisor for `profile.name` is already running, the old
    /// instance is removed and dropped *before* the new one is spawned. The
    /// displaced [`ProfileSupervisor`]'s `Drop` aborts its task (and signals
    /// shutdown), so the old session/listeners are torn down promptly instead
    /// of leaking and racing the new task for the same ports. For a graceful
    /// (awaited) stop+restart, prefer [`Self::restart_profile`].
    ///
    /// E5-F1: a profile whose `enabled` is explicitly `false` is not started —
    /// any stale instance is still removed and the slot left empty.
    ///
    /// The API stays synchronous so existing call sites are unaffected.
    pub fn start_profile(
        &self,
        profile: &Profile,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        endpoints: Vec<Endpoint>,
        cfg: ProfileSupervisorConfig,
    ) {
        self.start_profile_with_auth(profile, protocol, auth, HashMap::new(), endpoints, cfg);
    }

    /// Start a profile, threading per-endpoint credentials.
    ///
    /// Identical to [`Self::start_profile`] except `auth_by_endpoint` carries the
    /// resolved `(host, port) → AuthConfig` map (multi-auth Phase 3). `auth`
    /// remains the profile-level default used for any endpoint absent from the
    /// map. An empty map reproduces [`Self::start_profile`] exactly.
    pub fn start_profile_with_auth(
        &self,
        profile: &Profile,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        auth_by_endpoint: HashMap<(String, u16), AuthConfig>,
        endpoints: Vec<Endpoint>,
        mut cfg: ProfileSupervisorConfig,
    ) {
        // Remove + drop any existing instance first. Drop aborts its task
        // (E1-F5 backstop), so this is an immediate, synchronous teardown.
        let displaced = self.profiles.lock().remove(&profile.name);
        self.live_overrides.lock().remove(&profile.name);
        drop(displaced);

        if profile.enabled == Some(false) {
            tracing::info!(
                profile = %profile.name,
                "profile is disabled; not starting"
            );
            return;
        }

        // Inject the orchestrator's shared registry so the per-profile task
        // publishes its session row centrally.
        cfg.registry = self.registry.clone();
        // Inject the observability sinks (event bus + metrics) so the profile
        // re-emits canonical events and bumps the reconnect counter (E6-F1 /
        // E1-F13). No-op when nothing was injected.
        cfg.observers = self.observers();
        let sup = ProfileSupervisor::spawn_with_auth(
            profile.name.clone(),
            protocol,
            auth,
            auth_by_endpoint,
            endpoints,
            profile.forwards.clone(),
            cfg,
        );
        self.profiles
            .lock()
            .insert(profile.name.clone(), Arc::new(sup));
    }

    /// Gracefully stop any existing instance of `profile` (awaiting shutdown),
    /// then start the new one. Use this from async contexts that want a clean
    /// handoff; [`Self::start_profile`] is the synchronous best-effort variant.
    pub async fn restart_profile(
        &self,
        profile: &Profile,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        endpoints: Vec<Endpoint>,
        cfg: ProfileSupervisorConfig,
    ) {
        self.restart_profile_with_auth(profile, protocol, auth, HashMap::new(), endpoints, cfg)
            .await;
    }

    /// Per-endpoint-auth variant of [`Self::restart_profile`] (multi-auth
    /// Phase 3). An empty `auth_by_endpoint` reproduces `restart_profile`.
    pub async fn restart_profile_with_auth(
        &self,
        profile: &Profile,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        auth_by_endpoint: HashMap<(String, u16), AuthConfig>,
        endpoints: Vec<Endpoint>,
        cfg: ProfileSupervisorConfig,
    ) {
        self.stop_profile(&profile.name).await;
        self.start_profile_with_auth(profile, protocol, auth, auth_by_endpoint, endpoints, cfg);
    }

    /// Stop a profile, if present, awaiting shutdown.
    pub async fn stop_profile(&self, name: &str) {
        let sup = self.profiles.lock().remove(name);
        self.live_overrides.lock().remove(name);
        if let Some(s) = sup {
            s.stop().await;
        }
    }

    /// Apply a reload plan. New profiles use the values from `provider`, which
    /// resolves auth, endpoints, and config per profile name.
    pub async fn apply<F>(&self, plan: &ReloadPlan, mut provider: F)
    where
        F: FnMut(
            &str,
        ) -> Option<(
            Profile,
            Arc<dyn TunnelProtocol>,
            AuthConfig,
            Vec<Endpoint>,
            ProfileSupervisorConfig,
        )>,
    {
        // Adapt the 5-tuple provider to the per-endpoint-auth provider with an
        // empty map (every endpoint uses the profile-level default).
        self.apply_with_auth(plan, |name| {
            provider(name)
                .map(|(p, proto, auth, eps, cfg)| (p, proto, auth, HashMap::new(), eps, cfg))
        })
        .await;
    }

    /// Per-endpoint-auth variant of [`Self::apply`] (multi-auth Phase 3). The
    /// provider additionally yields the `(host, port) → AuthConfig` map for each
    /// profile; an empty map reproduces [`Self::apply`].
    pub async fn apply_with_auth<F>(&self, plan: &ReloadPlan, mut provider: F)
    where
        F: FnMut(
            &str,
        ) -> Option<(
            Profile,
            Arc<dyn TunnelProtocol>,
            AuthConfig,
            HashMap<(String, u16), AuthConfig>,
            Vec<Endpoint>,
            ProfileSupervisorConfig,
        )>,
    {
        // E1-F7: coalesce the per-forward actions of a profile into a single
        // restart. A reload touching three forwards of one profile must restart
        // it once, not three times (which would sever every other forward's
        // live connections on each pass). We collect the set of profiles that
        // need a forward-driven restart, then apply each exactly once.
        let mut forward_restart: Vec<String> = Vec::new();
        for action in &plan.actions {
            match action {
                ReloadAction::StopProfile(n) => self.stop_profile(n).await,
                ReloadAction::StartProfile(n) | ReloadAction::RestartProfile(n) => {
                    // `restart_profile` gracefully stops any existing instance
                    // first (E1-F5) and `start_profile` skips disabled profiles
                    // (E5-F1), so RestartProfile and StartProfile share a path.
                    if let Some((p, proto, auth, eauth, eps, cfg)) = provider(n) {
                        self.restart_profile_with_auth(&p, proto, auth, eauth, eps, cfg)
                            .await;
                    }
                }
                ReloadAction::AddForward { profile, .. }
                | ReloadAction::RemoveForward { profile, .. }
                | ReloadAction::RestartForward { profile, .. } => {
                    if !forward_restart.iter().any(|p| p == profile) {
                        forward_restart.push(profile.clone());
                    }
                }
            }
        }

        for profile in forward_restart {
            if let Some((p, proto, auth, eauth, eps, cfg)) = provider(&profile) {
                self.restart_profile_with_auth(&p, proto, auth, eauth, eps, cfg)
                    .await;
            }
        }
    }

    /// Stop every profile.
    pub async fn shutdown(&self) {
        let names: Vec<String> = self.profiles.lock().keys().cloned().collect();
        for n in names {
            self.stop_profile(&n).await;
        }
    }

    // -----------------------------------------------------------------------
    // Failover
    // -----------------------------------------------------------------------

    /// Trigger a failover for `profile`. If `endpoint` is `Some("host:port")`
    /// the selector is pinned to that endpoint for the next pick; otherwise
    /// the policy advances to the next priority/weighted choice.
    ///
    /// # Errors
    /// * Profile is not running.
    /// * Endpoint key is malformed (`"host:port"` parsing failure).
    pub async fn failover(&self, profile: &str, endpoint: Option<&str>) -> Result<()> {
        let sup = self.profile(profile)?;
        sup.failover(endpoint).await
    }

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------

    /// Snapshot of every live session.
    #[must_use]
    pub fn session_list(&self) -> Vec<SessionRow> {
        self.registry.snapshot()
    }

    /// Tear down the session identified by `id`, if any. The owning profile
    /// will reconnect.
    ///
    /// # Errors
    /// Returns [`Error::SessionNotFound`] if no live session matches.
    pub async fn session_close(&self, id: &SessionId) -> Result<()> {
        let row = self
            .registry
            .get(id)
            .ok_or_else(|| Error::SessionNotFound(id.as_ref().to_owned()))?;
        let sup = self.profile(&row.profile)?;
        sup.close_session().await
    }

    /// Drain every forward of `profile`: stop accepting new connections,
    /// wait `grace`, then force-close.
    ///
    /// # Errors
    /// Returns an error if `profile` is not running.
    pub async fn session_drain(&self, profile: &str, grace: Duration) -> Result<DrainReport> {
        let sup = self.profile(profile)?;
        sup.drain(grace).await
    }

    // -----------------------------------------------------------------------
    // Stats
    // -----------------------------------------------------------------------

    /// Subscribe to a periodic [`StatsTick`] feed. The first call lazily
    /// spawns a background tick task; subsequent calls share it.
    pub fn stats_subscribe(&self) -> broadcast::Receiver<StatsTick> {
        let mut g = self.stats.lock();
        if g.is_none() {
            let (tx, _rx) = broadcast::channel(self.stats_cfg.channel_capacity);
            let registry = self.registry.clone();
            let interval = self.stats_cfg.interval;
            let half_life = self.stats_cfg.ewma_half_life_secs;
            let tx_clone = tx.clone();
            // E1-F13 / E6-F4: snapshot the injected metric handle (if any) so the
            // flush populates per-profile byte / connection / state metrics.
            let metrics = self.observers.lock().metrics.clone();
            let task = tokio::spawn(async move {
                let ewma = Ewma::new(Duration::from_secs_f64(half_life.max(0.5)));
                let mut prev_total: u64 = 0;
                // Per-profile (bytes_in, bytes_out) high-water mark for monotonic
                // counter deltas across flushes.
                let mut metric_prev: std::collections::BTreeMap<String, (u64, u64)> =
                    std::collections::BTreeMap::new();
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                ticker.tick().await; // first tick is immediate
                loop {
                    ticker.tick().await;
                    let rows = registry.snapshot();
                    let mut tick = StatsTick::from_rows(&rows);
                    // Increment the standard metric counters from this flush.
                    flush_metrics(metrics.as_ref(), &tick, &mut metric_prev);
                    let total = tick.total_bytes_in + tick.total_bytes_out;
                    let bps = update_throughput_ewma(&ewma, prev_total, total, interval);
                    prev_total = total;
                    for ps in &mut tick.profiles {
                        let profile_total = ps.bytes_in + ps.bytes_out;
                        // Per-profile EWMA = total bps × profile share
                        let share = if total == 0 {
                            0.0
                        } else {
                            profile_total as f64 / total as f64
                        };
                        ps.throughput_bps_ewma = bps * share;
                    }
                    if tx_clone.send(tick).is_err() {
                        // No subscribers left; keep ticking — it's cheap.
                    }
                }
            });
            *g = Some(StatsBroadcast { tx, task });
        }
        g.as_ref().unwrap().tx.subscribe()
    }

    // -----------------------------------------------------------------------
    // Live connector
    // -----------------------------------------------------------------------

    /// Override the [`LiveConnector`] returned by [`Self::live_connector`] for
    /// `profile`. Used by tests and integrators that wire a backend-specific
    /// adapter into the orchestrator.
    pub fn set_live_connector(&self, profile: &str, conn: Arc<dyn LiveConnector>) {
        self.live_overrides.lock().insert(profile.to_owned(), conn);
    }

    /// Return a connector that opens fresh streams over the live tunnel
    /// session of `profile`. `forward` is currently informational — backends
    /// that key on a specific forward may consult it; the default
    /// implementation ignores it.
    ///
    /// Resolution order:
    /// 1. An explicit override registered via [`Self::set_live_connector`]
    ///    (tests / integrators) wins.
    /// 2. For a running profile, a [`SupervisorLiveConnector`] over the live
    ///    [`ProfileSupervisor`] — `open_tcp` opens a fresh forward through the
    ///    live session (latency / throughput / limits run genuinely live);
    ///    `open_udp` returns a structured "unsupported" error (no datagram seam
    ///    on the session API).
    /// 3. Otherwise an [`UnavailableConnector`] (profile not running) so the
    ///    caller can shape a uniform error.
    #[must_use]
    pub fn live_connector(&self, profile: &str, _forward: Option<&str>) -> Arc<dyn LiveConnector> {
        if let Some(c) = self.live_overrides.lock().get(profile) {
            return Arc::clone(c);
        }
        if let Some(sup) = self.profiles.lock().get(profile).cloned() {
            // E1-F13: a running profile gets a session-aware connector that
            // opens a real forward through the live tunnel. This replaces the
            // previous "not wired" UnavailableConnector — benchmark TCP traffic
            // now traverses the live session rather than an in-process echo.
            crate::live_connector::SupervisorLiveConnector::arc(sup)
        } else {
            UnavailableConnector::arc(format!("profile `{profile}` not running"))
        }
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn profile(&self, name: &str) -> Result<Arc<ProfileSupervisor>> {
        self.profiles
            .lock()
            .get(name)
            .cloned()
            .ok_or_else(|| {
                Error::runtime_failure(
                    spt_core::Diagnostic::what(format!(
                        "Profile `{name}` is not running"
                    ))
                    .why("no ProfileSupervisor entry exists for the requested name in the orchestrator registry")
                    .how_to_fix(
                        "Run `spt profile list` to see active profiles. Start the profile \
                         with `spt tunnel run --profile <name>` (or its CLI equivalent), or \
                         double-check spelling.",
                    )
                    .endpoint(name.to_string())
                    .retry_advice(spt_core::RetryAdvice::NotRetryable)
                    .build(),
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_auth::AuthConfig;
    use spt_config::load::load_str;
    use spt_forward::testing::MockTunnelProtocol;

    fn auth() -> AuthConfig {
        AuthConfig::new("u", vec![])
    }

    #[tokio::test]
    async fn start_and_stop_profile() {
        let orch = Orchestrator::new();
        let proto = Arc::new(MockTunnelProtocol::new());
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        orch.start_profile(
            &c.profiles[0],
            proto,
            auth(),
            vec![Endpoint::new("h", 22)],
            ProfileSupervisorConfig::default(),
        );
        assert_eq!(orch.len(), 1);
        orch.stop_profile("p").await;
        assert!(orch.is_empty());
    }

    #[tokio::test]
    async fn apply_plan_starts_then_stops() {
        let orch = Orchestrator::new();
        let proto = Arc::new(MockTunnelProtocol::new());
        let proto2 = Arc::clone(&proto);

        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "h"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        let prof = c.profiles[0].clone();

        let plan = ReloadPlan {
            actions: vec![ReloadAction::StartProfile("p".into())],
        };
        orch.apply(&plan, |_| {
            Some((
                prof.clone(),
                proto2.clone(),
                auth(),
                vec![Endpoint::new("h", 22)],
                ProfileSupervisorConfig::default(),
            ))
        })
        .await;
        assert_eq!(orch.len(), 1);

        let plan = ReloadPlan {
            actions: vec![ReloadAction::StopProfile("p".into())],
        };
        orch.apply(&plan, |_| None).await;
        assert!(orch.is_empty());
    }

    fn endpoint(host: &str, port: u16) -> Endpoint {
        Endpoint::new(host, port)
    }

    fn start_running_profile(orch: &Orchestrator) -> Arc<MockTunnelProtocol> {
        let proto = Arc::new(MockTunnelProtocol::new());
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "a"
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        orch.start_profile(
            &c.profiles[0],
            proto.clone(),
            auth(),
            vec![endpoint("a", 22), endpoint("b", 22)],
            ProfileSupervisorConfig::default(),
        );
        proto
    }

    async fn wait_for_session(orch: &Orchestrator) -> SessionRow {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let rows = orch.session_list();
            if !rows.is_empty() {
                return rows[0].clone();
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "session never came up"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    #[tokio::test]
    async fn failover_advances_endpoint() {
        let orch = Orchestrator::new();
        let _proto = start_running_profile(&orch);
        let _row = wait_for_session(&orch).await;

        // Pin to a specific endpoint
        orch.failover("p", Some("b:22")).await.unwrap();
        // Non-running profile errors
        assert!(orch.failover("ghost", None).await.is_err());
        // Bad key errors
        assert!(orch.failover("p", Some("noport")).await.is_err());

        orch.stop_profile("p").await;
    }

    #[tokio::test]
    async fn session_list_close_drain() {
        let orch = Orchestrator::new();
        let _proto = start_running_profile(&orch);
        let row = wait_for_session(&orch).await;

        let rows = orch.session_list();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].profile, "p");

        // session_close: row exists → ok
        orch.session_close(&row.id).await.unwrap();

        // session_close: missing id → SessionNotFound
        let bogus = SessionId::new_v4();
        let err = orch.session_close(&bogus).await.unwrap_err();
        assert!(matches!(err, Error::SessionNotFound(_)));

        // session_drain on running profile
        let report = orch
            .session_drain("p", Duration::from_millis(200))
            .await
            .unwrap();
        let _ = report;

        // session_drain on missing profile errors
        assert!(orch
            .session_drain("ghost", Duration::from_millis(50))
            .await
            .is_err());

        orch.stop_profile("p").await;
    }

    #[tokio::test]
    async fn stats_subscribe_emits_ticks() {
        let cfg = StatsTickConfig {
            interval: Duration::from_millis(50),
            ..Default::default()
        };
        let orch = Orchestrator::with_stats_config(cfg);
        let _proto = start_running_profile(&orch);
        let row = wait_for_session(&orch).await;

        let mut rx = orch.stats_subscribe();
        // Inject byte counters via the registry.
        orch.registry().add_bytes(&row.id, 1024, 2048);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let tick = tokio::time::timeout(Duration::from_millis(200), rx.recv())
                .await
                .ok()
                .and_then(std::result::Result::ok);
            if let Some(t) = tick {
                if t.total_bytes_in == 1024 && t.total_bytes_out == 2048 {
                    assert_eq!(t.total_sessions, 1);
                    assert_eq!(t.profiles.len(), 1);
                    assert_eq!(t.profiles[0].profile, "p");
                    break;
                }
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no matching tick observed"
            );
        }

        orch.stop_profile("p").await;
    }

    #[tokio::test]
    async fn start_profile_replaces_existing_without_leaking() {
        // E1-F5: starting a profile that's already running must stop the old
        // instance first (single entry, no leaked task / port race).
        let orch = Orchestrator::new();
        let _p1 = start_running_profile(&orch);
        assert_eq!(orch.len(), 1);
        let _row = wait_for_session(&orch).await;
        // Start "p" again — should still be exactly one entry.
        let _p2 = start_running_profile(&orch);
        assert_eq!(orch.len(), 1, "double-start must not leak a second entry");
        orch.stop_profile("p").await;
        assert!(orch.is_empty());
    }

    #[tokio::test]
    async fn start_profile_skips_disabled() {
        // E5-F1: a profile with enabled = false is not started.
        let orch = Orchestrator::new();
        let proto = Arc::new(MockTunnelProtocol::new());
        let cfg = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
            host = "a"
            enabled = false
        "#;
        let (c, _) = load_str(cfg, false).unwrap();
        orch.start_profile(
            &c.profiles[0],
            proto,
            auth(),
            vec![endpoint("a", 22)],
            ProfileSupervisorConfig::default(),
        );
        assert!(orch.is_empty(), "disabled profile must not start");
    }

    #[tokio::test]
    async fn live_connector_unavailable_when_not_running() {
        let orch = Orchestrator::new();
        let c = orch.live_connector("ghost", None);
        assert!(c.open_tcp("h", 1).await.is_err());
    }

    #[tokio::test]
    async fn live_connector_running_is_session_aware() {
        // E1-F13: a running profile now yields a session-aware
        // SupervisorLiveConnector rather than a bare UnavailableConnector. It
        // opens a real forward through the live session — but the no-I/O
        // MockTunnelProtocol binds no listener, so the connect honestly fails
        // (no fabricated throughput). open_udp is structurally unsupported.
        let orch = Orchestrator::new();
        let _proto = start_running_profile(&orch);
        let _row = wait_for_session(&orch).await;
        let conn = orch.live_connector("p", None);
        // TCP: opens a live forward; connecting to the (un-served) loopback
        // listener fails against the mock — an honest error, not fake data.
        assert!(conn.open_tcp("ignored", 0).await.is_err());
        // UDP: structured unsupported (no datagram seam on the session API).
        match conn.open_udp().await {
            Err(spt_core::Error::UnsupportedPlatform(_)) => {}
            Err(other) => panic!("expected UnsupportedPlatform, got {other:?}"),
            Ok(_) => panic!("expected UnsupportedPlatform, got Ok"),
        }
        orch.stop_profile("p").await;
    }

    #[tokio::test]
    async fn live_connector_uses_registered_override() {
        // An explicitly registered connector is still honoured for a running
        // profile (the supported wiring path).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let orch = Orchestrator::new();
        let _proto = start_running_profile(&orch);
        let _row = wait_for_session(&orch).await;
        orch.set_live_connector(
            "p",
            Arc::new(crate::live_connector::EchoLiveConnector::default()),
        );
        let conn = orch.live_connector("p", None);
        let mut s = conn.open_tcp("ignored", 0).await.unwrap();
        s.write_all(b"abc").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 3];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");
        orch.stop_profile("p").await;
    }

    // ──────── t8-A1: diagnostic regression tests ──────────────────────

    #[test]
    fn profile_not_running_diagnostic_renders_actionable_text() {
        // Mirrors the converted site in Orchestrator::profile.
        let d = spt_core::Diagnostic::what(format!(
            "Profile `{}` is not running",
            "missing"
        ))
        .why("no ProfileSupervisor entry exists for the requested name in the orchestrator registry")
        .how_to_fix(
            "Run `spt profile list` to see active profiles. Start the profile \
             with `spt tunnel run --profile <name>` (or its CLI equivalent), or \
             double-check spelling.",
        )
        .endpoint("missing".to_string())
        .retry_advice(spt_core::RetryAdvice::NotRetryable)
        .build();
        let e = spt_core::Error::runtime_failure(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "Profile `missing` is not running",
            how_to_fix: "spt profile list",
        );
        assert_eq!(e.exit_code(), spt_core::ExitCode::RuntimeFailure);
    }

    #[tokio::test]
    async fn orchestrator_returns_runtime_failure_for_unknown_profile() {
        // Functional check: calling Orchestrator methods for an unknown
        // profile surfaces our new diagnostic (not a panic, not an opaque
        // string).
        let orch = Orchestrator::new();
        let err = orch.profile("nonexistent").unwrap_err();
        assert_eq!(err.exit_code(), spt_core::ExitCode::RuntimeFailure);
        let d = err.diagnostic().expect("converted site has Diagnostic");
        assert!(d.what.contains("nonexistent"));
        assert!(d.how_to_fix.is_some());
    }
}
