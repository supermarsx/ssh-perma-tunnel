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
use crate::stats::{update_throughput_ewma, StatsTick, StatsTickConfig};

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
}

struct StatsBroadcast {
    tx: broadcast::Sender<StatsTick>,
    _task: JoinHandle<()>,
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
        }
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
    pub fn start_profile(
        &self,
        profile: &Profile,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        endpoints: Vec<Endpoint>,
        mut cfg: ProfileSupervisorConfig,
    ) {
        // Inject the orchestrator's shared registry so the per-profile task
        // publishes its session row centrally.
        cfg.registry = self.registry.clone();
        let sup = ProfileSupervisor::spawn(
            profile.name.clone(),
            protocol,
            auth,
            endpoints,
            profile.forwards.clone(),
            cfg,
        );
        self.profiles
            .lock()
            .insert(profile.name.clone(), Arc::new(sup));
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
        F: FnMut(&str)
            -> Option<(
                Profile,
                Arc<dyn TunnelProtocol>,
                AuthConfig,
                Vec<Endpoint>,
                ProfileSupervisorConfig,
            )>,
    {
        for action in &plan.actions {
            match action {
                ReloadAction::StopProfile(n) => self.stop_profile(n).await,
                ReloadAction::StartProfile(n) | ReloadAction::RestartProfile(n) => {
                    if matches!(action, ReloadAction::RestartProfile(_)) {
                        self.stop_profile(n).await;
                    }
                    if let Some((p, proto, auth, eps, cfg)) = provider(n) {
                        self.start_profile(&p, proto, auth, eps, cfg);
                    }
                }
                ReloadAction::AddForward { profile, .. }
                | ReloadAction::RemoveForward { profile, .. }
                | ReloadAction::RestartForward { profile, .. } => {
                    self.stop_profile(profile).await;
                    if let Some((p, proto, auth, eps, cfg)) = provider(profile) {
                        self.start_profile(&p, proto, auth, eps, cfg);
                    }
                }
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
            let task = tokio::spawn(async move {
                let ewma = Ewma::new(Duration::from_secs_f64(half_life.max(0.5)));
                let mut prev_total: u64 = 0;
                let mut ticker = tokio::time::interval(interval);
                ticker.set_missed_tick_behavior(
                    tokio::time::MissedTickBehavior::Delay,
                );
                ticker.tick().await; // first tick is immediate
                loop {
                    ticker.tick().await;
                    let rows = registry.snapshot();
                    let mut tick = StatsTick::from_rows(&rows);
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
            *g = Some(StatsBroadcast { tx, _task: task });
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
        self.live_overrides
            .lock()
            .insert(profile.to_owned(), conn);
    }

    /// Return a connector that opens fresh streams over the live tunnel
    /// session of `profile`. `forward` is currently informational — backends
    /// that key on a specific forward may consult it; the default
    /// implementation ignores it.
    ///
    /// If `profile` is not running, an [`UnavailableConnector`] that errors
    /// on every method is returned so the caller can shape error messages
    /// uniformly.
    #[must_use]
    pub fn live_connector(&self, profile: &str, _forward: Option<&str>) -> Arc<dyn LiveConnector> {
        if let Some(c) = self.live_overrides.lock().get(profile) {
            return Arc::clone(c);
        }
        if self.profiles.lock().contains_key(profile) {
            // Default fallback: a useful echo connector. Backends should
            // override via [`set_live_connector`] with their session-aware
            // adapter.
            Arc::new(crate::live_connector::EchoLiveConnector::default())
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
            .ok_or_else(|| Error::RuntimeFailure(format!("profile `{name}` not running")))
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
    async fn live_connector_unavailable_when_not_running() {
        let orch = Orchestrator::new();
        let c = orch.live_connector("ghost", None);
        assert!(c.open_tcp("h", 1).await.is_err());
    }

    #[tokio::test]
    async fn live_connector_running_default_echoes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let orch = Orchestrator::new();
        let _proto = start_running_profile(&orch);
        let _row = wait_for_session(&orch).await;
        let conn = orch.live_connector("p", None);
        let mut s = conn.open_tcp("ignored", 0).await.unwrap();
        s.write_all(b"abc").await.unwrap();
        s.flush().await.unwrap();
        let mut buf = [0u8; 3];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"abc");
        orch.stop_profile("p").await;
    }
}
