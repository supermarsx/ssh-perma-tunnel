//! Per-profile supervisor: wraps the [`ProfileStateMachine`] with the
//! reconnect / instability / failover state, drives a [`TunnelProtocol`], and
//! owns one [`ForwardRunner`] per configured forward.
//!
//! ## Control channel
//!
//! The task started by [`ProfileSupervisor::spawn`] listens on an
//! `mpsc::Sender<Control>` rather than a single shutdown oneshot. This lets
//! the orchestrator drive manual failover, session close, drain, and live
//! connector requests against the running profile.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::Mutex;
use rand::SeedableRng;
use spt_auth::AuthConfig;
use spt_config::schema::Forward;
use spt_core::{Error, Result, SessionId};
use spt_forward::{ForwardRunner, ForwardRunnerConfig};
use spt_protocol::{Endpoint, TunnelProtocol, TunnelSession};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::{Instant, MissedTickBehavior};

use crate::control::{Control, DrainReport};
use crate::failover::{EndpointSelector, FailoverMode, ManualOverride};
use crate::instability::{InstabilityAction, InstabilityDetector, InstabilityWindow};
use crate::reconnect::{Backoff, BackoffConfig};
use crate::session::{SessionRegistry, SessionRow};
use crate::state_machine::{ProfileEvent as SmEvent, ProfileStateMachine, ProfileStateName};
use crate::stats::SupervisorObservers;

/// Public observable events emitted by a [`ProfileSupervisor`].
#[derive(Debug, Clone)]
pub enum ProfileEvent {
    /// State transition `from → to`.
    StateChanged {
        /// Profile name.
        profile: String,
        /// Previous state.
        from: ProfileStateName,
        /// New state.
        to: ProfileStateName,
    },
    /// A reconnect attempt is starting after `delay`.
    ReconnectScheduled {
        /// Profile name.
        profile: String,
        /// Sleep before next attempt.
        delay: Duration,
        /// Attempt number (1-based on first try).
        attempt: u32,
    },
    /// Backoff exhausted — supervisor stops attempting.
    BackoffExhausted {
        /// Profile name.
        profile: String,
    },
    /// Instability detector triggered.
    InstabilityHit {
        /// Profile name.
        profile: String,
    },
    /// Instability detector cleared.
    InstabilityCleared {
        /// Profile name.
        profile: String,
    },
    /// External actor requested a failover. Payload is the optional manual
    /// endpoint override (`"host:port"`).
    FailoverRequested {
        /// Profile name.
        profile: String,
        /// Optional override.
        override_to: Option<String>,
    },
}

/// Endpoint health-probe style used by the failover/liveness check.
///
/// Mirrors `[profiles.failover].health_check`. The default
/// ([`HealthCheckStyle::SshHandshake`]) reproduces today's fixed behavior: the
/// supervisor's liveness probe is `TunnelSession::keepalive()`, an SSH-level
/// round-trip over the already-established session (not a bare TCP connect, not
/// a full re-auth, not an SSH3 endpoint probe).
///
/// CONSUMER (Wave C): the probe site that decides *how* to verify a candidate
/// endpoint / live session is healthy. Today that is the keepalive arm in
/// `profile.rs::ProfileTask::run_active` (and, for candidate endpoints, the
/// connect path). Wave C selects the probe implementation from this style;
/// unimplemented styles are validated/REJECTED upstream (see validate.rs in
/// Wave B2) so an unsupported style never silently no-ops.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthCheckStyle {
    /// Bare TCP connect to the endpoint (cheapest; no SSH exchange).
    TcpConnect,
    /// SSH transport handshake / keepalive round-trip over the live session
    /// (today's fixed behavior — the default).
    SshHandshake,
    /// Full SSH connect + auth preflight against the endpoint.
    SshAuthPreflight,
    /// SSH3 (QUIC) endpoint probe.
    Ssh3Endpoint,
}

impl Default for HealthCheckStyle {
    fn default() -> Self {
        // Matches today's probe: TunnelSession::keepalive() is an SSH-level
        // liveness round-trip over the established session.
        Self::SshHandshake
    }
}

/// Tunables for a [`ProfileSupervisor`].
#[derive(Debug, Clone)]
pub struct ProfileSupervisorConfig {
    /// Backoff parameters.
    pub backoff: BackoffConfig,
    /// Failover mode.
    pub failover_mode: FailoverMode,
    /// Consecutive endpoint failures before cooldown.
    pub failover_fail_after: u32,
    /// Cooldown unit used before an endpoint is eligible again.
    pub failover_cooldown: Duration,
    /// Health-probe style for the failover/liveness check. See
    /// [`HealthCheckStyle`]. Default [`HealthCheckStyle::SshHandshake`] =
    /// today's fixed behavior. The probe-site consumer is wired in Wave C.
    pub health_check: HealthCheckStyle,
    /// Instability detector parameters.
    pub instability: InstabilityWindow,
    /// Optional override for the runner.
    pub runner_cfg: ForwardRunnerConfig,
    /// Interval between in-`run_active` session-health polls
    /// (`TunnelSession::keepalive`). When the keepalive returns `Err`, the
    /// supervisor triggers a reconnect — see spec §11.3 ("missed keepalives
    /// beyond policy MUST trigger session replacement"). Default 30 s.
    pub keepalive_interval: Duration,
    /// Per-probe timeout bounding a single `TunnelSession::keepalive` call,
    /// independent of the probe cadence ([`Self::keepalive_interval`]).
    ///
    /// INVARIANT: `keepalive_timeout` MUST exceed the worst-case *healthy*
    /// round-trip latency of a live link (which can be multi-second on a slow
    /// but functioning path), and is deliberately decoupled from the cadence.
    /// Coupling the timeout to the interval would abort a healthy-but-slow
    /// probe and misclassify it as `SessionLost`, producing a spurious
    /// reconnect storm. Default 10 s. See E1-F11.
    pub keepalive_timeout: Duration,
    /// RNG seed (for deterministic tests). `None` ⇒ entropy.
    pub rng_seed: Option<u64>,
    /// Shared registry to publish session rows into. Default = a fresh
    /// per-supervisor registry; the [`crate::Orchestrator`] injects its own.
    pub registry: SessionRegistry,
    /// Optional observability sinks (canonical event bus + standard metric
    /// handles). Default = empty (every hook is a no-op). `p4-dispatch-wire`
    /// injects a wired set via [`crate::Orchestrator::with_event_bus`] /
    /// [`crate::Orchestrator::with_metrics`]; the orchestrator threads them in
    /// here when it spawns each profile. See E6-F1 / E1-F13.
    pub observers: SupervisorObservers,
}

impl Default for ProfileSupervisorConfig {
    fn default() -> Self {
        Self {
            backoff: BackoffConfig::default(),
            failover_mode: FailoverMode::Priority,
            failover_fail_after: 1,
            failover_cooldown: Duration::from_secs(5),
            health_check: HealthCheckStyle::default(),
            instability: InstabilityWindow::default(),
            runner_cfg: ForwardRunnerConfig::default(),
            keepalive_interval: Duration::from_secs(30),
            keepalive_timeout: Duration::from_secs(10),
            rng_seed: None,
            registry: SessionRegistry::new(),
            observers: SupervisorObservers::default(),
        }
    }
}

/// Per-profile supervisor.
pub struct ProfileSupervisor {
    name: String,
    state_rx: watch::Receiver<ProfileStateName>,
    events_rx: Mutex<Option<mpsc::Receiver<ProfileEvent>>>,
    control: mpsc::Sender<Control>,
    join: Mutex<Option<JoinHandle<()>>>,
    /// External access to the live failover selector for tests.
    selector: Arc<Mutex<EndpointSelector>>,
    /// Tracks the currently-published session id for this supervisor.
    current_session: Arc<Mutex<Option<SessionId>>>,
    /// Whether the backing protocol can open client-initiated UDP forwards
    /// (SSH3). Captured at spawn so the bench live connector can gate its UDP
    /// driver without re-reaching the protocol object.
    supports_udp: bool,
}

impl std::fmt::Debug for ProfileSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProfileSupervisor")
            .field("name", &self.name)
            .field("state", &*self.state_rx.borrow())
            .finish()
    }
}

impl ProfileSupervisor {
    /// Spawn a supervisor for `name` driving `protocol` against `endpoints`,
    /// opening `forwards` once a session establishes.
    ///
    /// `auth` is the profile-level / global default credential, used for any
    /// endpoint that has no per-endpoint override. To supply per-endpoint
    /// credentials, use [`Self::spawn_with_auth`].
    pub fn spawn(
        name: impl Into<String>,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        endpoints: Vec<Endpoint>,
        forwards: Vec<Forward>,
        cfg: ProfileSupervisorConfig,
    ) -> Self {
        Self::spawn_with_auth(
            name,
            protocol,
            auth,
            HashMap::new(),
            endpoints,
            forwards,
            cfg,
        )
    }

    /// Spawn a supervisor with per-endpoint authentication.
    ///
    /// `default_auth` is the profile-level fallback credential; `auth_by_endpoint`
    /// maps `(host, port)` to the resolved [`AuthConfig`] for that specific
    /// endpoint. At connect time the supervisor looks the chosen endpoint up in
    /// the map and uses its credential, falling back to `default_auth` when the
    /// endpoint has no entry. Passing an empty map reproduces the behaviour of
    /// [`Self::spawn`] exactly (every endpoint uses `default_auth`).
    pub fn spawn_with_auth(
        name: impl Into<String>,
        protocol: Arc<dyn TunnelProtocol>,
        default_auth: AuthConfig,
        auth_by_endpoint: HashMap<(String, u16), AuthConfig>,
        endpoints: Vec<Endpoint>,
        forwards: Vec<Forward>,
        cfg: ProfileSupervisorConfig,
    ) -> Self {
        let auth = default_auth;
        let name: String = name.into();
        // Capture UDP capability before `protocol` is moved into the task so the
        // bench live connector can gate its UDP driver (E1-F13 live bench).
        let supports_udp = protocol.capabilities().local_udp;
        let (state_tx, state_rx) = watch::channel(ProfileStateName::Idle);
        let (events_tx, events_rx) = mpsc::channel(PROFILE_EVENTS_CHANNEL_CAP);
        let (control_tx, control_rx) = mpsc::channel(16);

        let selector = Arc::new(Mutex::new(
            EndpointSelector::new(cfg.failover_mode, endpoints)
                .with_fail_after(cfg.failover_fail_after)
                .with_cooldown(cfg.failover_cooldown.as_secs()),
        ));
        let current_session: Arc<Mutex<Option<SessionId>>> = Arc::new(Mutex::new(None));
        let registry = cfg.registry.clone();
        // E1-F17: hold the failover RNG in the task rather than reseeding it on
        // every pick. With `rng_seed` set this makes weighted picks advance
        // deterministically; in entropy mode it avoids per-pick seeding cost.
        let rng: rand::rngs::StdRng = match cfg.rng_seed {
            Some(s) => SeedableRng::seed_from_u64(s),
            None => SeedableRng::from_entropy(),
        };
        let task = ProfileTask {
            name: name.clone(),
            protocol,
            auth,
            auth_by_endpoint,
            forwards,
            cfg,
            state_tx,
            events_tx,
            sm: ProfileStateMachine::new(),
            backoff: Backoff::new(BackoffConfig::default()),
            instability: InstabilityDetector::new(InstabilityWindow::default()),
            selector: Arc::clone(&selector),
            registry,
            current_session: Arc::clone(&current_session),
            session_up_since: None,
            rng,
            current_endpoint: None,
            last_instability_action: None,
        };
        let join = tokio::spawn(task.run(control_rx));

        Self {
            name,
            state_rx,
            events_rx: Mutex::new(Some(events_rx)),
            control: control_tx,
            join: Mutex::new(Some(join)),
            selector,
            current_session,
            supports_udp,
        }
    }

    /// Whether the backing protocol can open client-initiated UDP forwards.
    #[must_use]
    pub fn supports_udp(&self) -> bool {
        self.supports_udp
    }

    /// Profile name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Current state.
    #[must_use]
    pub fn state(&self) -> ProfileStateName {
        *self.state_rx.borrow()
    }

    /// Subscribe to state changes.
    pub fn watch_state(&self) -> watch::Receiver<ProfileStateName> {
        self.state_rx.clone()
    }

    /// Take the events stream — only the first caller succeeds.
    pub fn take_events(&self) -> Option<mpsc::Receiver<ProfileEvent>> {
        self.events_rx.lock().take()
    }

    /// Shared reference to the underlying [`EndpointSelector`] for tests
    /// and MCP control surfaces.
    pub fn selector(&self) -> Arc<Mutex<EndpointSelector>> {
        Arc::clone(&self.selector)
    }

    /// Currently-active session id, if any.
    #[must_use]
    pub fn current_session(&self) -> Option<SessionId> {
        self.current_session.lock().clone()
    }

    /// Request a failover. If `override_to` is `Some("host:port")`, the
    /// selector is pinned to that endpoint for the next pick; otherwise the
    /// current session is closed and the next pick proceeds per the failover
    /// policy.
    pub async fn failover(&self, override_to: Option<&str>) -> Result<()> {
        let key = override_to.map(str::to_owned);
        let (reply, rx) = oneshot::channel();
        self.control
            .send(Control::Failover {
                override_to: key,
                reply,
            })
            .await
            .map_err(|_| {
                Error::runtime_failure(
                    spt_core::Diagnostic::what("Cannot trigger failover: supervisor not running")
                        .why("the supervisor's control channel is closed — the task has exited")
                        .how_to_fix(
                            "Restart the profile (`spt profile restart <name>` or equivalent). \
                             Check recent logs for the underlying exit reason.",
                        )
                        .retry_advice(spt_core::RetryAdvice::NotRetryable)
                        .build(),
                )
            })?;
        rx.await.map_err(|_| {
            Error::runtime_failure(
                spt_core::Diagnostic::what("Supervisor failover reply was dropped")
                    .why("the oneshot sender was closed before responding — supervisor likely panicked")
                    .how_to_fix(
                        "Inspect the supervisor logs for a panic backtrace and file a bug. \
                         Retry once the profile is restarted.",
                    )
                    .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                    .build(),
            )
        })?
    }

    /// Force the current session closed; reconnect logic still applies.
    pub async fn close_session(&self) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.control
            .send(Control::CloseSession { reply })
            .await
            .map_err(|_| Error::RuntimeFailure("supervisor not running".into()))?;
        rx.await
            .map_err(|_| Error::RuntimeFailure("supervisor reply lost".into()))?
    }

    /// Open a fresh TCP forward through the **live** session for benchmarking.
    ///
    /// Returns a [`crate::control::BenchForward`] whose `local_addr` a caller
    /// connects to (driving bytes through the live tunnel) and whose `guard`,
    /// when dropped, tears the forward down. Errors with a structured
    /// "no live session" diagnostic if the profile is not currently Active.
    pub async fn open_bench_forward(&self) -> Result<crate::control::BenchForward> {
        let (reply, rx) = oneshot::channel();
        self.control
            .send(Control::OpenBenchForward { reply })
            .await
            .map_err(|_| Error::RuntimeFailure("supervisor not running".into()))?;
        rx.await
            .map_err(|_| Error::RuntimeFailure("supervisor reply lost".into()))?
    }

    /// Drain the profile: stop accepting new connections, wait `grace`, then
    /// force-close.
    pub async fn drain(&self, grace: Duration) -> Result<DrainReport> {
        let (reply, rx) = oneshot::channel();
        self.control
            .send(Control::Drain { grace, reply })
            .await
            .map_err(|_| Error::RuntimeFailure("supervisor not running".into()))?;
        rx.await
            .map_err(|_| Error::RuntimeFailure("supervisor reply lost".into()))?
    }

    /// Shut the supervisor down and join its task.
    pub async fn stop(&self) {
        let _ = self.control.send(Control::Shutdown).await;
        let join = self.join.lock().take();
        if let Some(j) = join {
            let _ = j.await;
        }
    }
}

impl Drop for ProfileSupervisor {
    fn drop(&mut self) {
        // Best-effort signal — non-blocking.
        let _ = self.control.try_send(Control::Shutdown);
        // E1-F5: abort the task as a backstop so a displaced supervisor cannot
        // keep its session and bound listeners alive (the `try_send` above can
        // silently fail if the 16-slot control channel is full). Callers that
        // need a graceful stop use `stop().await`, which takes the join handle
        // before drop runs.
        if let Some(j) = self.join.lock().take() {
            j.abort();
        }
    }
}

// ---------------------------------------------------------------------------
// Task
// ---------------------------------------------------------------------------

struct ProfileTask {
    name: String,
    protocol: Arc<dyn TunnelProtocol>,
    /// Profile-level / global default credential. Used at connect time for any
    /// endpoint that has no entry in [`Self::auth_by_endpoint`].
    auth: AuthConfig,
    /// Per-endpoint resolved credentials keyed by `(host, port)`. Populated from
    /// `ProfileBundle.endpoint_auth` (multi-auth Phase 3). Empty ⇒ every endpoint
    /// falls back to [`Self::auth`] (the pre-feature behaviour).
    auth_by_endpoint: HashMap<(String, u16), AuthConfig>,
    forwards: Vec<Forward>,
    cfg: ProfileSupervisorConfig,
    state_tx: watch::Sender<ProfileStateName>,
    events_tx: mpsc::Sender<ProfileEvent>,
    sm: ProfileStateMachine,
    backoff: Backoff,
    instability: InstabilityDetector,
    selector: Arc<Mutex<EndpointSelector>>,
    registry: SessionRegistry,
    current_session: Arc<Mutex<Option<SessionId>>>,
    /// `Some(t)` while a session is up *and* has reached `ForwardsUp`.
    /// Set when forwards come up; cleared when the active session exits
    /// (cleanly or via failure). Used by [`Self::maybe_reset_backoff`] to
    /// honour `BackoffConfig::reset_after` per spec §11.2:
    /// "Backoff MUST reset after a stable connected duration."
    session_up_since: Option<Instant>,
    /// E1-F17: long-lived failover RNG. Held across picks so a seeded
    /// supervisor advances its weighted choices instead of repeating the
    /// first pick forever.
    rng: rand::rngs::StdRng,
    /// Endpoint backing the currently-active session, recorded at connect
    /// time so a keepalive-detected loss can charge the failure to the right
    /// endpoint (E1-F3).
    current_endpoint: Option<Endpoint>,
    /// F-S1: timestamp of the last instability-driven LIVE failover/restart.
    /// Used as a storm guard so a live-session instability trip that drives a
    /// real teardown cannot fire more often than
    /// [`INSTABILITY_ACTION_MIN_INTERVAL`], independent of the detector's own
    /// trip latch. `None` until the first such action fires.
    last_instability_action: Option<Instant>,
}

/// A per-forward slot inside [`ProfileTask::run_active`]: the owned runner,
/// a clone of its state watch, and the config needed to reopen it (E1-F4).
struct ForwardSlot {
    runner: Option<ForwardRunner>,
    watch_rx: watch::Receiver<spt_protocol::ForwardState>,
    name: String,
    cfg: Option<Forward>,
}

impl ForwardSlot {
    fn runner_state(&self) -> spt_protocol::ForwardState {
        *self.watch_rx.borrow()
    }

    /// A forward is "healthy" when it has a live runner that is not in a
    /// terminal failure/stopped state.
    fn is_healthy(&self) -> bool {
        self.runner.is_some()
            && !matches!(
                self.runner_state(),
                spt_protocol::ForwardState::Failed
                    | spt_protocol::ForwardState::Stopped
                    | spt_protocol::ForwardState::Disabled
            )
    }
}

/// Small fixed backoff between per-forward reopen attempts (E1-F4).
const FORWARD_REOPEN_BACKOFF: Duration = Duration::from_millis(500);

/// Capacity of the per-profile lifecycle events channel (F3).
///
/// The channel is bounded so that a missing or slow `take_events()` consumer
/// cannot accumulate lifecycle events for the profile's entire lifetime (a slow
/// leak). On saturation, [`ProfileTask::emit_event`] drops the event with a
/// debug log rather than awaiting (which would stall the supervisor loop) or
/// growing without bound. Lifecycle events are advisory, so bounded-drop is the
/// correct trade-off — consistent with the lossy `try_send` UDP/demux paths.
const PROFILE_EVENTS_CHANNEL_CAP: usize = 256;

/// F-S1 storm guard: minimum wall-clock interval between two instability-driven
/// LIVE failovers/restarts. The instability detector already latches (`triggered`
/// stays set until `clear_after` of sustained health), so a single episode trips
/// once; this is a belt-and-suspenders floor ensuring that even a rapidly
/// re-arming detector cannot make the supervisor tear the live session down in a
/// tight loop.
const INSTABILITY_ACTION_MIN_INTERVAL: Duration = Duration::from_secs(10);

/// F-S1 / F-S4: what the caller of [`ProfileTask::on_instability_trip`] must do
/// to the LIVE session after a trip. Only the live-session (latency / keepalive)
/// probe path acts on this; the connect-failure / `SessionLost` paths are
/// already reconnecting and ignore it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstabilityOutcome {
    /// No live-session teardown required (observe-only, degrade, or a variant
    /// that has no live remediation and was warned about at load time).
    Handled,
    /// `Failover` action: tear the live session down, cool the current endpoint,
    /// and rotate to a sibling on the next pick.
    FailoverRotate,
    /// `RestartSession` action: tear the live session down and reconnect to the
    /// same endpoint (no cooling / rotation).
    RestartSession,
}

/// Outcome of one supervised session — drives the outer `run` loop.
enum LoopAction {
    /// Continue the reconnect loop after `delay`.
    Retry(Duration),
    /// Exit the run loop entirely.
    Exit,
}

/// Internal decision made inside [`ProfileTask::run_active`]'s
/// `tokio::select!`. Lifted to module scope so clippy's
/// `items-after-statements` is satisfied; carries control-message
/// reply senders so the dispatch happens *after* the select! arms
/// have released their borrows on `session` / `runners`.
enum ActiveDecision {
    ShutdownExit,
    Failover {
        override_to: Option<String>,
        reply: oneshot::Sender<Result<()>>,
    },
    CloseSession {
        reply: oneshot::Sender<Result<()>>,
    },
    Drain {
        grace: Duration,
        reply: oneshot::Sender<Result<DrainReport>>,
    },
    /// The session-health probe failed (keepalive `Err` or timeout) — the
    /// session is dead and must be replaced via the reconnect path.
    SessionLost,
    /// F-S1 / F-S4: an instability trip on the LIVE session selected a real
    /// remediation (`Failover` or `RestartSession`). Tear the session down and
    /// reconnect; `cool` charges the current endpoint a failure first so the
    /// next pick rotates to a sibling (Failover) rather than reusing it
    /// (RestartSession).
    InstabilityAction {
        /// Cool the current endpoint before reconnecting (Failover semantics).
        cool: bool,
    },
}

impl ProfileTask {
    async fn run(mut self, mut control: mpsc::Receiver<Control>) {
        self.backoff = Backoff::new(self.cfg.backoff);
        self.instability = InstabilityDetector::new(self.cfg.instability);

        // F-S2 / F-S4: surface load-time warnings for options that cannot be
        // honored on the live-session path (shallow probes, no-op actions).
        self.warn_unsupported_config();

        // Kick off
        self.fire(SmEvent::Start);

        loop {
            // Drain pending control messages without blocking the loop —
            // failover overrides are stored on the selector for the next pick.
            while let Ok(msg) = control.try_recv() {
                if self.handle_control_idle(msg).is_break() {
                    self.cleanup_session();
                    self.fire(SmEvent::Stop);
                    self.fire(SmEvent::Stopped);
                    return;
                }
            }

            if self.backoff.exhausted() {
                self.emit_event(ProfileEvent::BackoffExhausted {
                    profile: self.name.clone(),
                });
                // CRIT-LOG (w8): mirror the give-up decision to `tracing` at the
                // decision site — "this tunnel gave up" must be visible in logs,
                // not only on the event bus. Give-up is terminal → ERROR.
                let last_endpoint = self
                    .current_endpoint
                    .as_ref()
                    .map(|e| format!("{}:{}", e.host, e.port));
                tracing::error!(
                    profile = %self.name,
                    attempt = self.backoff.attempt(),
                    endpoint = last_endpoint.as_deref().unwrap_or("<none>"),
                    "reconnect backoff exhausted; giving up on this profile"
                );
                self.cfg.observers.emit_lifecycle(
                    "profile.backoff_exhausted",
                    spt_events::Severity::Error,
                    &self.name,
                    format!(
                        "profile `{}` exhausted reconnect backoff; giving up",
                        self.name
                    ),
                    &[("attempt", serde_json::Value::from(self.backoff.attempt()))],
                );
                // t8-C1: notify chaos / harness observer (no-op in production).
                crate::reconnect::notify_max_exhausted(self.backoff.attempt());
                break;
            }

            // 1. Pick endpoint. E1-F1: drive the state machine at its real
            //    boundaries. When re-entering the loop from `Reconnecting`
            //    or `FailingOver` (after a prior failure), advance out of
            //    that state honestly before resolving.
            self.enter_resolving();
            let endpoint = match self.pick_endpoint() {
                Some(ep) => ep,
                None => {
                    // No eligible endpoint (all cooling down): announce the
                    // failover attempt and back off.
                    self.fire(SmEvent::FailoverPick);
                    let delay = self.next_backoff();
                    if self.sleep_or_control(delay, &mut control).await {
                        break;
                    }
                    continue;
                }
            };

            // 2. Connect. We fold DNS resolution into `connect`, so we fire
            //    `ResolveOk` (→ Connecting) optimistically and only confirm
            //    `ConnectOk` / `AuthOk` once the backend actually returns a
            //    live session. A failure fires `ConnectFail` (→ Reconnecting).
            self.fire(SmEvent::ResolveOk);
            // Multi-auth Phase 3: select the credential resolved for *this*
            // endpoint, falling back to the profile-level default when the
            // endpoint has no per-endpoint override (empty map ⇒ always default).
            // Cloned up front so the borrow doesn't outlive into the `select!`
            // control arms (which take `&mut self`).
            let endpoint_auth: AuthConfig = self
                .auth_by_endpoint
                .get(&(endpoint.host.clone(), endpoint.port))
                .unwrap_or(&self.auth)
                .clone();
            let session_res = tokio::select! {
                r = self.protocol.connect(&endpoint, &endpoint_auth) => r,
                ctrl = control.recv() => {
                    match ctrl {
                        Some(Control::Shutdown) | None => {
                            self.cleanup_session();
                            self.fire(SmEvent::Stop);
                            self.fire(SmEvent::Stopped);
                            return;
                        }
                        Some(Control::Failover { override_to, reply }) => {
                            let res = self.apply_manual_override(override_to.as_deref());
                            let _ = reply.send(res);
                            continue;
                        }
                        Some(Control::CloseSession { reply }) => {
                            let _ = reply.send(Ok(()));
                            continue;
                        }
                        Some(Control::OpenBenchForward { reply }) => {
                            // Connecting, not yet active — no live session.
                            let _ = reply.send(Err(no_live_session_err()));
                            continue;
                        }
                        Some(Control::Drain { reply, .. }) => {
                            // Pre-session drain is terminal (E1-F18): mirror the
                            // active-path semantics so the same command always
                            // ends the profile.
                            let _ = reply.send(Ok(DrainReport::default()));
                            self.cleanup_session();
                            self.fire(SmEvent::Stop);
                            self.fire(SmEvent::Stopped);
                            return;
                        }
                    }
                }
            };
            let mut session = match session_res {
                Ok(s) => {
                    self.selector
                        .lock()
                        .record_success(&endpoint.host, endpoint.port);
                    // CRIT-LOG (w8): a successful (re)connect is the operator's
                    // "recovered" signal — mirror it to `tracing` at INFO so even
                    // recovery is visible in logs (not just on the event bus).
                    tracing::info!(
                        profile = %self.name,
                        endpoint = %format!("{}:{}", endpoint.host, endpoint.port),
                        attempt = self.backoff.attempt(),
                        "session connected and authenticated"
                    );
                    // Connect + auth confirmed: walk the SM to EstablishingForwards.
                    self.fire(SmEvent::ConnectOk);
                    self.fire(SmEvent::AuthOk);
                    self.current_endpoint = Some(endpoint.clone());
                    // t8-C1: notify chaos / harness observer (no-op in production).
                    crate::reconnect::notify_success(self.backoff.attempt());
                    s
                }
                Err(e) => {
                    // H2: genuinely unrecoverable connect errors must be terminal
                    // regardless of `retry_auth_failures`. A host-key / trust
                    // mismatch (`TrustFailed`) will NEVER be accepted on retry —
                    // hammering the host both wastes effort and is a security
                    // concern — and a private-key load/parse/permission failure
                    // (`KeyFailure`) is a static config error that cannot heal by
                    // retrying. Transient network/DNS/bind errors stay retryable.
                    if is_terminal_connect_error(&e) {
                        self.fire(SmEvent::ConnectFail);
                        tracing::error!(
                            profile = %self.name,
                            error = %e,
                            "connect failed with an unrecoverable trust/key error; \
                             treating as terminal and stopping the profile"
                        );
                        self.cfg.observers.emit_lifecycle(
                            "profile.connect_failed_terminal",
                            spt_events::Severity::Error,
                            &self.name,
                            format!(
                                "profile `{}` connect failed unrecoverably ({e}); \
                                 stopping (fix the host key / key file and restart)",
                                self.name
                            ),
                            &[],
                        );
                        self.handle_session_failure(&endpoint, &e);
                        break;
                    }
                    // TW-C2: terminal-vs-retryable classifier for auth failures.
                    // `[profiles.reconnect].retry_auth_failures` (default false)
                    // decides whether an `AuthFailed*` error from `connect` ends
                    // the profile (terminal) or rejoins the backoff loop. Every
                    // other connect error always retries (today's behavior).
                    if is_auth_failure(&e) && !self.cfg.backoff.retry_auth_failures {
                        self.fire(SmEvent::AuthFail);
                        tracing::warn!(
                            profile = %self.name,
                            error = %e,
                            "authentication failed and retry_auth_failures is off; \
                             treating as terminal and stopping the profile"
                        );
                        self.cfg.observers.emit_lifecycle(
                            "profile.auth_failed",
                            spt_events::Severity::Error,
                            &self.name,
                            format!(
                                "profile `{}` authentication failed (terminal); \
                                 set retry_auth_failures=true to keep retrying",
                                self.name
                            ),
                            &[],
                        );
                        self.handle_session_failure(&endpoint, &e);
                        break;
                    }
                    self.fire(SmEvent::ConnectFail);
                    self.handle_session_failure(&endpoint, &e);
                    let delay = self.next_backoff();
                    if self.sleep_or_control(delay, &mut control).await {
                        break;
                    }
                    continue;
                }
            };

            // Register session with the registry.
            let session_id = SessionId::new_v4();
            self.publish_session(&session_id, &endpoint, &*session);

            // 3. Open forwards.
            let runners = match self.open_forwards(session.as_mut()).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(profile = %self.name, error = %e, "failed to open forwards");
                    // We never reached a healthy session: abandon it and treat
                    // this like a session loss (→ Reconnecting), not a partial
                    // Degraded state.
                    self.fire(SmEvent::SessionLost);
                    self.unpublish_session();
                    let _ = close_session_bounded(session, self.cfg.keepalive_interval).await;
                    self.handle_session_failure(&endpoint, &e);
                    let delay = self.next_backoff();
                    if self.sleep_or_control(delay, &mut control).await {
                        break;
                    }
                    continue;
                }
            };
            self.fire(SmEvent::ForwardsUp);
            // Spec §11.2: "Backoff MUST reset after a stable connected
            // duration." We do *not* reset eagerly on ForwardsUp — that
            // would make `BackoffConfig::reset_after` a no-op. Instead, we
            // record when the session reached `ForwardsUp` and reset the
            // attempt counter on the *next* failure, conditional on
            // uptime ≥ `reset_after`. See `maybe_reset_backoff`.
            self.session_up_since = Some(Instant::now());

            // 4. Hold the session until shutdown / control message.
            let action = self.run_active(&mut control, session, runners).await;
            self.unpublish_session();
            match action {
                LoopAction::Exit => break,
                LoopAction::Retry(delay) => {
                    if self.sleep_or_control(delay, &mut control).await {
                        break;
                    }
                    // 1.88 lint: redundant_continue
                }
            }
        }

        self.cleanup_session();
        self.fire(SmEvent::Stop);
        self.fire(SmEvent::Stopped);
    }

    async fn run_active(
        &mut self,
        control: &mut mpsc::Receiver<Control>,
        mut session: Box<dyn TunnelSession>,
        runners: Vec<ForwardRunner>,
    ) -> LoopAction {
        // Spec §11.3: the supervisor MUST detect session-level liveness
        // failures and trigger replacement. We drive
        // `TunnelSession::keepalive` on `cfg.keepalive_interval` and
        // treat any `Err` *or* timeout as "session dead → reconnect now".
        //
        // H1 (defensive): `tokio::time::interval` PANICS on a zero period.
        // Config validation rejects a zero `keepalive.interval`, but a config
        // built programmatically (bypassing validation) could still carry one;
        // clamp a non-positive interval up to the default cadence so the probe
        // loop can never crash the profile task.
        let keepalive_period = if self.cfg.keepalive_interval.is_zero() {
            tracing::warn!(
                profile = %self.name,
                "keepalive_interval is zero; clamping to 30s (a zero interval would panic)"
            );
            Duration::from_secs(30)
        } else {
            self.cfg.keepalive_interval
        };
        // M1 (defensive): a zero per-probe timeout elapses immediately, so every
        // probe is recorded as a miss → permanent reconnect storm. Validation
        // rejects it; clamp defensively to the default for non-validated configs.
        let keepalive_timeout = if self.cfg.keepalive_timeout.is_zero() {
            tracing::warn!(
                profile = %self.name,
                "keepalive_timeout is zero; clamping to 10s (a zero timeout would storm-reconnect)"
            );
            Duration::from_secs(10)
        } else {
            self.cfg.keepalive_timeout
        };
        let mut keepalive = tokio::time::interval(keepalive_period);
        // The first interval tick fires immediately; consume it so we
        // don't probe the moment we enter the loop.
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await;

        // E1-F4: observe each forward's live state. `forwards` pairs the
        // owned runner with its watch receiver and config so a failed forward
        // can be reopened in place while the session stays up.
        let mut forwards: Vec<ForwardSlot> = runners
            .into_iter()
            .map(|r| {
                let watch_rx = r.watch_state();
                let name = r.name().to_owned();
                let cfg = self.forwards.iter().find(|f| f.name == name).cloned();
                ForwardSlot {
                    runner: Some(r),
                    watch_rx,
                    name,
                    cfg,
                }
            })
            .collect();
        // `degraded` mirrors the SM: true once we've fired ForwardDown for a
        // forward and haven't yet recovered every forward.
        let mut degraded = false;
        // Pending per-forward reopen deadline (small backoff). `None` when no
        // forward is awaiting reopen.
        let mut reopen_at: Option<Instant> = None;

        let decision = loop {
            // Build a future that resolves when any forward's state changes.
            let any_forward_changed = async {
                use futures::StreamExt as _;
                if forwards.is_empty() {
                    return std::future::pending::<usize>().await;
                }
                let mut futs = futures::stream::FuturesUnordered::new();
                for (idx, slot) in forwards.iter().enumerate() {
                    let mut rx = slot.watch_rx.clone();
                    futs.push(async move {
                        let _ = rx.changed().await;
                        idx
                    });
                }
                // Always at least one element here, so `next()` resolves.
                futs.next().await.unwrap_or(0)
            };

            let reopen_tick = async {
                match reopen_at {
                    Some(t) => tokio::time::sleep_until(t).await,
                    None => std::future::pending::<()>().await,
                }
            };

            tokio::select! {
                msg = control.recv() => {
                    match msg {
                        None | Some(Control::Shutdown) => break ActiveDecision::ShutdownExit,
                        Some(Control::Failover { override_to, reply }) => {
                            break ActiveDecision::Failover { override_to, reply };
                        }
                        Some(Control::CloseSession { reply }) => {
                            break ActiveDecision::CloseSession { reply };
                        }
                        Some(Control::Drain { grace, reply }) => {
                            break ActiveDecision::Drain { grace, reply };
                        }
                        Some(Control::OpenBenchForward { reply }) => {
                            // Open a fresh `local` forward over the LIVE session
                            // for benchmarking, without disturbing the supervised
                            // forwards or the session lifecycle (E1-F13 live
                            // bench wiring). Stays in the active loop.
                            let res = open_bench_forward(session.as_mut()).await;
                            let _ = reply.send(res);
                            // 1.88 lint: redundant_continue
                        }
                    }
                }
                _ = keepalive.tick() => {
                    // E1-F11: bound the probe so a black-holed connection can't
                    // wedge the control channel. Treat timeout as failure.
                    // TW-C2 / TW2-A3: select the liveness probe by `health_check`
                    // style.
                    // * `SshHandshake` (default) — SSH-level keepalive round-trip
                    //   over the live session (today's fixed behavior).
                    // * `TcpConnect` — bare TCP reachability check to the live
                    //   endpoint.
                    // * `SshAuthPreflight` — a connect+auth-only side dial via
                    //   `TunnelSession::preflight_connect` (Phase-1 trait method;
                    //   the spt-ssh2 backend performs the real side connection).
                    // * `Ssh3Endpoint` — a QUIC-endpoint reachability+auth probe
                    //   via `TunnelSession::preflight_connect` (protocol-agnostic
                    //   trait call). For an ssh3-backed session this performs a
                    //   fresh QUIC+TLS+HTTP/3-CONNECT+auth side-dial, dropped
                    //   immediately. (An ssh2 session here would run ssh2's
                    //   TCP+auth preflight instead; the validate layer rejects the
                    //   protocol×health_check mismatch upstream.)
                    //
                    // TW2-A3: time each probe so a SUCCESSFUL outcome yields a
                    // coarse RTT sample (`Instant::now()` before/after the probe
                    // future) fed to the instability detector's rolling-p95
                    // latency estimator, while a FAILED/timed-out outcome is
                    // recorded as a keepalive miss. The RTT is coarse — it
                    // includes tokio scheduler jitter and the `timeout` wrapper
                    // overhead.
                    let probe_started = Instant::now();
                    let probe = match self.cfg.health_check {
                        HealthCheckStyle::TcpConnect => {
                            tokio::time::timeout(
                                keepalive_timeout,
                                probe_tcp_connect(self.current_endpoint.as_ref()),
                            ).await
                        }
                        HealthCheckStyle::SshAuthPreflight => {
                            tokio::time::timeout(
                                keepalive_timeout,
                                session.preflight_connect(),
                            ).await
                        }
                        HealthCheckStyle::SshHandshake => {
                            tokio::time::timeout(
                                keepalive_timeout,
                                session.keepalive(),
                            ).await
                        }
                        HealthCheckStyle::Ssh3Endpoint => {
                            // F5 (w8): same `preflight_connect()` call as
                            // `SshAuthPreflight` — the ssh3/QUIC vs ssh2/TCP
                            // distinction is entirely inside the session impl, so
                            // at the supervisor layer these two styles are the
                            // same connect+auth side-dial (documented in the
                            // load-time shallow-probe WARN).
                            tokio::time::timeout(
                                keepalive_timeout,
                                session.preflight_connect(),
                            ).await
                        }
                    };
                    match probe {
                        Ok(Ok(())) => {
                            // TW2-A3: feed a coarse RTT sample for the rolling
                            // p95 latency trip condition. A successful probe also
                            // resets the consecutive-miss counter inside the
                            // detector.
                            let rtt = probe_started.elapsed();
                            if self.instability.record_probe(Some(rtt)) {
                                // F-S1 / F-S4: a latency-p95 trip on the LIVE
                                // session can now drive a real remediation
                                // (Failover cools + rotates; RestartSession
                                // tears down + reconnects) instead of only
                                // relabelling to Unstable / emitting an event.
                                match self.on_instability_trip() {
                                    InstabilityOutcome::Handled => {}
                                    InstabilityOutcome::FailoverRotate => {
                                        break ActiveDecision::InstabilityAction { cool: true };
                                    }
                                    InstabilityOutcome::RestartSession => {
                                        break ActiveDecision::InstabilityAction { cool: false };
                                    }
                                }
                            }
                            // E1-F8: a healthy probe accrues clean-uptime for
                            // the instability detector. When enough clean time
                            // has elapsed the Unstable flag clears.
                            if self.instability.tick_healthy(Instant::now()) {
                                self.emit_event(ProfileEvent::InstabilityCleared {
                                    profile: self.name.clone(),
                                });
                                self.cfg.observers.emit_lifecycle(
                                    "profile.instability_cleared",
                                    spt_events::Severity::Info,
                                    &self.name,
                                    format!(
                                        "profile `{}` instability cleared",
                                        self.name
                                    ),
                                    &[],
                                );
                                self.fire(SmEvent::InstabilityClear);
                            }
                            // 1.88 lint: redundant_continue
                        }
                        Ok(Err(e)) => {
                            // TW2-A3: a failed probe is a keepalive miss. Feed it
                            // to the detector (consecutive-miss trip condition)
                            // before we tear the session down for reconnect.
                            // We're already breaking to SessionLost (which cools
                            // the endpoint + reconnects), so the trip outcome is
                            // moot here — ignore it.
                            if self.instability.record_probe(None) {
                                let _ = self.on_instability_trip();
                            }
                            tracing::warn!(
                                profile = %self.name,
                                error = %e,
                                "health probe failed; triggering reconnect"
                            );
                            break ActiveDecision::SessionLost;
                        }
                        Err(_) => {
                            // TW2-A3: a timed-out probe is also a keepalive miss.
                            // As in the `Err` arm, we're breaking to SessionLost
                            // regardless, so ignore the trip outcome.
                            if self.instability.record_probe(None) {
                                let _ = self.on_instability_trip();
                            }
                            tracing::warn!(
                                profile = %self.name,
                                "health probe timed out; triggering reconnect"
                            );
                            break ActiveDecision::SessionLost;
                        }
                    }
                }
                idx = any_forward_changed, if !forwards.is_empty() => {
                    let st = forwards[idx].runner_state();
                    if matches!(st, spt_protocol::ForwardState::Failed | spt_protocol::ForwardState::Stopped)
                        && forwards[idx].cfg.is_some()
                    {
                        // Forward died unexpectedly while the session is up.
                        if !degraded {
                            degraded = true;
                            self.fire(SmEvent::ForwardDown);
                            self.emit_event(ProfileEvent::StateChanged {
                                profile: self.name.clone(),
                                from: ProfileStateName::Active,
                                to: ProfileStateName::Degraded,
                            });
                        }
                        // Schedule a reopen with a small backoff.
                        if reopen_at.is_none() {
                            reopen_at = Some(Instant::now() + FORWARD_REOPEN_BACKOFF);
                        }
                    }
                }
                _ = reopen_tick => {
                    reopen_at = None;
                    // Attempt to reopen every failed forward in place.
                    self.reopen_failed_forwards(session.as_mut(), &mut forwards).await;
                    let all_up = forwards.iter().all(ForwardSlot::is_healthy);
                    if all_up && degraded {
                        degraded = false;
                        self.fire(SmEvent::ForwardsUp);
                    } else if !all_up {
                        // Still down — retry after another backoff.
                        reopen_at = Some(Instant::now() + FORWARD_REOPEN_BACKOFF);
                    }
                }
            }
        };

        let runners: Vec<ForwardRunner> = forwards
            .iter_mut()
            .filter_map(|s| s.runner.take())
            .collect();

        match decision {
            ActiveDecision::ShutdownExit => {
                stop_runners_bounded(runners, self.cfg.keepalive_interval).await;
                let _ = close_session_bounded(session, self.cfg.keepalive_interval).await;
                LoopAction::Exit
            }
            ActiveDecision::Failover { override_to, reply } => {
                let res = self.apply_manual_override(override_to.as_deref());
                self.emit_failover(override_to.as_deref());
                self.emit_event(ProfileEvent::FailoverRequested {
                    profile: self.name.clone(),
                    override_to,
                });
                let _ = reply.send(res);
                self.fire(SmEvent::SessionLost);
                stop_runners_bounded(runners, self.cfg.keepalive_interval).await;
                let _ = close_session_bounded(session, self.cfg.keepalive_interval).await;
                LoopAction::Retry(Duration::from_millis(0))
            }
            ActiveDecision::CloseSession { reply } => {
                self.fire(SmEvent::SessionLost);
                stop_runners_bounded(runners, self.cfg.keepalive_interval).await;
                let _ = close_session_bounded(session, self.cfg.keepalive_interval).await;
                let _ = reply.send(Ok(()));
                LoopAction::Retry(Duration::from_millis(0))
            }
            ActiveDecision::Drain { grace, reply } => {
                let report = drain_runners(runners, grace).await;
                let _ = close_session_bounded(session, self.cfg.keepalive_interval).await;
                let _ = reply.send(Ok(report));
                LoopAction::Exit
            }
            ActiveDecision::SessionLost => {
                // E1-F3: route session loss through the failure accounting and
                // backoff machinery just like a connect failure.
                self.fire(SmEvent::SessionLost);
                stop_runners_bounded(runners, self.cfg.keepalive_interval).await;
                let _ = close_session_bounded(session, self.cfg.keepalive_interval).await;
                if let Some(ep) = self.current_endpoint.clone() {
                    self.handle_session_failure(
                        &ep,
                        &Error::NetworkUnreachable("session keepalive failed".into()),
                    );
                }
                let delay = self.next_backoff();
                LoopAction::Retry(delay)
            }
            ActiveDecision::InstabilityAction { cool } => {
                // F-S1 / F-S4: a live-session instability trip drove a real
                // remediation. Route it through the same teardown + reconnect
                // machinery as a session loss so forwards and the session are
                // closed cleanly, then reconnect. For the `Failover` action we
                // charge the current endpoint a failure first (cooling it) so
                // the next `pick_endpoint` rotates to a healthy sibling; for
                // `RestartSession` we leave the endpoint uncooled so the
                // reconnect targets the same endpoint.
                self.fire(SmEvent::SessionLost);
                stop_runners_bounded(runners, self.cfg.keepalive_interval).await;
                let _ = close_session_bounded(session, self.cfg.keepalive_interval).await;
                if cool {
                    if let Some(ep) = self.current_endpoint.clone() {
                        self.selector
                            .lock()
                            .record_failure(&ep.host, ep.port, Instant::now());
                    }
                }
                // Reconnect promptly (rotate). A zero delay mirrors the
                // operator-initiated failover path; connect latency still paces
                // the loop and the endpoint cooldown biases the pick.
                LoopAction::Retry(Duration::from_millis(0))
            }
        }
    }

    /// Attempt to reopen every failed/stopped forward in place over the live
    /// session (E1-F4). Updates the slots' runners on success.
    async fn reopen_failed_forwards(
        &self,
        session: &mut dyn TunnelSession,
        forwards: &mut [ForwardSlot],
    ) {
        for slot in forwards.iter_mut() {
            if slot.is_healthy() {
                continue;
            }
            let Some(cfg) = slot.cfg.clone() else {
                continue;
            };
            // Drop the dead runner first.
            if let Some(old) = slot.runner.take() {
                old.stop().await;
            }
            match ForwardRunner::start(&cfg, session, &self.cfg.runner_cfg).await {
                Ok(r) => {
                    slot.watch_rx = r.watch_state();
                    slot.runner = Some(r);
                    tracing::info!(profile = %self.name, forward = %slot.name, "forward reopened");
                }
                Err(e) => {
                    tracing::warn!(
                        profile = %self.name,
                        forward = %slot.name,
                        error = %e,
                        "forward reopen failed; will retry"
                    );
                }
            }
        }
    }

    /// Emit a lifecycle [`ProfileEvent`] on the bounded events channel without
    /// blocking the supervisor loop (F3).
    ///
    /// If no consumer ever called `take_events()`, or a slow consumer has let
    /// the channel fill, we drop the event and log at debug rather than
    /// awaiting (which would stall the profile task) or growing memory without
    /// bound. This mirrors the best-effort semantics of the previous unbounded
    /// `let _ = send(..)` while capping the channel at
    /// [`PROFILE_EVENTS_CHANNEL_CAP`].
    fn emit_event(&self, event: ProfileEvent) {
        match self.events_tx.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(ev)) => {
                tracing::debug!(
                    profile = %self.name,
                    event = ?ev,
                    "profile events channel full; dropping lifecycle event (no/slow consumer)"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                // Receiver was dropped — nothing to deliver, same as the old
                // best-effort `let _ = send(..)`.
            }
        }
    }

    /// E1-F1: advance honestly out of `Reconnecting` / `FailingOver` into
    /// `Resolving` before the next connect attempt. No-op from `Idle` (the
    /// initial `Start` already moved us to `Resolving`).
    fn enter_resolving(&mut self) {
        match self.sm.state() {
            ProfileStateName::Reconnecting => {
                self.fire(SmEvent::RetryNow);
            }
            ProfileStateName::FailingOver => {
                self.fire(SmEvent::EndpointReady);
            }
            _ => {}
        }
    }

    fn handle_control_idle(&mut self, msg: Control) -> std::ops::ControlFlow<()> {
        match msg {
            Control::Shutdown => std::ops::ControlFlow::Break(()),
            Control::Failover { override_to, reply } => {
                let res = self.apply_manual_override(override_to.as_deref());
                self.emit_failover(override_to.as_deref());
                self.emit_event(ProfileEvent::FailoverRequested {
                    profile: self.name.clone(),
                    override_to,
                });
                let _ = reply.send(res);
                std::ops::ControlFlow::Continue(())
            }
            Control::CloseSession { reply } => {
                let _ = reply.send(Ok(()));
                std::ops::ControlFlow::Continue(())
            }
            Control::Drain { reply, .. } => {
                // E1-F18: drain is terminal in every path. With no session up
                // there is nothing to drain, so reply with an empty report and
                // end the profile (mirrors the active-path Exit semantics).
                let _ = reply.send(Ok(DrainReport::default()));
                std::ops::ControlFlow::Break(())
            }
            Control::OpenBenchForward { reply } => {
                // No live session in the idle/reconnect phase — report honestly.
                let _ = reply.send(Err(no_live_session_err()));
                std::ops::ControlFlow::Continue(())
            }
        }
    }

    fn apply_manual_override(&self, override_to: Option<&str>) -> Result<()> {
        let mut sel = self.selector.lock();
        match override_to {
            Some(key) => {
                let (host, port) = parse_endpoint_key(key)?;
                sel.set_manual(Some(ManualOverride { host, port }));
            }
            None => sel.set_manual(None),
        }
        Ok(())
    }

    fn publish_session(&self, id: &SessionId, endpoint: &Endpoint, session: &dyn TunnelSession) {
        let info = session.session_info();
        let row = SessionRow {
            id: id.clone(),
            profile: self.name.clone(),
            protocol: info.backend,
            endpoint: format!("{}:{}", endpoint.host, endpoint.port),
            since: Utc::now(),
            state: format!("{:?}", self.sm.state()),
            bytes_in: 0,
            bytes_out: 0,
            conns_open: 0,
        };
        self.registry.insert(row);
        *self.current_session.lock() = Some(id.clone());
    }

    fn unpublish_session(&self) {
        if let Some(id) = self.current_session.lock().take() {
            self.registry.remove(&id);
        }
    }

    fn cleanup_session(&self) {
        self.unpublish_session();
    }

    fn pick_endpoint(&mut self) -> Option<Endpoint> {
        let now = Instant::now();
        let sel = self.selector.lock();
        sel.pick(&mut self.rng, now).ok().cloned()
    }

    fn handle_session_failure(&mut self, endpoint: &Endpoint, e: &spt_core::Error) {
        let now = Instant::now();
        // CRIT-LOG (w8): the session-failure error was previously discarded
        // (`_e`), so the single most useful outage diagnostic ("why did the
        // tunnel drop / fail to connect") never reached logs. Log it at the
        // decision site. `%e` is the redacted `Display` (kind + reason, no
        // secret material — mirrors the terminal-error sites above).
        tracing::warn!(
            profile = %self.name,
            endpoint = %format!("{}:{}", endpoint.host, endpoint.port),
            error = %e,
            "session failed; cooling endpoint and entering reconnect/backoff"
        );
        self.selector
            .lock()
            .record_failure(&endpoint.host, endpoint.port, now);
        if self.instability.record_disconnect(now) {
            // Already on the failure/reconnect path (the endpoint was just
            // cooled above), so the live-teardown outcome is not actionable
            // here — ignore it.
            let _ = self.on_instability_trip();
        }
    }

    /// TW-C2: respond to a newly-tripped instability detector by selecting the
    /// configured [`InstabilityAction`]. Every variant emits the canonical
    /// `profile.instability_hit` event and the `ProfileEvent::InstabilityHit`
    /// observer event (so an instability trip is always observable); the action
    /// then layers on its specific response.
    ///
    /// Wired today:
    /// * `MarkDegraded` (default) — fire `SmEvent::InstabilityHit` (→ `Unstable`)
    ///   and let backoff escalate. This is the pre-TW-C2 fixed behavior.
    /// * `EmitEvent` — observe only: emit the event, do NOT change state.
    /// * `Failover` (F-S1) — emit a `FailoverRequested` event AND, when called
    ///   from the LIVE session path, return [`InstabilityOutcome::FailoverRotate`]
    ///   so the caller cools the current endpoint and rotates to a sibling. On
    ///   the connect-failure / `SessionLost` path the endpoint is already cooled
    ///   and the reconnect is already underway, so the caller ignores the
    ///   outcome. A storm guard ([`INSTABILITY_ACTION_MIN_INTERVAL`]) bounds how
    ///   often a live teardown can fire.
    /// * `RestartSession` (F-S4) — on the LIVE path, return
    ///   [`InstabilityOutcome::RestartSession`] so the caller tears the session
    ///   down and reconnects to the SAME endpoint (no cooling).
    ///
    /// `IncreaseKeepalive` / `IncreaseBackoff` have no live-session mechanism
    /// (the keepalive cadence and backoff ceilings are fixed after
    /// construction), so they degrade like `MarkDegraded`. This is NOT silent:
    /// [`Self::warn_unsupported_config`] emits a load-time validation WARN for
    /// them so operators aren't misled that a no-op remediation is active
    /// (F-S4).
    fn on_instability_trip(&mut self) -> InstabilityOutcome {
        // Always-observable: event-bus lifecycle event + supervisor event.
        self.emit_event(ProfileEvent::InstabilityHit {
            profile: self.name.clone(),
        });
        // CRIT-LOG (w8): an instability trip is a health decision an operator
        // needs to see — mirror it to `tracing` at WARN with the selected action.
        tracing::warn!(
            profile = %self.name,
            action = ?self.cfg.instability.action,
            "instability detector tripped; applying configured action"
        );
        self.cfg.observers.emit_lifecycle(
            "profile.instability_hit",
            spt_events::Severity::Warn,
            &self.name,
            format!("profile `{}` instability detector tripped", self.name),
            &[(
                "action",
                serde_json::Value::from(format!("{:?}", self.cfg.instability.action)),
            )],
        );

        match self.cfg.instability.action {
            InstabilityAction::EmitEvent => {
                // Observe only — no state change.
                InstabilityOutcome::Handled
            }
            InstabilityAction::Failover => {
                // Signal failover intent, mark Unstable (so backoff escalation
                // applies while we rotate), and — subject to the storm guard —
                // ask the caller to actually cool the current endpoint and
                // rotate. On the failure/reconnect path the caller ignores the
                // returned outcome (the endpoint is already cooled).
                self.emit_failover(None);
                self.emit_event(ProfileEvent::FailoverRequested {
                    profile: self.name.clone(),
                    override_to: None,
                });
                self.fire(SmEvent::InstabilityHit);
                if self.allow_instability_action() {
                    InstabilityOutcome::FailoverRotate
                } else {
                    InstabilityOutcome::Handled
                }
            }
            InstabilityAction::RestartSession => {
                // F-S4: force a real session restart via the reconnect path.
                self.fire(SmEvent::InstabilityHit);
                if self.allow_instability_action() {
                    InstabilityOutcome::RestartSession
                } else {
                    InstabilityOutcome::Handled
                }
            }
            // MarkDegraded (default) + the two variants with no live mechanism
            // (IncreaseKeepalive / IncreaseBackoff) all degrade. The latter two
            // are warned about at load time (warn_unsupported_config) so they
            // are never SILENTLY cosmetic.
            InstabilityAction::MarkDegraded
            | InstabilityAction::IncreaseKeepalive
            | InstabilityAction::IncreaseBackoff => {
                self.fire(SmEvent::InstabilityHit);
                InstabilityOutcome::Handled
            }
        }
    }

    /// F-S1 storm guard: return `true` (and arm the timer) at most once per
    /// [`INSTABILITY_ACTION_MIN_INTERVAL`], so a live-session instability
    /// remediation can't tear the session down in a tight loop.
    fn allow_instability_action(&mut self) -> bool {
        let now = Instant::now();
        let allow = self
            .last_instability_action
            .map(|t| now.duration_since(t) >= INSTABILITY_ACTION_MIN_INTERVAL)
            .unwrap_or(true);
        if allow {
            self.last_instability_action = Some(now);
        }
        allow
    }

    /// F-S2 / F-S4: emit load-time configuration WARNs for options that cannot
    /// be honored on the live-session path. Called once at task start. These
    /// are advisory (the profile still runs) but ensure no configured option is
    /// SILENTLY cosmetic / weaker than an operator expects. Warnings surface on
    /// the canonical event bus (`profile.config_warning`) when one is injected,
    /// and always via `tracing::warn!`.
    fn warn_unsupported_config(&self) {
        // F-S4: live-session instability actions with no runtime mechanism.
        let action_warning = match self.cfg.instability.action {
            InstabilityAction::IncreaseKeepalive => Some(
                "instability action `increase_keepalive` has no live mechanism to mutate the \
                 running keepalive cadence; it degrades to `mark_degraded`. Use `failover` or \
                 `restart_session` for an active remediation.",
            ),
            InstabilityAction::IncreaseBackoff => Some(
                "instability action `increase_backoff` cannot mutate the immutable backoff \
                 ceiling at runtime; it degrades to `mark_degraded`. Use `failover` or \
                 `restart_session` for an active remediation.",
            ),
            _ => None,
        };
        if let Some(msg) = action_warning {
            tracing::warn!(profile = %self.name, "{msg}");
            self.cfg.observers.emit_lifecycle(
                "profile.config_warning",
                spt_events::Severity::Warn,
                &self.name,
                format!("profile `{}`: {msg}", self.name),
                &[("kind", serde_json::Value::from("instability_action"))],
            );
        }

        // F-S2: shallow health-check styles side-dial and never touch the live
        // session, so a silently-dead session whose host stays reachable never
        // trips SessionLost. Recommend the end-to-end SshHandshake probe.
        let shallow_probe = match self.cfg.health_check {
            HealthCheckStyle::TcpConnect => Some("tcp_connect"),
            HealthCheckStyle::SshAuthPreflight => Some("ssh_auth_preflight"),
            HealthCheckStyle::Ssh3Endpoint => Some("ssh3_endpoint"),
            HealthCheckStyle::SshHandshake => None,
        };
        if let Some(style) = shallow_probe {
            // F5 (w8): `ssh3_endpoint` and `ssh_auth_preflight` dispatch to the
            // identical `session.preflight_connect()` at the supervisor layer —
            // the ssh2/ssh3 transport difference lives entirely inside the
            // session impl, not here. Call that out so the two names don't imply
            // a supervisor-level distinction that does not exist.
            let equivalence = if matches!(self.cfg.health_check, HealthCheckStyle::Ssh3Endpoint) {
                " (identical to `ssh_auth_preflight` at the supervisor layer: both are a \
                 connect+auth side-dial via `preflight_connect`; the QUIC/HTTP-3 vs TCP \
                 difference is internal to the session)"
            } else {
                ""
            };
            let msg = format!(
                "health_check `{style}` is a side-dial probe that does not exercise the live \
                 session, so it cannot detect a silently-dead session whose host stays \
                 reachable; `ssh_handshake` is recommended for end-to-end liveness{equivalence}"
            );
            tracing::warn!(profile = %self.name, "{msg}");
            self.cfg.observers.emit_lifecycle(
                "profile.config_warning",
                spt_events::Severity::Warn,
                &self.name,
                format!("profile `{}`: {msg}", self.name),
                &[("kind", serde_json::Value::from("health_check"))],
            );
        }
    }

    async fn open_forwards(
        &mut self,
        session: &mut dyn TunnelSession,
    ) -> Result<Vec<ForwardRunner>> {
        let mut runners = Vec::with_capacity(self.forwards.len());
        for f in &self.forwards {
            match ForwardRunner::start(f, session, &self.cfg.runner_cfg).await {
                Ok(r) => runners.push(r),
                Err(e) => {
                    // TW-C2: per-forward `required` gate. A `required` forward
                    // that fails to open is fatal — propagate so the caller
                    // abandons the session (→ Reconnecting per the state
                    // machine), preserving today's `?`-propagation behavior for
                    // required forwards. A NON-required forward is best-effort:
                    // log-and-continue so the session (and its other forwards)
                    // stays up. `Forward::required` is `Option<bool>` (default
                    // None = not required), mirrored by `ForwardRunner::required()`.
                    let required = f.required.unwrap_or(false);
                    if required {
                        return Err(e);
                    }
                    tracing::warn!(
                        profile = %self.name,
                        forward = %f.name,
                        error = %e,
                        "non-required forward failed to open; continuing without it"
                    );
                }
            }
        }
        Ok(runners)
    }

    fn next_backoff(&mut self) -> Duration {
        // Spec §11.2 reset semantics: if the just-ended session was up
        // (had reached `ForwardsUp`) for at least `reset_after`, drop the
        // attempt counter back to 0 *before* computing the next delay.
        // Always clear `session_up_since` here because, regardless of
        // uptime length, the session is no longer up.
        if let Some(since) = self.session_up_since.take() {
            if since.elapsed() >= self.cfg.backoff.reset_after {
                self.backoff.reset();
            }
        }
        let attempt = self.backoff.attempt() + 1;
        let delay = self.backoff.next_delay_default();
        self.emit_event(ProfileEvent::ReconnectScheduled {
            profile: self.name.clone(),
            delay,
            attempt,
        });
        // E6-F1: a scheduled reconnect is an alertable lifecycle event.
        // E1-F13: bump the reconnects counter (label = profile).
        let endpoint = self
            .current_endpoint
            .as_ref()
            .map(|e| format!("{}:{}", e.host, e.port));
        let mut fields = vec![
            ("attempt", serde_json::Value::from(attempt)),
            (
                "delay_ms",
                serde_json::Value::from(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)),
            ),
        ];
        if let Some(ep) = &endpoint {
            fields.push(("endpoint", serde_json::Value::from(ep.clone())));
        }
        // CRIT-LOG (w8): mirror the scheduled reconnect to `tracing` at WARN so
        // the reconnect cadence (attempt #, delay, endpoint) is visible in logs.
        tracing::warn!(
            profile = %self.name,
            attempt,
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            endpoint = endpoint.as_deref().unwrap_or("<none>"),
            "scheduling reconnect after backoff"
        );
        self.cfg.observers.emit_lifecycle(
            "profile.reconnect_scheduled",
            spt_events::Severity::Warn,
            &self.name,
            format!(
                "profile `{}` reconnect attempt {attempt} in {delay:?}",
                self.name
            ),
            &fields,
        );
        self.cfg.observers.inc_reconnect(&self.name);
        // t8-C1: notify chaos / harness observer (no-op in production).
        crate::reconnect::notify_attempt(attempt, delay);
        delay
    }

    /// Sleep or honour an incoming control message. Returns `true` if the
    /// task should exit.
    async fn sleep_or_control(
        &self,
        delay: Duration,
        control: &mut mpsc::Receiver<Control>,
    ) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(delay) => false,
            msg = control.recv() => {
                match msg {
                    None | Some(Control::Shutdown) => true,
                    Some(Control::Failover { override_to, reply }) => {
                        let res = self.apply_manual_override(override_to.as_deref());
                        self.emit_failover(override_to.as_deref());
                        self.emit_event(ProfileEvent::FailoverRequested {
                            profile: self.name.clone(),
                            override_to,
                        });
                        let _ = reply.send(res);
                        false
                    }
                    Some(Control::CloseSession { reply }) => {
                        let _ = reply.send(Ok(()));
                        false
                    }
                    Some(Control::OpenBenchForward { reply }) => {
                        // Backoff/reconnect phase — no live session yet.
                        let _ = reply.send(Err(no_live_session_err()));
                        false
                    }
                    Some(Control::Drain { reply, .. }) => {
                        // E1-F18: drain is terminal even mid-backoff.
                        let _ = reply.send(Ok(DrainReport::default()));
                        true
                    }
                }
            }
        }
    }

    /// Emit a canonical `profile.failover_requested` event (E6-F1). No-op
    /// unless an event bus was injected.
    fn emit_failover(&self, override_to: Option<&str>) {
        let mut fields = Vec::new();
        if let Some(ep) = override_to {
            fields.push(("override_to", serde_json::Value::from(ep.to_owned())));
        }
        if let Some(cur) = &self.current_endpoint {
            fields.push((
                "endpoint",
                serde_json::Value::from(format!("{}:{}", cur.host, cur.port)),
            ));
        }
        // CRIT-LOG (w8): a failover (operator- or instability-driven) is an
        // alertable transition — mirror it to `tracing` at WARN with the
        // from-endpoint and the requested override target (if any).
        tracing::warn!(
            profile = %self.name,
            from = self
                .current_endpoint
                .as_ref()
                .map(|c| format!("{}:{}", c.host, c.port))
                .as_deref()
                .unwrap_or("<none>"),
            to = override_to.unwrap_or("<policy>"),
            "failover requested; rotating endpoint"
        );
        self.cfg.observers.emit_lifecycle(
            "profile.failover_requested",
            spt_events::Severity::Warn,
            &self.name,
            format!("profile `{}` failover requested", self.name),
            &fields,
        );
    }

    fn fire(&mut self, ev: SmEvent) {
        let prev = self.sm.state();
        if let Ok(new) = self.sm.step(ev) {
            if new != prev {
                let _ = self.state_tx.send(new);
                // w8: a per-tunnel state-history trail in logs. DEBUG keeps the
                // default-`info` stream quiet while giving operators a
                // reconstructable transition log when they raise the level.
                tracing::debug!(
                    profile = %self.name,
                    from = %prev,
                    to = %new,
                    "profile state transition"
                );
                self.emit_event(ProfileEvent::StateChanged {
                    profile: self.name.clone(),
                    from: prev,
                    to: new,
                });
                // E6-F1 / E1-F13: re-emit the transition as a canonical event
                // and update the profile_state gauge. Both are no-ops unless a
                // bus / metrics handle was injected.
                let endpoint = self
                    .current_endpoint
                    .as_ref()
                    .map(|e| format!("{}:{}", e.host, e.port));
                self.cfg
                    .observers
                    .emit_state_change(&self.name, prev, new, endpoint.as_deref());
                self.cfg.observers.set_profile_state(&self.name, new);
            }
        }
    }
}

/// Stop every runner concurrently, bounding each stop so one wedged forward
/// (E1-F11) cannot stall profile teardown indefinitely. The grace per forward
/// is derived from `bound`; runners that don't reach a terminal state in time
/// are abandoned (their tasks drop when the handle drops).
async fn stop_runners_bounded(runners: Vec<ForwardRunner>, bound: Duration) {
    if runners.is_empty() {
        return;
    }
    let grace = bound.max(Duration::from_secs(1));
    let mut joins = Vec::with_capacity(runners.len());
    for r in runners {
        joins.push(tokio::spawn(async move {
            r.stop().await;
        }));
    }
    for j in joins {
        let _ = tokio::time::timeout(grace, j).await;
    }
}

/// Close a session with a bounded wait so a black-holed connection cannot wedge
/// the supervisor's stop / reconnect path (E1-F11).
async fn close_session_bounded(session: Box<dyn TunnelSession>, bound: Duration) -> Result<()> {
    let grace = bound.max(Duration::from_secs(1));
    match tokio::time::timeout(grace, session.close()).await {
        Ok(r) => r,
        Err(_) => {
            // Abandon: dropping the box drops the underlying transport.
            Ok(())
        }
    }
}

async fn drain_runners(runners: Vec<ForwardRunner>, grace: Duration) -> DrainReport {
    use spt_protocol::ForwardState;

    let mut report = DrainReport::default();
    if runners.is_empty() {
        return report;
    }
    let deadline = tokio::time::Instant::now() + grace;
    // Fire close on every runner concurrently and wait up to `grace` for
    // each one to reach a terminal state.
    let mut joins: Vec<tokio::task::JoinHandle<(bool, ForwardState)>> = Vec::new();
    for r in runners {
        let already = r.state().is_terminal();
        joins.push(tokio::spawn(async move {
            let already_term = already;
            r.stop().await;
            (already_term, ForwardState::Stopped)
        }));
    }

    for j in joins {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, j).await {
            Ok(Ok((already_term, _))) => {
                if already_term {
                    report.already_closed += 1;
                } else {
                    report.drained += 1;
                }
            }
            Ok(Err(_)) | Err(_) => {
                report.force_closed += 1;
            }
        }
    }
    report
}

/// TW-C2: bare TCP-connect liveness probe (`HealthCheckStyle::TcpConnect`).
/// Opens (and immediately drops) a TCP connection to the live endpoint as the
/// cheapest reachability check — no SSH exchange. Returns `Err` on connect
/// failure or when no endpoint is recorded, so the caller treats it like any
/// other failed probe (→ `SessionLost`).
async fn probe_tcp_connect(endpoint: Option<&Endpoint>) -> Result<()> {
    let ep = endpoint
        .ok_or_else(|| Error::NetworkUnreachable("tcp health-check: no current endpoint".into()))?;
    let addr = format!("{}:{}", ep.host, ep.port);
    let stream = tokio::net::TcpStream::connect(&addr).await.map_err(|e| {
        Error::NetworkUnreachable(format!("tcp health-check to {addr} failed: {e}"))
    })?;
    drop(stream);
    Ok(())
}

/// Classify whether an [`Error`] from [`TunnelProtocol::connect`] represents an
/// authentication failure, so the reconnect loop can decide terminal vs
/// retryable per `[profiles.reconnect].retry_auth_failures` (TW-C2). Covers both
/// the legacy string variant and the structured-diagnostic sibling.
fn is_auth_failure(e: &Error) -> bool {
    matches!(e, Error::AuthFailed(_) | Error::AuthFailedDiagnostic(_))
}

/// Classify whether an [`Error`] from [`TunnelProtocol::connect`] is genuinely
/// UNRECOVERABLE, so the reconnect loop must stop instead of retrying forever
/// against a host that will never accept the connection (H2).
///
/// Terminal:
/// * [`Error::TrustFailed`] — host-key / certificate / TLS-pin verification
///   failed. A retry against the same (changed/untrusted) key is futile and is
///   a security concern (hammering a host whose key no longer matches).
/// * [`Error::KeyFailure`] — private-key generation / parse / permission
///   failure. A static local-config error that cannot heal by reconnecting.
///
/// Everything else — network unreachable, DNS, bind, timeouts, generic runtime
/// failures — stays RETRYABLE so a transient outage still recovers. Auth
/// failures are handled separately ([`is_auth_failure`]) because their terminal
/// behavior is gated by `[profiles.reconnect].retry_auth_failures`.
fn is_terminal_connect_error(e: &Error) -> bool {
    matches!(e, Error::TrustFailed(_) | Error::KeyFailure(_))
}

fn parse_endpoint_key(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| Error::InvalidArgs(format!("endpoint key `{s}` missing `:port`")))?;
    let port: u16 = port
        .parse()
        .map_err(|e| Error::InvalidArgs(format!("endpoint port `{port}`: {e}")))?;
    Ok((host.to_owned(), port))
}

/// Structured error returned when an [`Control::OpenBenchForward`] arrives while
/// no live session is up (idle / connecting / backoff phases).
fn no_live_session_err() -> Error {
    Error::runtime_failure(
        spt_core::Diagnostic::what("Cannot open a benchmark forward: no live session")
            .why(
                "the profile is between sessions (connecting, reconnecting, or idle); a live \
                 benchmark forward can only be opened while a session is Active",
            )
            .how_to_fix(
                "Wait until `spt status` shows the profile Active, then re-run the benchmark. \
                 For a deterministic measurement, run against a synthetic loopback connector \
                 instead of `--live`.",
            )
            .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
            .build(),
    )
}

/// Open a fresh `local` forward over the **live** session for benchmarking.
///
/// The supervisor pre-binds a loopback listener to learn a concrete ephemeral
/// port, hands that port to the backend as the forward's `listen` address, and
/// returns the bound [`SocketAddr`] so a benchmark connector can dial it; the
/// bytes then traverse the live tunnel's channel. The returned
/// [`crate::control::BenchForward`] carries a drop-guard whose paired receiver
/// is awaited by a spawned task that closes the forward when the guard drops.
///
/// The forward's `target` is `127.0.0.1:<same port>` — appropriate for a
/// deployment whose remote side echoes loopback; absent a remote echoer the
/// per-iteration reads simply time out and the driver records them honestly
/// (the live channel is still genuinely exercised on the write path).
async fn open_bench_forward(
    session: &mut dyn TunnelSession,
) -> Result<crate::control::BenchForward> {
    use spt_core::BindAddr;
    use spt_protocol::{LocalForwardSpec, TargetAddr};

    // Pre-bind to discover a free loopback port, then release it so the backend
    // can bind the same address for the forward listener. The brief gap is a
    // benign TOCTOU for a benchmark seam.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| Error::RuntimeFailure(format!("bench forward port probe failed: {e}")))?;
    let local_addr = probe
        .local_addr()
        .map_err(|e| Error::RuntimeFailure(format!("bench forward local_addr failed: {e}")))?;
    drop(probe);

    let spec = LocalForwardSpec {
        name: format!("__spt_bench_{}", local_addr.port()),
        listen: BindAddr::Tcp(local_addr),
        target: TargetAddr::new(local_addr.ip().to_string(), local_addr.port()),
        max_connections: None,
        // TW-A1 added these fields; a benchmark forward keeps the prior
        // behavior (unlimited, no idle timeout, default bind-conflict policy,
        // not required).
        limits: spt_protocol::ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: spt_protocol::BindConflictPolicy::default(),
        required: false,
    };
    let handle = session.open_local_forward(&spec).await?;

    // Own the forward handle in a task that lives until the caller drops the
    // guard. Dropping the guard closes `guard_rx`, which closes the forward.
    let (guard, guard_rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = guard_rx.await;
        handle.close().await;
    });

    Ok(crate::control::BenchForward { local_addr, guard })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_auth::AuthConfig;
    use spt_forward::testing::MockTunnelProtocol;

    fn auth() -> AuthConfig {
        AuthConfig::new("u", vec![])
    }

    fn endpoint(host: &str) -> Endpoint {
        Endpoint::new(host, 22)
    }

    #[tokio::test]
    async fn events_channel_is_bounded_and_drops_when_no_consumer() {
        // F3 regression: the per-profile events channel is BOUNDED, so a
        // missing/slow `take_events()` consumer cannot accumulate lifecycle
        // events for the profile's whole lifetime. Emulate `emit_event`'s
        // drop-on-full `try_send` path against the real capacity and assert the
        // buffered depth never exceeds the cap regardless of how many events
        // are produced with no consumer draining.
        let (tx, mut rx) = mpsc::channel::<ProfileEvent>(PROFILE_EVENTS_CHANNEL_CAP);
        let mut delivered = 0usize;
        let mut dropped = 0usize;
        for _ in 0..(PROFILE_EVENTS_CHANNEL_CAP * 4) {
            match tx.try_send(ProfileEvent::InstabilityHit {
                profile: "p".into(),
            }) {
                Ok(()) => delivered += 1,
                Err(mpsc::error::TrySendError::Full(_)) => dropped += 1,
                Err(mpsc::error::TrySendError::Closed(_)) => unreachable!(),
            }
        }
        // The channel never queued more than the cap; the surplus was dropped
        // (bounded), not retained (which an unbounded channel would do).
        assert_eq!(delivered, PROFILE_EVENTS_CHANNEL_CAP);
        assert_eq!(dropped, PROFILE_EVENTS_CHANNEL_CAP * 3);
        // Exactly `cap` items are actually buffered for the eventual consumer.
        let mut count = 0usize;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, PROFILE_EVENTS_CHANNEL_CAP);
    }

    #[test]
    fn config_health_check_defaults_to_ssh_handshake() {
        // TW-A3: the new failover health-probe style defaults to today's fixed
        // behavior (SSH-level keepalive round-trip).
        let cfg = ProfileSupervisorConfig::default();
        assert_eq!(cfg.health_check, HealthCheckStyle::SshHandshake);
        assert_eq!(HealthCheckStyle::default(), HealthCheckStyle::SshHandshake);
    }

    #[test]
    fn config_health_check_round_trips_via_struct_update() {
        let cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::TcpConnect,
            ..Default::default()
        };
        assert_eq!(cfg.health_check, HealthCheckStyle::TcpConnect);
        // Other new defaults remain in place.
        assert!(!cfg.backoff.retry_auth_failures);
        assert!(cfg.instability.enabled);
    }

    #[tokio::test]
    async fn supervisor_reaches_active_with_mock_protocol() {
        let proto = Arc::new(MockTunnelProtocol::new());
        let sup = ProfileSupervisor::spawn(
            "p",
            proto.clone(),
            auth(),
            vec![endpoint("a")],
            vec![],
            ProfileSupervisorConfig::default(),
        );

        let mut rx = sup.watch_state();
        loop {
            if *rx.borrow() == ProfileStateName::Active {
                break;
            }
            rx.changed().await.unwrap();
        }
        assert_eq!(proto.connect_count(), 1);
        sup.stop().await;
    }

    #[tokio::test]
    async fn supervisor_retries_on_connect_failure() {
        let proto = Arc::new(MockTunnelProtocol::new());
        proto.set_connect_fails(true);
        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        cfg.backoff.max_attempts = 3;
        let sup = ProfileSupervisor::spawn("p", proto, auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        let mut got_exhausted = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(ProfileEvent::BackoffExhausted { .. }) => { got_exhausted = true; break }
                    Some(_) => {} // 1.88 lint: redundant_continue
                    None => break,
                },
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
        assert!(got_exhausted, "expected BackoffExhausted");
        sup.stop().await;
    }

    // ──────── t8-FixSup: reset_after + session-health regression tests ─

    /// A tunnel session whose `keepalive()` fails on demand. Used to
    /// drive the session-health loop into the reconnect path
    /// deterministically.
    #[derive(Debug)]
    struct ToggleKeepaliveSession {
        fail: Arc<std::sync::atomic::AtomicBool>,
        info: spt_protocol::SessionInfo,
    }

    impl ToggleKeepaliveSession {
        fn new(fail: Arc<std::sync::atomic::AtomicBool>) -> Self {
            Self {
                fail,
                info: spt_protocol::SessionInfo {
                    backend: "toggle".into(),
                    peer_version: None,
                    negotiated: None,
                    established_at: 0,
                },
            }
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelSession for ToggleKeepaliveSession {
        async fn open_local_forward(
            &mut self,
            _spec: &spt_protocol::LocalForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_remote_forward(
            &mut self,
            _spec: &spt_protocol::RemoteForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_dynamic_forward(
            &mut self,
            _spec: &spt_protocol::DynamicForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_udp_forward(
            &mut self,
            _spec: &spt_protocol::UdpForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn keepalive(&mut self) -> Result<()> {
            if self.fail.load(std::sync::atomic::Ordering::SeqCst) {
                Err(Error::NetworkUnreachable("toggle".into()))
            } else {
                Ok(())
            }
        }
        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }
        fn session_info(&self) -> spt_protocol::SessionInfo {
            self.info.clone()
        }
    }

    /// `TunnelProtocol` that hands out [`ToggleKeepaliveSession`] but
    /// can be flipped to fail `connect()` too, simulating an upstream
    /// that's gone away.
    #[derive(Debug)]
    struct ToggleProto {
        keepalive_fail: Arc<std::sync::atomic::AtomicBool>,
        connect_fail: Arc<std::sync::atomic::AtomicBool>,
        connect_count: Arc<std::sync::atomic::AtomicU32>,
    }

    impl ToggleProto {
        fn new() -> Self {
            Self {
                keepalive_fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                connect_fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                connect_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for ToggleProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            self.connect_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if self.connect_fail.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Error::NetworkUnreachable("toggle".into()));
            }
            Ok(Box::new(ToggleKeepaliveSession::new(Arc::clone(
                &self.keepalive_fail,
            ))))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "toggle"
        }
    }

    /// Wait for the next `ProfileEvent::ReconnectScheduled` and
    /// return its `attempt` field. Times out after `deadline`.
    async fn wait_for_reconnect_attempt(
        events: &mut mpsc::Receiver<ProfileEvent>,
        deadline: Duration,
    ) -> Option<u32> {
        let until = tokio::time::Instant::now() + deadline;
        loop {
            let remaining = until.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return None;
            }
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Some(ProfileEvent::ReconnectScheduled { attempt, .. })) => {
                    return Some(attempt);
                }
                Ok(Some(_)) => {} // 1.88 lint: redundant_continue
                Ok(None) | Err(_) => return None,
            }
        }
    }

    /// A `TunnelSession` whose `keepalive()` deliberately sleeps for a fixed
    /// duration, modelling a healthy-but-slow link (multi-RTT latency). Used to
    /// prove the supervisor's per-probe timeout is decoupled from the cadence.
    struct SlowKeepaliveSession {
        probe_delay: Duration,
        info: spt_protocol::SessionInfo,
    }

    impl SlowKeepaliveSession {
        fn new(probe_delay: Duration) -> Self {
            Self {
                probe_delay,
                info: spt_protocol::SessionInfo {
                    backend: "slow".into(),
                    peer_version: None,
                    negotiated: None,
                    established_at: 0,
                },
            }
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelSession for SlowKeepaliveSession {
        async fn open_local_forward(
            &mut self,
            _spec: &spt_protocol::LocalForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_remote_forward(
            &mut self,
            _spec: &spt_protocol::RemoteForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_dynamic_forward(
            &mut self,
            _spec: &spt_protocol::DynamicForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_udp_forward(
            &mut self,
            _spec: &spt_protocol::UdpForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn keepalive(&mut self) -> Result<()> {
            // Healthy probe that simply takes a while to round-trip.
            tokio::time::sleep(self.probe_delay).await;
            Ok(())
        }
        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }
        fn session_info(&self) -> spt_protocol::SessionInfo {
            self.info.clone()
        }
    }

    #[derive(Debug)]
    struct SlowKeepaliveProto {
        probe_delay: Duration,
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for SlowKeepaliveProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            Ok(Box::new(SlowKeepaliveSession::new(self.probe_delay)))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "slow"
        }
    }

    /// E1-F11 regression guard: a healthy probe that is *slower than the
    /// keepalive interval but faster than the keepalive timeout* MUST NOT be
    /// misclassified as `SessionLost`. Before the fix the per-probe timeout was
    /// hard-coupled to `keepalive_interval`, so this slow-but-alive probe was
    /// aborted at the cadence and triggered a spurious reconnect storm.
    #[tokio::test]
    async fn slow_healthy_probe_does_not_trigger_session_lost() {
        // Probe takes 150 ms: 3× the 50 ms interval, but well under the
        // 2 s timeout.
        let proto = Arc::new(SlowKeepaliveProto {
            probe_delay: Duration::from_millis(150),
        });

        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(5);
        cfg.backoff.max_delay = Duration::from_millis(10);
        cfg.backoff.max_attempts = 0;
        cfg.keepalive_interval = Duration::from_millis(50);
        cfg.keepalive_timeout = Duration::from_secs(2);

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        // Run long enough that several probes complete (≥6 cadence ticks,
        // ≥4 full 150 ms probes). With the bug, the FIRST probe would abort
        // at 50 ms and schedule a reconnect; with the fix, none should.
        let attempt = wait_for_reconnect_attempt(&mut events, Duration::from_secs(1)).await;
        assert!(
            attempt.is_none(),
            "a slow-but-healthy probe (150 ms < 2 s timeout) must NOT trigger a \
             reconnect; got reconnect attempt {attempt:?}"
        );

        sup.stop().await;
    }

    /// A `TunnelSession` that counts which liveness method the supervisor calls.
    /// `keepalive` and `preflight_connect` both succeed; the counters let a test
    /// assert the `health_check` dispatch routes to the intended primitive.
    struct CountingProbeSession {
        keepalive_calls: Arc<std::sync::atomic::AtomicU32>,
        preflight_calls: Arc<std::sync::atomic::AtomicU32>,
        info: spt_protocol::SessionInfo,
    }

    impl CountingProbeSession {
        fn new(
            keepalive_calls: Arc<std::sync::atomic::AtomicU32>,
            preflight_calls: Arc<std::sync::atomic::AtomicU32>,
        ) -> Self {
            Self {
                keepalive_calls,
                preflight_calls,
                info: spt_protocol::SessionInfo {
                    backend: "counting".into(),
                    peer_version: None,
                    negotiated: None,
                    established_at: 0,
                },
            }
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelSession for CountingProbeSession {
        async fn open_local_forward(
            &mut self,
            _spec: &spt_protocol::LocalForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_remote_forward(
            &mut self,
            _spec: &spt_protocol::RemoteForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_dynamic_forward(
            &mut self,
            _spec: &spt_protocol::DynamicForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_udp_forward(
            &mut self,
            _spec: &spt_protocol::UdpForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn keepalive(&mut self) -> Result<()> {
            self.keepalive_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn preflight_connect(&mut self) -> Result<()> {
            self.preflight_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }
        fn session_info(&self) -> spt_protocol::SessionInfo {
            self.info.clone()
        }
    }

    #[derive(Debug)]
    struct CountingProbeProto {
        keepalive_calls: Arc<std::sync::atomic::AtomicU32>,
        preflight_calls: Arc<std::sync::atomic::AtomicU32>,
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for CountingProbeProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            Ok(Box::new(CountingProbeSession::new(
                Arc::clone(&self.keepalive_calls),
                Arc::clone(&self.preflight_calls),
            )))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "counting"
        }
    }

    /// TW2-A3: `health_check = SshAuthPreflight` must dispatch the probe to
    /// `TunnelSession::preflight_connect`, NOT silently fall through to
    /// `keepalive`.
    #[tokio::test]
    async fn ssh_auth_preflight_dispatches_to_preflight_connect() {
        let keepalive_calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let preflight_calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let proto = Arc::new(CountingProbeProto {
            keepalive_calls: Arc::clone(&keepalive_calls),
            preflight_calls: Arc::clone(&preflight_calls),
        });

        let cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::SshAuthPreflight,
            keepalive_interval: Duration::from_millis(20),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);

        // Let several probe ticks fire.
        tokio::time::sleep(Duration::from_millis(200)).await;
        sup.stop().await;

        let pf = preflight_calls.load(std::sync::atomic::Ordering::SeqCst);
        let ka = keepalive_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            pf >= 1,
            "SshAuthPreflight must call preflight_connect; got {pf} preflight, {ka} keepalive"
        );
        assert_eq!(
            ka, 0,
            "SshAuthPreflight must NOT fall through to keepalive; got {ka} keepalive calls"
        );
    }

    /// TW2-A3: `health_check = SshHandshake` (default) keeps calling `keepalive`
    /// and never `preflight_connect` — the dispatch split is exclusive.
    #[tokio::test]
    async fn ssh_handshake_dispatches_to_keepalive() {
        let keepalive_calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let preflight_calls = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let proto = Arc::new(CountingProbeProto {
            keepalive_calls: Arc::clone(&keepalive_calls),
            preflight_calls: Arc::clone(&preflight_calls),
        });

        let cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::SshHandshake,
            keepalive_interval: Duration::from_millis(20),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        tokio::time::sleep(Duration::from_millis(200)).await;
        sup.stop().await;

        assert!(
            keepalive_calls.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "SshHandshake must call keepalive"
        );
        assert_eq!(
            preflight_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "SshHandshake must not call preflight_connect"
        );
    }

    /// An ssh3-style `TunnelSession` whose liveness primitive is
    /// `preflight_connect` (the QUIC-endpoint reachability+auth side-dial).
    /// Configurable: it counts `preflight_connect` vs `keepalive` calls, can be
    /// told to FAIL the preflight (modelling an unreachable QUIC endpoint /
    /// rejected auth), and can sleep a fixed delay to model a slow round-trip
    /// for latency-sample assertions. Mirrors the existing `CountingProbeSession`
    /// / `SlowKeepaliveSession` patterns.
    struct Ssh3ProbeSession {
        keepalive_calls: Arc<std::sync::atomic::AtomicU32>,
        preflight_calls: Arc<std::sync::atomic::AtomicU32>,
        preflight_fail: Arc<std::sync::atomic::AtomicBool>,
        preflight_delay: Duration,
        info: spt_protocol::SessionInfo,
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelSession for Ssh3ProbeSession {
        async fn open_local_forward(
            &mut self,
            _spec: &spt_protocol::LocalForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_remote_forward(
            &mut self,
            _spec: &spt_protocol::RemoteForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_dynamic_forward(
            &mut self,
            _spec: &spt_protocol::DynamicForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn open_udp_forward(
            &mut self,
            _spec: &spt_protocol::UdpForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no forwards".into()))
        }
        async fn keepalive(&mut self) -> Result<()> {
            self.keepalive_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn preflight_connect(&mut self) -> Result<()> {
            self.preflight_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            if !self.preflight_delay.is_zero() {
                tokio::time::sleep(self.preflight_delay).await;
            }
            if self
                .preflight_fail
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                Err(Error::NetworkUnreachable(
                    "ssh3 endpoint preflight failed".into(),
                ))
            } else {
                Ok(())
            }
        }
        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }
        fn session_info(&self) -> spt_protocol::SessionInfo {
            self.info.clone()
        }
    }

    #[derive(Debug)]
    struct Ssh3ProbeProto {
        keepalive_calls: Arc<std::sync::atomic::AtomicU32>,
        preflight_calls: Arc<std::sync::atomic::AtomicU32>,
        preflight_fail: Arc<std::sync::atomic::AtomicBool>,
        preflight_delay: Duration,
    }

    impl Ssh3ProbeProto {
        fn new() -> Self {
            Self {
                keepalive_calls: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                preflight_calls: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                preflight_fail: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                preflight_delay: Duration::ZERO,
            }
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for Ssh3ProbeProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            Ok(Box::new(Ssh3ProbeSession {
                keepalive_calls: Arc::clone(&self.keepalive_calls),
                preflight_calls: Arc::clone(&self.preflight_calls),
                preflight_fail: Arc::clone(&self.preflight_fail),
                preflight_delay: self.preflight_delay,
                info: spt_protocol::SessionInfo {
                    backend: "ssh3".into(),
                    peer_version: None,
                    negotiated: None,
                    established_at: 0,
                },
            }))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "ssh3"
        }
    }

    /// Wave D: `health_check = Ssh3Endpoint` must dispatch the liveness probe to
    /// `TunnelSession::preflight_connect` (the QUIC-endpoint reachability+auth
    /// side-dial), NOT fall through to `keepalive`. This replaces the old
    /// defensive `UnsupportedPlatform` no-op arm.
    #[tokio::test]
    async fn ssh3_endpoint_dispatches_to_preflight_connect() {
        let proto = Arc::new(Ssh3ProbeProto::new());
        let keepalive_calls = Arc::clone(&proto.keepalive_calls);
        let preflight_calls = Arc::clone(&proto.preflight_calls);

        let cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::Ssh3Endpoint,
            keepalive_interval: Duration::from_millis(20),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        tokio::time::sleep(Duration::from_millis(200)).await;
        sup.stop().await;

        let pf = preflight_calls.load(std::sync::atomic::Ordering::SeqCst);
        let ka = keepalive_calls.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            pf >= 1,
            "Ssh3Endpoint must call preflight_connect; got {pf} preflight, {ka} keepalive"
        );
        assert_eq!(
            ka, 0,
            "Ssh3Endpoint must NOT fall through to keepalive; got {ka} keepalive calls"
        );
    }

    /// Wave D: a FAILED `Ssh3Endpoint` preflight (unreachable QUIC endpoint /
    /// rejected auth) drives the same `SessionLost` → reconnect path as the other
    /// probe styles — proving the arm is a live probe, not the old inert no-op.
    #[tokio::test]
    async fn ssh3_endpoint_preflight_err_triggers_reconnect() {
        let proto = Arc::new(Ssh3ProbeProto::new());
        // Preflight fails from the first tick → the probe outcome is `Err`.
        proto
            .preflight_fail
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let mut cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::Ssh3Endpoint,
            keepalive_interval: Duration::from_millis(20),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        cfg.backoff.initial_delay = Duration::from_millis(5);
        cfg.backoff.max_delay = Duration::from_millis(10);
        cfg.backoff.max_attempts = 0;

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        let attempt = wait_for_reconnect_attempt(&mut events, Duration::from_secs(2)).await;
        assert!(
            attempt.is_some(),
            "a failed Ssh3Endpoint preflight must drive SessionLost → a reconnect attempt"
        );
        assert!(
            proto
                .preflight_calls
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 1,
            "the failure must have come from preflight_connect"
        );

        sup.stop().await;
    }

    /// Wave D: a SUCCESSFUL `Ssh3Endpoint` preflight feeds a coarse RTT latency
    /// sample to the instability detector exactly like the other probe styles.
    /// A slow (~120 ms) successful preflight against a 50 ms `max_latency_p95`
    /// ceiling trips the detector (action `EmitEvent` → `InstabilityHit`),
    /// observing the sampling end-to-end at the probe site.
    #[tokio::test]
    async fn ssh3_endpoint_records_latency_sample_on_success() {
        let mut proto = Ssh3ProbeProto::new();
        proto.preflight_delay = Duration::from_millis(120);
        let proto = Arc::new(proto);

        let mut cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::Ssh3Endpoint,
            keepalive_interval: Duration::from_millis(40),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        cfg.instability.max_latency_p95 = Some(Duration::from_millis(50));
        cfg.instability.action = InstabilityAction::EmitEvent;

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();
        let state_rx = sup.watch_state();

        let mut saw_hit = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
                Ok(Some(ProfileEvent::InstabilityHit { .. })) => {
                    saw_hit = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {}
            }
        }
        assert!(
            saw_hit,
            "a successful-but-slow Ssh3Endpoint preflight (RTT > max_latency_p95) must \
             record a latency sample that trips the detector and emits InstabilityHit"
        );
        // EmitEvent action: observe only, never transition to Unstable; the
        // successful preflights keep the session alive (no SessionLost).
        assert_ne!(
            *state_rx.borrow(),
            ProfileStateName::Unstable,
            "EmitEvent action must not transition to Unstable on a latency trip"
        );
        assert_eq!(
            proto
                .keepalive_calls
                .load(std::sync::atomic::Ordering::SeqCst),
            0,
            "Ssh3Endpoint must never call keepalive"
        );

        sup.stop().await;
    }

    #[tokio::test]
    async fn reset_after_short_uptime_does_not_reset() {
        // Session is up only briefly (< reset_after) before keepalive
        // fails. Verify the next-failure backoff attempt is *not* 1
        // (i.e. did not reset) when uptime was short.
        let proto = Arc::new(ToggleProto::new());
        let keepalive_fail = Arc::clone(&proto.keepalive_fail);
        let connect_fail = Arc::clone(&proto.connect_fail);

        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(5);
        cfg.backoff.max_delay = Duration::from_millis(20);
        cfg.backoff.max_attempts = 0;
        cfg.backoff.reset_after = Duration::from_secs(60); // long
        cfg.keepalive_interval = Duration::from_millis(30);

        // Force connect failures FIRST so the supervisor bumps the
        // attempt counter, then let it succeed so the session is up
        // for a short moment, then trip keepalive.
        connect_fail.store(true, std::sync::atomic::Ordering::SeqCst);

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        // Wait until at least 2 reconnect attempts have been scheduled.
        let mut seen_attempts = 0_u32;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline && seen_attempts < 2 {
            if let Some(a) =
                wait_for_reconnect_attempt(&mut events, Duration::from_millis(500)).await
            {
                seen_attempts = a;
            }
        }
        assert!(
            seen_attempts >= 2,
            "expected ≥2 attempts before allowing connect, got {seen_attempts}"
        );

        // Let the next connect succeed.
        connect_fail.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Trip keepalive — uptime was ~200ms, well under 60s reset_after.
        keepalive_fail.store(true, std::sync::atomic::Ordering::SeqCst);
        // Re-arm connect_fail so the post-keepalive reconnect attempt
        // surfaces a ReconnectScheduled event with the carried-over
        // attempt counter.
        connect_fail.store(true, std::sync::atomic::Ordering::SeqCst);

        let next_attempt = wait_for_reconnect_attempt(&mut events, Duration::from_secs(2))
            .await
            .expect("expected a reconnect-scheduled event after keepalive failure");
        assert!(
            next_attempt > 1,
            "short-uptime should NOT reset backoff; expected attempt > 1, got {next_attempt}"
        );

        sup.stop().await;
    }

    #[tokio::test]
    async fn reset_after_long_uptime_resets() {
        // Session stays up longer than reset_after; the next failure
        // must reset the attempt counter to 0 → next attempt is 1.
        let proto = Arc::new(ToggleProto::new());
        let keepalive_fail = Arc::clone(&proto.keepalive_fail);
        let connect_fail = Arc::clone(&proto.connect_fail);

        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(5);
        cfg.backoff.max_delay = Duration::from_millis(20);
        cfg.backoff.max_attempts = 0;
        cfg.backoff.reset_after = Duration::from_millis(150);
        cfg.keepalive_interval = Duration::from_millis(50);

        // Connect succeeds → session up.
        connect_fail.store(false, std::sync::atomic::Ordering::SeqCst);

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        // Drain events until ForwardsUp; that's when session_up_since
        // is set. We can't easily peek that internal state — instead,
        // we just wait long enough to exceed reset_after.
        tokio::time::sleep(Duration::from_millis(500)).await;
        assert!(
            proto
                .connect_count
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 1,
            "expected ≥1 successful connect by now"
        );

        // Trip keepalive AND set connect_fail so the subsequent
        // reconnect attempt produces an observable ReconnectScheduled
        // event.
        keepalive_fail.store(true, std::sync::atomic::Ordering::SeqCst);
        connect_fail.store(true, std::sync::atomic::Ordering::SeqCst);

        let attempt = wait_for_reconnect_attempt(&mut events, Duration::from_secs(2))
            .await
            .expect("expected reconnect event after keepalive failure");
        assert_eq!(
            attempt, 1,
            "uptime ≥ reset_after should reset backoff; expected attempt = 1, got {attempt}"
        );

        sup.stop().await;
    }

    /// E1-F1: after a keepalive-detected loss and a successful reconnect, the
    /// profile MUST re-enter `Active` (it used to get stuck in `Degraded`
    /// forever because `ForwardsUp` was illegal from `Degraded` and success
    /// events were fired pre-connect).
    #[tokio::test]
    async fn reenters_active_after_keepalive_reconnect() {
        let proto = Arc::new(ToggleProto::new());
        let keepalive_fail = Arc::clone(&proto.keepalive_fail);

        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(5);
        cfg.backoff.max_delay = Duration::from_millis(10);
        cfg.backoff.max_attempts = 0;
        cfg.keepalive_interval = Duration::from_millis(40);

        // Two endpoints: a keepalive failure cools the active one (60s floor),
        // so the reconnect must fail over to the sibling. Both share the toggle,
        // so once keepalive succeeds again the new session stays Active.
        let sup = ProfileSupervisor::spawn(
            "p",
            proto.clone(),
            auth(),
            vec![endpoint("a"), endpoint("b")],
            vec![],
            cfg,
        );
        let mut rx = sup.watch_state();

        // Wait for first Active.
        wait_for_state(&mut rx, ProfileStateName::Active).await;

        // Trip keepalive → session loss → reconnect. Connect still succeeds.
        keepalive_fail.store(true, std::sync::atomic::Ordering::SeqCst);
        // Wait until we leave Active (Reconnecting/Resolving/...).
        loop {
            if *rx.borrow() != ProfileStateName::Active {
                break;
            }
            rx.changed().await.unwrap();
        }
        // Let keepalive succeed again so the new session stays up.
        keepalive_fail.store(false, std::sync::atomic::Ordering::SeqCst);

        // We must return to Active, not be stuck in Degraded.
        wait_for_state(&mut rx, ProfileStateName::Active).await;
        assert!(
            proto
                .connect_count
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 2,
            "expected a real reconnect (≥2 connects)"
        );
        sup.stop().await;
    }

    async fn wait_for_state(rx: &mut watch::Receiver<ProfileStateName>, target: ProfileStateName) {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if *rx.borrow() == target {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "state never reached {target:?} (now {:?})",
                *rx.borrow()
            );
            let _ = tokio::time::timeout(Duration::from_millis(200), rx.changed()).await;
        }
    }

    /// E6-F1 (supervisor side): a supervisor with an injected [`EventBus`]
    /// re-emits its state transitions as canonical `profile.*` events. We drive
    /// it to `Active` via the mock protocol and assert `profile.connected`
    /// arrives on the bus carrying the profile id.
    #[tokio::test]
    async fn injected_event_bus_receives_state_transition_events() {
        use spt_events::{EventBus, Severity};

        let bus = EventBus::default();
        let mut rx = bus.subscribe();

        let proto = Arc::new(MockTunnelProtocol::new());
        let cfg = ProfileSupervisorConfig {
            observers: crate::stats::SupervisorObservers {
                event_bus: Some(bus),
                metrics: None,
            },
            ..Default::default()
        };
        let sup = ProfileSupervisor::spawn(
            "alerting-profile",
            proto.clone(),
            auth(),
            vec![endpoint("a")],
            vec![],
            cfg,
        );

        // Wait until the profile reaches Active.
        let mut state_rx = sup.watch_state();
        loop {
            if *state_rx.borrow() == ProfileStateName::Active {
                break;
            }
            state_rx.changed().await.unwrap();
        }

        // Drain the bus until we see the canonical `profile.connected` event.
        let mut saw_connected = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            // Non-event ticks (timeout/lagged) just loop again.
            if let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                if ev.kind.as_str() == "profile.connected" {
                    assert_eq!(ev.severity, Severity::Info);
                    assert_eq!(
                        ev.profile_id.as_ref().map(spt_core::ProfileId::as_str),
                        Some("alerting-profile")
                    );
                    saw_connected = true;
                    break;
                }
            }
        }
        assert!(
            saw_connected,
            "expected a canonical profile.connected event on the injected bus"
        );
        sup.stop().await;
    }

    /// The injected metrics handle's `reconnects` counter advances when the
    /// supervisor schedules a reconnect (E1-F13).
    #[tokio::test]
    async fn injected_metrics_count_reconnects() {
        use spt_observability::metrics::MetricsExporter;

        let metrics = MetricsExporter::new().unwrap().standard().clone();

        let proto = Arc::new(MockTunnelProtocol::new());
        proto.set_connect_fails(true); // force the reconnect path
        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        cfg.backoff.max_attempts = 3;
        cfg.observers = crate::stats::SupervisorObservers {
            event_bus: None,
            metrics: Some(metrics.clone()),
        };
        let sup =
            ProfileSupervisor::spawn("recon", proto, auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        // Wait until backoff is exhausted (several reconnects scheduled).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(100), events.recv()).await {
                Ok(Some(ProfileEvent::BackoffExhausted { .. })) => break,
                Ok(Some(_)) => {} // 1.88 lint: redundant_continue
                Ok(None) | Err(_) => {}
            }
        }
        assert!(
            metrics.reconnects.with_label_values(&["recon"]).get() >= 1,
            "expected the reconnects counter to advance for the failing profile"
        );
        sup.stop().await;
    }

    #[tokio::test]
    async fn endpoint_key_round_trip() {
        let (h, p) = parse_endpoint_key("example.com:2222").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 2222);
        assert!(parse_endpoint_key("noport").is_err());
        assert!(parse_endpoint_key("h:notaport").is_err());
    }

    // ──────── t8-A1: diagnostic regression tests ──────────────────────

    #[test]
    fn failover_supervisor_not_running_diagnostic_renders_actionable_text() {
        // Mirrors the converted site for `failover_to` when the control
        // channel is closed.
        let d = spt_core::Diagnostic::what("Cannot trigger failover: supervisor not running")
            .why("the supervisor's control channel is closed — the task has exited")
            .how_to_fix(
                "Restart the profile (`spt profile restart <name>` or equivalent). \
             Check recent logs for the underlying exit reason.",
            )
            .retry_advice(spt_core::RetryAdvice::NotRetryable)
            .build();
        let e = spt_core::Error::runtime_failure(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "Cannot trigger failover",
            how_to_fix: "spt profile restart",
        );
    }

    #[test]
    fn failover_reply_dropped_diagnostic_suggests_bug_report() {
        let d = spt_core::Diagnostic::what("Supervisor failover reply was dropped")
            .why("the oneshot sender was closed before responding — supervisor likely panicked")
            .how_to_fix(
                "Inspect the supervisor logs for a panic backtrace and file a bug. \
                 Retry once the profile is restarted.",
            )
            .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
            .build();
        let e = spt_core::Error::runtime_failure(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "failover reply was dropped",
            why: "oneshot",
            how_to_fix: "file a bug",
        );
        let s = format!("{e}");
        assert!(s.contains("retry: retry with backoff"));
    }

    // ──────── multi-auth Phase 3: per-endpoint credential selection ────

    /// A `TunnelProtocol` that records, per connect, the `(host:port)` it was
    /// asked to reach and the `AuthConfig.username` it was handed. Lets a test
    /// assert the supervisor selected the credential resolved for *that*
    /// endpoint rather than one profile-wide default. `connect` always
    /// succeeds, then the session's keepalive holds the loop open.
    #[derive(Debug, Clone)]
    struct RecordingAuthProto {
        seen: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl RecordingAuthProto {
        fn new() -> Self {
            Self {
                seen: Arc::new(Mutex::new(Vec::new())),
            }
        }

        /// `(host:port → username)` recorded across all connects so far.
        fn pairs(&self) -> Vec<(String, String)> {
            self.seen.lock().clone()
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for RecordingAuthProto {
        async fn connect(
            &self,
            endpoint: &Endpoint,
            auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            self.seen.lock().push((
                format!("{}:{}", endpoint.host, endpoint.port),
                auth.username.clone(),
            ));
            // Healthy session that never fails keepalive, so the supervisor
            // stays Active on the first endpoint it connects.
            Ok(Box::new(SlowKeepaliveSession::new(Duration::from_secs(0))))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "recording-auth"
        }
    }

    /// A profile with two endpoints, each carrying a *distinct* `AuthConfig`,
    /// drives the supervisor's per-endpoint credential lookup: the mock protocol
    /// must receive the username matching the endpoint it was asked to connect.
    #[tokio::test]
    async fn per_endpoint_auth_is_passed_to_matching_endpoint() {
        let proto = Arc::new(RecordingAuthProto::new());

        let ep_a = Endpoint::new("host-a", 22);
        let ep_b = Endpoint::new("host-b", 2022);

        let auth_a = AuthConfig::new("alice", vec![]);
        let auth_b = AuthConfig::new("bob", vec![]);

        let mut map: HashMap<(String, u16), AuthConfig> = HashMap::new();
        map.insert(("host-a".to_owned(), 22), auth_a.clone());
        map.insert(("host-b".to_owned(), 2022), auth_b.clone());

        // Priority failover picks the first endpoint; the default_auth is a
        // sentinel that must NOT be used for either endpoint.
        let default_auth = AuthConfig::new("SHOULD-NOT-BE-USED", vec![]);

        let sup = ProfileSupervisor::spawn_with_auth(
            "p",
            proto.clone(),
            default_auth,
            map,
            vec![ep_a, ep_b],
            vec![],
            ProfileSupervisorConfig::default(),
        );

        // Wait until at least one connect has been recorded.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if !proto.pairs().is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no connect was recorded"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // The first connect targets the priority endpoint (host-a:22) and MUST
        // carry alice's credential, never the sentinel default.
        let pairs = proto.pairs();
        let (host_port, username) = &pairs[0];
        assert_eq!(host_port, "host-a:22");
        assert_eq!(
            username, "alice",
            "endpoint host-a:22 must receive its own resolved auth (alice), \
             got `{username}`"
        );
        assert_ne!(
            username, "SHOULD-NOT-BE-USED",
            "the profile-wide default must not be used when a per-endpoint \
             override exists"
        );

        sup.stop().await;
    }

    /// Failover to the second endpoint hands the protocol *that* endpoint's
    /// credential (bob), proving the lookup is keyed per `(host, port)` rather
    /// than fixed to the first pick.
    #[tokio::test]
    async fn per_endpoint_auth_follows_failover_to_second_endpoint() {
        let proto = Arc::new(RecordingAuthProto::new());

        let ep_a = Endpoint::new("host-a", 22);
        let ep_b = Endpoint::new("host-b", 2022);

        let mut map: HashMap<(String, u16), AuthConfig> = HashMap::new();
        map.insert(("host-a".to_owned(), 22), AuthConfig::new("alice", vec![]));
        map.insert(("host-b".to_owned(), 2022), AuthConfig::new("bob", vec![]));

        let sup = ProfileSupervisor::spawn_with_auth(
            "p",
            proto.clone(),
            AuthConfig::new("default", vec![]),
            map,
            vec![ep_a, ep_b],
            vec![],
            ProfileSupervisorConfig::default(),
        );

        // Wait for the first connect (host-a).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            if !proto.pairs().is_empty() {
                break;
            }
            assert!(tokio::time::Instant::now() < deadline, "no first connect");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Pin failover to host-b:2022 and force the active session to drop.
        sup.failover(Some("host-b:2022")).await.unwrap();

        // Wait for a connect that targeted host-b carrying bob.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            if proto
                .pairs()
                .iter()
                .any(|(hp, user)| hp == "host-b:2022" && user == "bob")
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "never connected host-b:2022 with bob's auth; saw {:?}",
                proto.pairs()
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // No connect to host-b should ever have used alice's or the default
        // credential.
        for (hp, user) in proto.pairs() {
            if hp == "host-b:2022" {
                assert_eq!(
                    user, "bob",
                    "host-b:2022 must always receive bob's resolved auth"
                );
            }
        }

        sup.stop().await;
    }

    // ──────── TW-C2: tuning-knob consumer tests ───────────────────────

    /// A protocol whose `connect` always returns `Error::AuthFailed`, counting
    /// attempts. Drives the retry-auth-failures classifier deterministically.
    #[derive(Debug)]
    struct AuthFailProto {
        count: Arc<std::sync::atomic::AtomicU32>,
    }
    impl AuthFailProto {
        fn new() -> Self {
            Self {
                count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            }
        }
    }
    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for AuthFailProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(Error::AuthFailed("publickey rejected".into()))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "authfail"
        }
    }

    /// TW-C2: with `retry_auth_failures = false` (default), an `AuthFailed`
    /// connect error is terminal — the supervisor stops after a single connect
    /// instead of looping the backoff path forever.
    #[tokio::test]
    async fn auth_failure_is_terminal_when_retry_disabled() {
        let proto = Arc::new(AuthFailProto::new());
        let count = Arc::clone(&proto.count);
        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        // retry_auth_failures defaults to false.
        assert!(!cfg.backoff.retry_auth_failures);
        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut rx = sup.watch_state();
        // The profile must reach a terminal Stopped state (not keep reconnecting).
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            if *rx.borrow() == ProfileStateName::Stopped {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "auth failure should stop the profile; stuck in {:?}",
                *rx.borrow()
            );
            let _ = tokio::time::timeout(Duration::from_millis(100), rx.changed()).await;
        }
        // Exactly one connect attempt — no backoff retry loop.
        assert_eq!(
            count.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "terminal auth failure must not retry connect"
        );
        sup.stop().await;
    }

    /// TW-C2: with `retry_auth_failures = true`, an `AuthFailed` connect error is
    /// retryable — it rejoins the backoff loop and eventually exhausts
    /// `max_attempts` (i.e. it retried, rather than stopping after one connect).
    #[tokio::test]
    async fn auth_failure_is_retried_when_retry_enabled() {
        let proto = Arc::new(AuthFailProto::new());
        let count = Arc::clone(&proto.count);
        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        cfg.backoff.max_attempts = 3;
        cfg.backoff.retry_auth_failures = true;
        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        let mut got_exhausted = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(100), events.recv()).await {
                Ok(Some(ProfileEvent::BackoffExhausted { .. })) => {
                    got_exhausted = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {}
            }
        }
        assert!(
            got_exhausted,
            "retryable auth failure should exhaust max_attempts, not stop after one connect"
        );
        assert!(
            count.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "expected multiple connect attempts when auth failures are retried"
        );
        sup.stop().await;
    }

    /// A session that fails `open_local_forward` for a configured forward name,
    /// succeeds for any other, and keeps `keepalive` healthy. Counts keepalive
    /// calls so health-check style selection is observable.
    struct ForwardFailSession {
        fail_name: Option<String>,
        keepalive_count: Arc<std::sync::atomic::AtomicU32>,
        info: spt_protocol::SessionInfo,
        // Keep the state senders alive for the life of their handles' receivers
        // so the watch channels don't close out from under the supervisor.
        state_txs: Vec<watch::Sender<spt_protocol::ForwardState>>,
    }
    impl std::fmt::Debug for ForwardFailSession {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("ForwardFailSession")
                .field("fail_name", &self.fail_name)
                .finish()
        }
    }
    impl ForwardFailSession {
        fn new(
            fail_name: Option<String>,
            keepalive_count: Arc<std::sync::atomic::AtomicU32>,
        ) -> Self {
            Self {
                fail_name,
                keepalive_count,
                info: spt_protocol::SessionInfo {
                    backend: "fwdfail".into(),
                    peer_version: None,
                    negotiated: None,
                    established_at: 0,
                },
                state_txs: Vec::new(),
            }
        }
        fn make_ok_handle(&mut self, name: &str) -> spt_protocol::ForwardHandle {
            let (state_tx, state_rx) = watch::channel(spt_protocol::ForwardState::Active);
            let (close_tx, close_rx) = oneshot::channel::<()>();
            let tx = state_tx.clone();
            tokio::spawn(async move {
                let _ = close_rx.await;
                let _ = tx.send(spt_protocol::ForwardState::Stopped);
            });
            self.state_txs.push(state_tx);
            spt_protocol::ForwardHandle::new(
                spt_protocol::ForwardId::new(),
                name.to_owned(),
                state_rx,
                close_tx,
            )
        }
    }
    #[async_trait::async_trait]
    impl spt_protocol::TunnelSession for ForwardFailSession {
        async fn open_local_forward(
            &mut self,
            spec: &spt_protocol::LocalForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            if self.fail_name.as_deref() == Some(spec.name.as_str()) {
                return Err(Error::RuntimeFailure(format!(
                    "forward `{}` open failed",
                    spec.name
                )));
            }
            Ok(self.make_ok_handle(&spec.name))
        }
        async fn open_remote_forward(
            &mut self,
            _spec: &spt_protocol::RemoteForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no remote".into()))
        }
        async fn open_dynamic_forward(
            &mut self,
            _spec: &spt_protocol::DynamicForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no dynamic".into()))
        }
        async fn open_udp_forward(
            &mut self,
            _spec: &spt_protocol::UdpForwardSpec,
        ) -> Result<spt_protocol::ForwardHandle> {
            Err(Error::RuntimeFailure("no udp".into()))
        }
        async fn keepalive(&mut self) -> Result<()> {
            self.keepalive_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        async fn close(self: Box<Self>) -> Result<()> {
            Ok(())
        }
        fn session_info(&self) -> spt_protocol::SessionInfo {
            self.info.clone()
        }
    }

    #[derive(Debug)]
    struct ForwardFailProto {
        fail_name: Option<String>,
        keepalive_count: Arc<std::sync::atomic::AtomicU32>,
        connect_count: Arc<std::sync::atomic::AtomicU32>,
    }
    impl ForwardFailProto {
        fn new(fail_name: Option<String>) -> Self {
            Self {
                fail_name,
                keepalive_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                connect_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            }
        }
    }
    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for ForwardFailProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            self.connect_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Box::new(ForwardFailSession::new(
                self.fail_name.clone(),
                Arc::clone(&self.keepalive_count),
            )))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "fwdfail"
        }
    }

    fn local_forward(name: &str, required: Option<bool>) -> Forward {
        Forward {
            name: name.to_owned(),
            kind: "local".to_owned(),
            transport: "tcp".to_owned(),
            bind: Some("127.0.0.1:0".to_owned()),
            target: Some("203.0.113.1:22".to_owned()),
            required,
            ..Default::default()
        }
    }

    /// TW-C2: a NON-required forward that fails to open must NOT fail the
    /// profile — the session stays up and reaches Active.
    #[tokio::test]
    async fn non_required_forward_failure_does_not_fail_profile() {
        let proto = Arc::new(ForwardFailProto::new(Some("opt".to_owned())));
        let cfg = ProfileSupervisorConfig::default();
        let sup = ProfileSupervisor::spawn(
            "p",
            proto.clone(),
            auth(),
            vec![endpoint("a")],
            vec![local_forward("opt", Some(false))],
            cfg,
        );
        let mut rx = sup.watch_state();
        wait_for_state(&mut rx, ProfileStateName::Active).await;
        // One connect: the failing non-required forward did not trigger a
        // session-abandon/reconnect.
        assert_eq!(
            proto
                .connect_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1,
            "non-required forward failure must not cause a reconnect"
        );
        sup.stop().await;
    }

    /// TW-C2: a REQUIRED forward that fails to open fails the profile — the
    /// session is abandoned and the supervisor reconnects (never reaches Active
    /// while the open keeps failing).
    #[tokio::test]
    async fn required_forward_failure_fails_profile() {
        let proto = Arc::new(ForwardFailProto::new(Some("must".to_owned())));
        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(2);
        cfg.backoff.max_delay = Duration::from_millis(4);
        let sup = ProfileSupervisor::spawn(
            "p",
            proto.clone(),
            auth(),
            vec![endpoint("a")],
            vec![local_forward("must", Some(true))],
            cfg,
        );
        let mut rx = sup.watch_state();
        // It must NOT reach Active within the window, and must retry (connect
        // count climbs as the session is abandoned and reconnected).
        let deadline = tokio::time::Instant::now() + Duration::from_millis(600);
        while tokio::time::Instant::now() < deadline {
            assert_ne!(
                *rx.borrow(),
                ProfileStateName::Active,
                "required forward failure must prevent Active"
            );
            let _ = tokio::time::timeout(Duration::from_millis(50), rx.changed()).await;
        }
        assert!(
            proto
                .connect_count
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 2,
            "required forward failure should abandon the session and reconnect"
        );
        sup.stop().await;
    }

    /// TW-C2: instability action = `EmitEvent` emits the InstabilityHit event
    /// but does NOT move the profile to Unstable; the default `MarkDegraded`
    /// does. We drive disconnects past the threshold via repeated connect
    /// failures and observe whether the Unstable state is entered.
    #[tokio::test]
    async fn instability_action_emit_event_does_not_mark_unstable() {
        let proto = Arc::new(MockTunnelProtocol::new());
        proto.set_connect_fails(true);
        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        cfg.backoff.max_attempts = 0;
        cfg.instability.window = Duration::from_secs(60);
        cfg.instability.max_disconnects = 1; // trip after 2 disconnects
        cfg.instability.action = InstabilityAction::EmitEvent;
        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();
        let state_rx = sup.watch_state();

        let mut saw_hit = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(100), events.recv()).await {
                Ok(Some(ProfileEvent::InstabilityHit { .. })) => {
                    saw_hit = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {}
            }
        }
        assert!(
            saw_hit,
            "EmitEvent action must still emit the InstabilityHit event"
        );
        // With EmitEvent the SM must never enter Unstable (it stays on the
        // connect/reconnect path — Resolving/Connecting/Reconnecting).
        assert_ne!(
            *state_rx.borrow(),
            ProfileStateName::Unstable,
            "EmitEvent action must not transition to Unstable"
        );
        sup.stop().await;
    }

    /// TW2-A3: a healthy-but-slow probe whose coarse RTT exceeds
    /// `max_latency_p95` trips the instability detector, and the trip selects the
    /// configured `InstabilityAction` (here `EmitEvent` → emit the InstabilityHit
    /// event but do NOT transition to Unstable). This exercises the latency
    /// sampling path end-to-end at the probe site.
    #[tokio::test]
    async fn high_latency_probe_trips_with_configured_action() {
        // Each keepalive succeeds but takes ~120 ms → RTT sample ~120 ms.
        let proto = Arc::new(SlowKeepaliveProto {
            probe_delay: Duration::from_millis(120),
        });
        let mut cfg = ProfileSupervisorConfig {
            keepalive_interval: Duration::from_millis(40),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        // Ceiling 50 ms — the ~120 ms RTT p95 exceeds it on the first sample.
        cfg.instability.max_latency_p95 = Some(Duration::from_millis(50));
        cfg.instability.action = InstabilityAction::EmitEvent;

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();
        let state_rx = sup.watch_state();

        let mut saw_hit = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(200), events.recv()).await {
                Ok(Some(ProfileEvent::InstabilityHit { .. })) => {
                    saw_hit = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {}
            }
        }
        assert!(
            saw_hit,
            "a high-latency probe (p95 > max_latency_p95) must trip the detector \
             and emit InstabilityHit"
        );
        // EmitEvent action: observe only, never transition to Unstable.
        assert_ne!(
            *state_rx.borrow(),
            ProfileStateName::Unstable,
            "EmitEvent action must not transition to Unstable on a latency trip"
        );
        sup.stop().await;
    }

    /// TW2-A3: with `max_latency_p95 = None` (default) a slow-but-healthy probe
    /// never trips on latency — preserving today's behavior.
    #[tokio::test]
    async fn high_latency_probe_inert_when_threshold_unset() {
        let proto = Arc::new(SlowKeepaliveProto {
            probe_delay: Duration::from_millis(120),
        });
        let cfg = ProfileSupervisorConfig {
            keepalive_interval: Duration::from_millis(40),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        // max_latency_p95 left None (default).
        assert_eq!(cfg.instability.max_latency_p95, None);

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        let mut saw_hit = false;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(800);
        while tokio::time::Instant::now() < deadline {
            match tokio::time::timeout(Duration::from_millis(150), events.recv()).await {
                Ok(Some(ProfileEvent::InstabilityHit { .. })) => {
                    saw_hit = true;
                    break;
                }
                Ok(Some(_)) => {}
                Ok(None) | Err(_) => {}
            }
        }
        assert!(
            !saw_hit,
            "with max_latency_p95 = None a slow-but-healthy probe must not trip"
        );
        sup.stop().await;
    }

    /// TW-C2: `health_check = TcpConnect` selects the bare-TCP liveness probe —
    /// the session's SSH `keepalive()` is NOT used for the liveness check. We
    /// point the endpoint at a live local TCP listener so the probe succeeds and
    /// the profile stays Active, while `keepalive_count` stays 0.
    #[tokio::test]
    async fn health_check_tcp_connect_uses_tcp_probe_not_keepalive() {
        // A real loopback listener the TCP probe can reach.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accept-and-drop loop so connects succeed repeatedly.
        tokio::spawn(async move {
            loop {
                let _ = listener.accept().await;
            }
        });

        let proto = Arc::new(ForwardFailProto::new(None));
        let keepalive_count = Arc::clone(&proto.keepalive_count);
        let cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::TcpConnect,
            keepalive_interval: Duration::from_millis(20),
            keepalive_timeout: Duration::from_secs(2),
            ..Default::default()
        };
        let ep = Endpoint::new(addr.ip().to_string(), addr.port());
        let sup = ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![ep], vec![], cfg);
        let mut rx = sup.watch_state();
        wait_for_state(&mut rx, ProfileStateName::Active).await;
        // Let several probe cadences elapse.
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(
            *rx.borrow(),
            ProfileStateName::Active,
            "TCP health-check against a live listener must keep the profile Active"
        );
        assert_eq!(
            keepalive_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "TcpConnect style must not call the session's SSH keepalive for liveness"
        );
        sup.stop().await;
    }

    /// TW-C2 sanity: the default `SshHandshake` style DOES drive the session's
    /// `keepalive()` (today's fixed behavior), so the counter advances.
    #[tokio::test]
    async fn health_check_ssh_handshake_uses_keepalive() {
        let proto = Arc::new(ForwardFailProto::new(None));
        let keepalive_count = Arc::clone(&proto.keepalive_count);
        let cfg = ProfileSupervisorConfig {
            keepalive_interval: Duration::from_millis(20),
            ..Default::default()
        };
        assert_eq!(cfg.health_check, HealthCheckStyle::SshHandshake);
        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut rx = sup.watch_state();
        wait_for_state(&mut rx, ProfileStateName::Active).await;
        // Wait for at least one keepalive probe to fire.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while keepalive_count.load(std::sync::atomic::Ordering::SeqCst) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            keepalive_count.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "SshHandshake style must drive the session keepalive probe"
        );
        sup.stop().await;
    }

    // ──────── H1 / H2: zero-duration guards + terminal classifier ─────────

    /// H2: a `connect()` that fails with a configurable error, counting
    /// attempts. Lets a test assert that an unrecoverable error stops the
    /// profile after exactly one attempt while a transient one keeps retrying.
    #[derive(Debug)]
    struct ConnectErrProto {
        kind: ConnectErrKind,
        attempts: Arc<std::sync::atomic::AtomicU32>,
    }

    #[derive(Debug, Clone, Copy)]
    enum ConnectErrKind {
        Trust,
        Key,
        Network,
    }

    impl ConnectErrProto {
        fn new(kind: ConnectErrKind) -> Self {
            Self {
                kind,
                attempts: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            }
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for ConnectErrProto {
        async fn connect(
            &self,
            _endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            self.attempts
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(match self.kind {
                ConnectErrKind::Trust => Error::TrustFailed("host key mismatch".into()),
                ConnectErrKind::Key => Error::KeyFailure("cannot load private key".into()),
                ConnectErrKind::Network => Error::NetworkUnreachable("connection refused".into()),
            })
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "connect-err"
        }
    }

    #[test]
    fn is_terminal_connect_error_classifies_trust_and_key_only() {
        assert!(is_terminal_connect_error(&Error::TrustFailed("x".into())));
        assert!(is_terminal_connect_error(&Error::KeyFailure("x".into())));
        // Transient / retryable errors are NOT terminal.
        assert!(!is_terminal_connect_error(&Error::NetworkUnreachable(
            "x".into()
        )));
        assert!(!is_terminal_connect_error(&Error::DnsFailed("x".into())));
        assert!(!is_terminal_connect_error(&Error::KeepaliveTimeout {
            after_ms: 0
        }));
        // Auth failures are handled by the separate `retry_auth_failures` gate.
        assert!(!is_terminal_connect_error(&Error::AuthFailed("x".into())));
        // H-1: a transient key/cert-file I/O error is now surfaced by the ssh2
        // backend as `RuntimeFailure` (not `KeyFailure`), so it must be
        // RETRYABLE — a key briefly unreadable during rotation heals on retry.
        assert!(!is_terminal_connect_error(&Error::RuntimeFailure(
            "transient key-file I/O (NotFound)".into()
        )));
    }

    #[tokio::test]
    async fn trust_failure_is_terminal_and_does_not_retry() {
        // H2: a host-key/trust mismatch must stop the profile, not reconnect
        // forever. Default backoff is unlimited attempts; a non-terminal error
        // would loop indefinitely.
        let proto = Arc::new(ConnectErrProto::new(ConnectErrKind::Trust));
        let attempts = Arc::clone(&proto.attempts);
        let cfg = ProfileSupervisorConfig {
            backoff: BackoffConfig {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(2),
                ..Default::default()
            },
            ..Default::default()
        };
        let sup = ProfileSupervisor::spawn("p", proto, auth(), vec![endpoint("a")], vec![], cfg);
        let mut rx = sup.watch_state();
        wait_for_state(&mut rx, ProfileStateName::Stopped).await;
        // Give the loop a beat to (incorrectly) retry, then assert it did not.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "TrustFailed must be terminal: exactly one connect attempt"
        );
        sup.stop().await;
    }

    #[tokio::test]
    async fn key_failure_is_terminal_and_does_not_retry() {
        // H2: a private-key load failure is a static config error — terminal.
        let proto = Arc::new(ConnectErrProto::new(ConnectErrKind::Key));
        let attempts = Arc::clone(&proto.attempts);
        let cfg = ProfileSupervisorConfig {
            backoff: BackoffConfig {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(2),
                ..Default::default()
            },
            ..Default::default()
        };
        let sup = ProfileSupervisor::spawn("p", proto, auth(), vec![endpoint("a")], vec![], cfg);
        let mut rx = sup.watch_state();
        wait_for_state(&mut rx, ProfileStateName::Stopped).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            attempts.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "KeyFailure must be terminal: exactly one connect attempt"
        );
        sup.stop().await;
    }

    #[tokio::test]
    async fn network_failure_still_retries() {
        // H2 (negative): a transient network error must STAY retryable.
        let proto = Arc::new(ConnectErrProto::new(ConnectErrKind::Network));
        let attempts = Arc::clone(&proto.attempts);
        let cfg = ProfileSupervisorConfig {
            backoff: BackoffConfig {
                initial_delay: Duration::from_millis(1),
                max_delay: Duration::from_millis(2),
                max_attempts: 5,
                ..Default::default()
            },
            ..Default::default()
        };
        let sup = ProfileSupervisor::spawn("p", proto, auth(), vec![endpoint("a")], vec![], cfg);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while attempts.load(std::sync::atomic::Ordering::SeqCst) < 2
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            attempts.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "NetworkUnreachable must remain retryable (more than one attempt)"
        );
        sup.stop().await;
    }

    #[tokio::test]
    async fn zero_keepalive_interval_does_not_panic() {
        // H1 / M1: a programmatically-built config with zero keepalive
        // interval/timeout (bypassing validation) must NOT panic
        // `tokio::time::interval`; the supervisor clamps defensively and still
        // reaches Active.
        let proto = Arc::new(MockTunnelProtocol::new());
        let cfg = ProfileSupervisorConfig {
            keepalive_interval: Duration::ZERO,
            keepalive_timeout: Duration::ZERO,
            ..Default::default()
        };
        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);
        let mut rx = sup.watch_state();
        wait_for_state(&mut rx, ProfileStateName::Active).await;
        // Hold the active loop briefly: the clamped interval keeps it alive
        // rather than crashing or storm-reconnecting.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*rx.borrow(), ProfileStateName::Active);
        sup.stop().await;
    }

    // ──────── F-S1 / F-S4: real instability remediation ───────────────

    /// A protocol that counts connects, records the last endpoint host it was
    /// asked to reach, and hands out a session whose `keepalive` succeeds but
    /// takes `probe_delay` to round-trip — modelling a healthy-but-degraded
    /// (high-latency) link that trips the `max_latency_p95` condition on the
    /// LIVE session.
    #[derive(Debug)]
    struct CountingSlowProto {
        probe_delay: Duration,
        connect_count: Arc<std::sync::atomic::AtomicU32>,
        last_host: Arc<Mutex<Option<String>>>,
    }

    impl CountingSlowProto {
        fn new(probe_delay: Duration) -> Self {
            Self {
                probe_delay,
                connect_count: Arc::new(std::sync::atomic::AtomicU32::new(0)),
                last_host: Arc::new(Mutex::new(None)),
            }
        }
    }

    #[async_trait::async_trait]
    impl spt_protocol::TunnelProtocol for CountingSlowProto {
        async fn connect(
            &self,
            endpoint: &Endpoint,
            _auth: &AuthConfig,
        ) -> Result<Box<dyn spt_protocol::TunnelSession>> {
            self.connect_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.last_host.lock() = Some(endpoint.host.clone());
            Ok(Box::new(SlowKeepaliveSession::new(self.probe_delay)))
        }
        fn capabilities(&self) -> spt_protocol::ProtocolCapabilities {
            spt_protocol::ProtocolCapabilities::ssh3()
        }
        fn name(&self) -> &'static str {
            "counting-slow"
        }
    }

    /// F-S1: a latency-p95 instability trip with `action = Failover` on a LIVE
    /// (slow-but-healthy) session must perform REAL remediation — cool the
    /// current endpoint and rotate to a healthy sibling — not merely relabel to
    /// `Unstable` / emit an event. Pre-fix the profile served over the degraded
    /// link forever (`connect_count` stuck at 1, never leaving endpoint "a").
    #[tokio::test]
    async fn failover_action_latency_trip_cools_and_rotates() {
        let proto = Arc::new(CountingSlowProto::new(Duration::from_millis(60)));

        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        cfg.backoff.max_attempts = 0;
        cfg.keepalive_interval = Duration::from_millis(20);
        cfg.keepalive_timeout = Duration::from_secs(2);
        // Keep the cooled endpoint out of rotation long enough that the pick
        // after the trip lands on the sibling.
        cfg.failover_cooldown = Duration::from_secs(30);
        // A 60 ms probe RTT trips a 10 ms p95 ceiling on the first sample.
        cfg.instability.max_latency_p95 = Some(Duration::from_millis(10));
        cfg.instability.action = InstabilityAction::Failover;

        let sup = ProfileSupervisor::spawn(
            "p",
            proto.clone(),
            auth(),
            vec![endpoint("a"), endpoint("b")],
            vec![],
            cfg,
        );

        // The Failover action must cool "a" and rotate to "b": a second connect
        // whose target is the sibling.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let count = proto
                .connect_count
                .load(std::sync::atomic::Ordering::SeqCst);
            let last = proto.last_host.lock().clone();
            if count >= 2 && last.as_deref() == Some("b") {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "Failover action did not cool+rotate off the degraded endpoint: \
                 connect_count={count}, last_host={last:?}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        sup.stop().await;
    }

    /// F-S4: `action = RestartSession` on a LIVE latency trip must actually tear
    /// the session down and reconnect (a real restart via the reconnect path),
    /// not silently degrade. With a single endpoint the reconnect targets the
    /// same host, so a second connect proves the restart happened. Pre-fix
    /// RestartSession fell through to `MarkDegraded` and never reconnected
    /// (`connect_count` stuck at 1).
    #[tokio::test]
    async fn restart_session_action_latency_trip_reconnects() {
        let proto = Arc::new(CountingSlowProto::new(Duration::from_millis(60)));

        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        cfg.backoff.max_attempts = 0;
        cfg.keepalive_interval = Duration::from_millis(20);
        cfg.keepalive_timeout = Duration::from_secs(2);
        cfg.instability.max_latency_p95 = Some(Duration::from_millis(10));
        cfg.instability.action = InstabilityAction::RestartSession;

        let sup =
            ProfileSupervisor::spawn("p", proto.clone(), auth(), vec![endpoint("a")], vec![], cfg);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if proto
                .connect_count
                .load(std::sync::atomic::Ordering::SeqCst)
                >= 2
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "RestartSession action did not restart the live session (no reconnect)"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        sup.stop().await;
    }

    /// F-S4: an instability action with no live-session mechanism
    /// (`IncreaseKeepalive` / `IncreaseBackoff`) must NOT be silently cosmetic —
    /// it emits a load-time `profile.config_warning` on the injected event bus so
    /// operators aren't misled that a no-op remediation is active.
    #[tokio::test]
    async fn cosmetic_instability_action_emits_config_warning() {
        use spt_events::EventBus;

        let bus = EventBus::default();
        let mut rx = bus.subscribe();

        let proto = Arc::new(MockTunnelProtocol::new());
        let mut cfg = ProfileSupervisorConfig {
            observers: crate::stats::SupervisorObservers {
                event_bus: Some(bus),
                metrics: None,
            },
            ..Default::default()
        };
        cfg.instability.action = InstabilityAction::IncreaseKeepalive;

        let sup = ProfileSupervisor::spawn(
            "warned",
            proto.clone(),
            auth(),
            vec![endpoint("a")],
            vec![],
            cfg,
        );

        let mut saw_warning = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                if ev.kind.as_str() == "profile.config_warning" {
                    assert_eq!(ev.severity, spt_events::Severity::Warn);
                    assert_eq!(
                        ev.profile_id.as_ref().map(spt_core::ProfileId::as_str),
                        Some("warned")
                    );
                    saw_warning = true;
                    break;
                }
            }
        }
        assert!(
            saw_warning,
            "a cosmetic instability action must emit a load-time profile.config_warning"
        );

        sup.stop().await;
    }

    /// F-S2: a shallow health-check style (`TcpConnect`) must emit a load-time
    /// `profile.config_warning` recommending `SshHandshake`, because it can't
    /// detect a silently-dead session whose host stays reachable.
    #[tokio::test]
    async fn shallow_health_check_emits_config_warning() {
        use spt_events::EventBus;

        let bus = EventBus::default();
        let mut rx = bus.subscribe();

        let proto = Arc::new(MockTunnelProtocol::new());
        let cfg = ProfileSupervisorConfig {
            health_check: HealthCheckStyle::TcpConnect,
            observers: crate::stats::SupervisorObservers {
                event_bus: Some(bus),
                metrics: None,
            },
            ..Default::default()
        };

        let sup = ProfileSupervisor::spawn(
            "shallow",
            proto.clone(),
            auth(),
            vec![endpoint("a")],
            vec![],
            cfg,
        );

        let mut saw_warning = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        while tokio::time::Instant::now() < deadline {
            if let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
                if ev.kind.as_str() == "profile.config_warning" {
                    saw_warning = true;
                    break;
                }
            }
        }
        assert!(
            saw_warning,
            "a shallow health_check must emit a load-time profile.config_warning"
        );

        sup.stop().await;
    }

    // ──────── w8: supervisor decisions are mirrored to `tracing` ────────

    /// give-up (ERROR), reconnect (WARN), and the previously-discarded
    /// session-failure error (WARN) must all reach `tracing` at the decision
    /// site with structured fields. Pre-fix these were bus-only / discarded.
    #[tokio::test(flavor = "current_thread")]
    async fn give_up_reconnect_and_session_failure_are_logged() {
        let sub = crate::log_capture::CaptureSubscriber::new();
        let _guard = tracing::subscriber::set_default(sub.clone());

        let proto = Arc::new(MockTunnelProtocol::new());
        proto.set_connect_fails(true);
        let mut cfg = ProfileSupervisorConfig::default();
        cfg.backoff.initial_delay = Duration::from_millis(1);
        cfg.backoff.max_delay = Duration::from_millis(2);
        cfg.backoff.max_attempts = 2;
        let sup = ProfileSupervisor::spawn("logp", proto, auth(), vec![endpoint("a")], vec![], cfg);
        let mut events = sup.take_events().unwrap();

        let mut exhausted = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                ev = events.recv() => match ev {
                    Some(ProfileEvent::BackoffExhausted { .. }) => { exhausted = true; break; }
                    Some(_) => {}
                    None => break,
                },
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
        assert!(exhausted, "profile should exhaust backoff and give up");
        sup.stop().await;

        let recon = sub
            .find("scheduling reconnect")
            .expect("reconnect must be mirrored to tracing");
        assert_eq!(recon.level, tracing::Level::WARN);
        assert!(
            recon.field("attempt").is_some(),
            "reconnect log carries attempt"
        );
        assert!(
            recon.field("delay_ms").is_some(),
            "reconnect log carries delay"
        );

        let giveup = sub
            .find("giving up")
            .expect("give-up must be mirrored to tracing at ERROR");
        assert_eq!(giveup.level, tracing::Level::ERROR);
        assert!(giveup.field("attempt").is_some());

        let fail = sub
            .find("session failed")
            .expect("session-failure error must be logged, not discarded (_e)");
        assert_eq!(fail.level, tracing::Level::WARN);
        assert!(
            fail.field("error").is_some(),
            "the session-failure error is now logged (previously bound to `_e`)"
        );
    }

    /// A successful (re)connect is mirrored to `tracing` at INFO with the
    /// endpoint — even recovery is visible in logs.
    #[tokio::test(flavor = "current_thread")]
    async fn successful_connect_is_logged_at_info() {
        let sub = crate::log_capture::CaptureSubscriber::new();
        let _guard = tracing::subscriber::set_default(sub.clone());

        let proto = Arc::new(MockTunnelProtocol::new());
        let sup = ProfileSupervisor::spawn(
            "okp",
            proto,
            auth(),
            vec![endpoint("a")],
            vec![],
            ProfileSupervisorConfig::default(),
        );
        let mut rx = sup.watch_state();
        loop {
            if *rx.borrow() == ProfileStateName::Active {
                break;
            }
            rx.changed().await.unwrap();
        }
        sup.stop().await;

        let ok = sub
            .find("session connected and authenticated")
            .expect("connect-ok must be mirrored to tracing at INFO");
        assert_eq!(ok.level, tracing::Level::INFO);
        assert_eq!(ok.field("endpoint"), Some("a:22"));
    }

    /// A manual failover is mirrored to `tracing` at WARN with the
    /// from-endpoint.
    #[tokio::test(flavor = "current_thread")]
    async fn manual_failover_is_logged_at_warn() {
        let sub = crate::log_capture::CaptureSubscriber::new();
        let _guard = tracing::subscriber::set_default(sub.clone());

        let proto = Arc::new(MockTunnelProtocol::new());
        let sup = ProfileSupervisor::spawn(
            "fop",
            proto,
            auth(),
            vec![endpoint("a"), endpoint("b")],
            vec![],
            ProfileSupervisorConfig::default(),
        );
        let mut rx = sup.watch_state();
        loop {
            if *rx.borrow() == ProfileStateName::Active {
                break;
            }
            rx.changed().await.unwrap();
        }
        sup.failover(None).await.unwrap();
        sup.stop().await;

        let fo = sub
            .find("failover requested")
            .expect("failover must be mirrored to tracing at WARN");
        assert_eq!(fo.level, tracing::Level::WARN);
        assert_eq!(fo.field("from"), Some("a:22"));
    }
}
