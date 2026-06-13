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
use crate::instability::{InstabilityDetector, InstabilityWindow};
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
    events_rx: Mutex<Option<mpsc::UnboundedReceiver<ProfileEvent>>>,
    control: mpsc::Sender<Control>,
    join: Mutex<Option<JoinHandle<()>>>,
    /// External access to the live failover selector for tests.
    selector: Arc<Mutex<EndpointSelector>>,
    /// Tracks the currently-published session id for this supervisor.
    current_session: Arc<Mutex<Option<SessionId>>>,
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
        let (state_tx, state_rx) = watch::channel(ProfileStateName::Idle);
        let (events_tx, events_rx) = mpsc::unbounded_channel();
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
        }
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
    pub fn take_events(&self) -> Option<mpsc::UnboundedReceiver<ProfileEvent>> {
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
    events_tx: mpsc::UnboundedSender<ProfileEvent>,
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
}

impl ProfileTask {
    async fn run(mut self, mut control: mpsc::Receiver<Control>) {
        self.backoff = Backoff::new(self.cfg.backoff);
        self.instability = InstabilityDetector::new(self.cfg.instability);

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
                let _ = self.events_tx.send(ProfileEvent::BackoffExhausted {
                    profile: self.name.clone(),
                });
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
                    // Connect + auth confirmed: walk the SM to EstablishingForwards.
                    self.fire(SmEvent::ConnectOk);
                    self.fire(SmEvent::AuthOk);
                    self.current_endpoint = Some(endpoint.clone());
                    // t8-C1: notify chaos / harness observer (no-op in production).
                    crate::reconnect::notify_success(self.backoff.attempt());
                    s
                }
                Err(e) => {
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
        let mut keepalive = tokio::time::interval(self.cfg.keepalive_interval);
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
                    break match msg {
                        None | Some(Control::Shutdown) => ActiveDecision::ShutdownExit,
                        Some(Control::Failover { override_to, reply }) => {
                            ActiveDecision::Failover { override_to, reply }
                        }
                        Some(Control::CloseSession { reply }) => {
                            ActiveDecision::CloseSession { reply }
                        }
                        Some(Control::Drain { grace, reply }) => {
                            ActiveDecision::Drain { grace, reply }
                        }
                    };
                }
                _ = keepalive.tick() => {
                    // E1-F11: bound the probe so a black-holed connection can't
                    // wedge the control channel. Treat timeout as failure.
                    let probe = tokio::time::timeout(
                        self.cfg.keepalive_timeout,
                        session.keepalive(),
                    ).await;
                    match probe {
                        Ok(Ok(())) => {
                            // E1-F8: a healthy probe accrues clean-uptime for
                            // the instability detector. When enough clean time
                            // has elapsed the Unstable flag clears.
                            if self.instability.tick_healthy(Instant::now()) {
                                let _ = self.events_tx.send(ProfileEvent::InstabilityCleared {
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
                            tracing::warn!(
                                profile = %self.name,
                                error = %e,
                                "session keepalive failed; triggering reconnect"
                            );
                            break ActiveDecision::SessionLost;
                        }
                        Err(_) => {
                            tracing::warn!(
                                profile = %self.name,
                                "session keepalive timed out; triggering reconnect"
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
                            let _ = self.events_tx.send(ProfileEvent::StateChanged {
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
                let _ = self.events_tx.send(ProfileEvent::FailoverRequested {
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
                    self.handle_session_failure(&ep, &Error::NetworkUnreachable(
                        "session keepalive failed".into(),
                    ));
                }
                let delay = self.next_backoff();
                LoopAction::Retry(delay)
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
                let _ = self.events_tx.send(ProfileEvent::FailoverRequested {
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

    fn handle_session_failure(&mut self, endpoint: &Endpoint, _e: &spt_core::Error) {
        let now = Instant::now();
        self.selector
            .lock()
            .record_failure(&endpoint.host, endpoint.port, now);
        if self.instability.record_disconnect(now) {
            let _ = self.events_tx.send(ProfileEvent::InstabilityHit {
                profile: self.name.clone(),
            });
            self.cfg.observers.emit_lifecycle(
                "profile.instability_hit",
                spt_events::Severity::Warn,
                &self.name,
                format!("profile `{}` instability detector tripped", self.name),
                &[],
            );
            self.fire(SmEvent::InstabilityHit);
        }
    }

    async fn open_forwards(
        &mut self,
        session: &mut dyn TunnelSession,
    ) -> Result<Vec<ForwardRunner>> {
        let mut runners = Vec::with_capacity(self.forwards.len());
        for f in &self.forwards {
            let r = ForwardRunner::start(f, session, &self.cfg.runner_cfg).await?;
            runners.push(r);
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
        let _ = self.events_tx.send(ProfileEvent::ReconnectScheduled {
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
                serde_json::Value::from(
                    u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                ),
            ),
        ];
        if let Some(ep) = &endpoint {
            fields.push(("endpoint", serde_json::Value::from(ep.clone())));
        }
        self.cfg.observers.emit_lifecycle(
            "profile.reconnect_scheduled",
            spt_events::Severity::Warn,
            &self.name,
            format!("profile `{}` reconnect attempt {attempt} in {delay:?}", self.name),
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
                        let _ = self.events_tx.send(ProfileEvent::FailoverRequested {
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
                let _ = self.events_tx.send(ProfileEvent::StateChanged {
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

fn parse_endpoint_key(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| Error::InvalidArgs(format!("endpoint key `{s}` missing `:port`")))?;
    let port: u16 = port
        .parse()
        .map_err(|e| Error::InvalidArgs(format!("endpoint port `{port}`: {e}")))?;
    Ok((host.to_owned(), port))
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
        events: &mut mpsc::UnboundedReceiver<ProfileEvent>,
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
            proto.connect_count.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "expected a real reconnect (≥2 connects)"
        );
        sup.stop().await;
    }

    async fn wait_for_state(
        rx: &mut watch::Receiver<ProfileStateName>,
        target: ProfileStateName,
    ) {
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
}
