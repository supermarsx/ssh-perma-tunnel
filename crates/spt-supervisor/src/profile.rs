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
    /// RNG seed (for deterministic tests). `None` ⇒ entropy.
    pub rng_seed: Option<u64>,
    /// Shared registry to publish session rows into. Default = a fresh
    /// per-supervisor registry; the [`crate::Orchestrator`] injects its own.
    pub registry: SessionRegistry,
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
            rng_seed: None,
            registry: SessionRegistry::new(),
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
    pub fn spawn(
        name: impl Into<String>,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        endpoints: Vec<Endpoint>,
        forwards: Vec<Forward>,
        cfg: ProfileSupervisorConfig,
    ) -> Self {
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
        let task = ProfileTask {
            name: name.clone(),
            protocol,
            auth,
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
    }
}

// ---------------------------------------------------------------------------
// Task
// ---------------------------------------------------------------------------

struct ProfileTask {
    name: String,
    protocol: Arc<dyn TunnelProtocol>,
    auth: AuthConfig,
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
    KeepaliveFailed,
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
                // t8-C1: notify chaos / harness observer (no-op in production).
                crate::reconnect::notify_max_exhausted(self.backoff.attempt());
                break;
            }

            // 1. Pick endpoint.
            let endpoint = match self.pick_endpoint() {
                Some(ep) => ep,
                None => {
                    self.fire(SmEvent::FailoverPick);
                    let delay = self.next_backoff();
                    if self.sleep_or_control(delay, &mut control).await {
                        break;
                    }
                    continue;
                }
            };

            // 2. Connect.
            self.fire(SmEvent::ResolveOk);
            self.fire(SmEvent::ConnectOk);
            self.fire(SmEvent::AuthOk);
            let session_res = tokio::select! {
                r = self.protocol.connect(&endpoint, &self.auth) => r,
                ctrl = control.recv() => {
                    match ctrl {
                        Some(Control::Shutdown) | None => {
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
                            // Nothing to drain pre-session.
                            let _ = reply.send(Ok(DrainReport::default()));
                            continue;
                        }
                    }
                }
            };
            let mut session = match session_res {
                Ok(s) => {
                    self.selector
                        .lock()
                        .record_success(&endpoint.host, endpoint.port);
                    // t8-C1: notify chaos / harness observer (no-op in production).
                    crate::reconnect::notify_success(self.backoff.attempt());
                    s
                }
                Err(e) => {
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
                    self.fire(SmEvent::ForwardDown);
                    self.unpublish_session();
                    let _ = session.close().await;
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
                    continue;
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
        // treat any `Err` as "session dead → reconnect now".
        let mut keepalive = tokio::time::interval(self.cfg.keepalive_interval);
        // The first interval tick fires immediately; consume it so we
        // don't probe the moment we enter the loop.
        keepalive.set_missed_tick_behavior(MissedTickBehavior::Delay);
        keepalive.tick().await;

        let decision = loop {
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
                    match session.keepalive().await {
                        Ok(()) => continue,
                        Err(e) => {
                            tracing::warn!(
                                profile = %self.name,
                                error = %e,
                                "session keepalive failed; triggering reconnect"
                            );
                            break ActiveDecision::KeepaliveFailed;
                        }
                    }
                }
            }
        };

        match decision {
            ActiveDecision::ShutdownExit => {
                for r in runners {
                    r.stop().await;
                }
                let _ = session.close().await;
                LoopAction::Exit
            }
            ActiveDecision::Failover { override_to, reply } => {
                let res = self.apply_manual_override(override_to.as_deref());
                let _ = self.events_tx.send(ProfileEvent::FailoverRequested {
                    profile: self.name.clone(),
                    override_to,
                });
                let _ = reply.send(res);
                for r in runners {
                    r.stop().await;
                }
                let _ = session.close().await;
                LoopAction::Retry(Duration::from_millis(0))
            }
            ActiveDecision::CloseSession { reply } => {
                for r in runners {
                    r.stop().await;
                }
                let _ = session.close().await;
                let _ = reply.send(Ok(()));
                LoopAction::Retry(Duration::from_millis(0))
            }
            ActiveDecision::Drain { grace, reply } => {
                let report = drain_runners(runners, grace).await;
                let _ = session.close().await;
                let _ = reply.send(Ok(report));
                LoopAction::Exit
            }
            ActiveDecision::KeepaliveFailed => {
                self.fire(SmEvent::ForwardDown);
                for r in runners {
                    r.stop().await;
                }
                let _ = session.close().await;
                LoopAction::Retry(Duration::from_millis(0))
            }
        }
    }

    fn handle_control_idle(&mut self, msg: Control) -> std::ops::ControlFlow<()> {
        match msg {
            Control::Shutdown => std::ops::ControlFlow::Break(()),
            Control::Failover { override_to, reply } => {
                let res = self.apply_manual_override(override_to.as_deref());
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
                let _ = reply.send(Ok(DrainReport::default()));
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

    fn pick_endpoint(&self) -> Option<Endpoint> {
        let mut rng: rand::rngs::StdRng = match self.cfg.rng_seed {
            Some(s) => SeedableRng::seed_from_u64(s),
            None => SeedableRng::from_entropy(),
        };
        let now = Instant::now();
        let sel = self.selector.lock();
        sel.pick(&mut rng, now).ok().cloned()
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
                        let _ = reply.send(Ok(DrainReport::default()));
                        false
                    }
                }
            }
        }
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
            }
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
                    Some(_) => continue,
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
                Ok(Some(_)) => continue,
                Ok(None) | Err(_) => return None,
            }
        }
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
}
