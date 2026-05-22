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
use tokio::time::Instant;

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
}

/// Outcome of one supervised session — drives the outer `run` loop.
enum LoopAction {
    /// Continue the reconnect loop after `delay`.
    Retry(Duration),
    /// Exit the run loop entirely.
    Exit,
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
            self.backoff.reset();

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
        session: Box<dyn TunnelSession>,
        runners: Vec<ForwardRunner>,
    ) -> LoopAction {
        let msg = control.recv().await;
        match msg {
            None | Some(Control::Shutdown) => {
                for r in runners {
                    r.stop().await;
                }
                let _ = session.close().await;
                LoopAction::Exit
            }
            Some(Control::Failover { override_to, reply }) => {
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
            Some(Control::CloseSession { reply }) => {
                for r in runners {
                    r.stop().await;
                }
                let _ = session.close().await;
                let _ = reply.send(Ok(()));
                LoopAction::Retry(Duration::from_millis(0))
            }
            Some(Control::Drain { grace, reply }) => {
                let report = drain_runners(runners, grace).await;
                let _ = session.close().await;
                let _ = reply.send(Ok(report));
                LoopAction::Exit
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
        let attempt = self.backoff.attempt() + 1;
        let delay = self.backoff.next_delay_default();
        let _ = self.events_tx.send(ProfileEvent::ReconnectScheduled {
            profile: self.name.clone(),
            delay,
            attempt,
        });
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
        let d = spt_core::Diagnostic::what(
            "Cannot trigger failover: supervisor not running",
        )
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
