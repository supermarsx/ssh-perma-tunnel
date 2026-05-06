//! Per-profile supervisor: wraps the [`ProfileStateMachine`] with the
//! reconnect / instability / failover state, drives a [`TunnelProtocol`], and
//! owns one [`ForwardRunner`] per configured forward.

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::SeedableRng;
use spt_auth::AuthConfig;
use spt_config::schema::Forward;
use spt_core::Result;
use spt_forward::{ForwardRunner, ForwardRunnerConfig};
use spt_protocol::{Endpoint, TunnelProtocol, TunnelSession};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::failover::{EndpointSelector, FailoverMode};
use crate::instability::{InstabilityDetector, InstabilityWindow};
use crate::reconnect::{Backoff, BackoffConfig};
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
}

/// Tunables for a [`ProfileSupervisor`].
#[derive(Debug, Clone)]
pub struct ProfileSupervisorConfig {
    /// Backoff parameters.
    pub backoff: BackoffConfig,
    /// Failover mode.
    pub failover_mode: FailoverMode,
    /// Instability detector parameters.
    pub instability: InstabilityWindow,
    /// Optional override for the runner.
    pub runner_cfg: ForwardRunnerConfig,
    /// RNG seed (for deterministic tests). `None` ⇒ entropy.
    pub rng_seed: Option<u64>,
}

impl Default for ProfileSupervisorConfig {
    fn default() -> Self {
        Self {
            backoff: BackoffConfig::default(),
            failover_mode: FailoverMode::Priority,
            instability: InstabilityWindow::default(),
            runner_cfg: ForwardRunnerConfig::default(),
            rng_seed: None,
        }
    }
}

/// Per-profile supervisor.
pub struct ProfileSupervisor {
    name: String,
    state_rx: watch::Receiver<ProfileStateName>,
    events_rx: Option<mpsc::UnboundedReceiver<ProfileEvent>>,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
    /// External access to the live failover selector for tests.
    selector: Arc<Mutex<EndpointSelector>>,
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
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let selector = Arc::new(Mutex::new(EndpointSelector::new(
            cfg.failover_mode,
            endpoints,
        )));

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
        };
        let join = tokio::spawn(task.run(shutdown_rx));

        Self {
            name,
            state_rx,
            events_rx: Some(events_rx),
            shutdown: Some(shutdown_tx),
            join: Some(join),
            selector,
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
    pub fn take_events(&mut self) -> Option<mpsc::UnboundedReceiver<ProfileEvent>> {
        self.events_rx.take()
    }

    /// Shared reference to the underlying [`EndpointSelector`] for tests
    /// and MCP control surfaces.
    pub fn selector(&self) -> Arc<Mutex<EndpointSelector>> {
        Arc::clone(&self.selector)
    }

    /// Shut the supervisor down and join its task.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for ProfileSupervisor {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
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
}

impl ProfileTask {
    async fn run(mut self, mut shutdown: oneshot::Receiver<()>) {
        self.backoff = Backoff::new(self.cfg.backoff);
        self.instability = InstabilityDetector::new(self.cfg.instability);

        // Kick off
        self.fire(SmEvent::Start);

        loop {
            // Bail out if asked to stop or if backoff exhausted.
            if shutdown.try_recv().is_ok() {
                break;
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
                    if Self::sleep_or_shutdown(delay, &mut shutdown).await {
                        break;
                    }
                    continue;
                }
            };

            // 2. Resolve / Connect.
            self.fire(SmEvent::ResolveOk);
            self.fire(SmEvent::ConnectOk);
            self.fire(SmEvent::AuthOk); // protocol.connect handles auth atomically
            let session_res = self.protocol.connect(&endpoint, &self.auth).await;
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
                    if Self::sleep_or_shutdown(delay, &mut shutdown).await {
                        break;
                    }
                    continue;
                }
            };

            // 3. Open forwards.
            let runners = match self.open_forwards(session.as_mut()).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(profile = %self.name, error = %e, "failed to open forwards");
                    self.fire(SmEvent::ForwardDown);
                    let _ = session.close().await;
                    self.handle_session_failure(&endpoint, &e);
                    let delay = self.next_backoff();
                    if Self::sleep_or_shutdown(delay, &mut shutdown).await {
                        break;
                    }
                    continue;
                }
            };
            self.fire(SmEvent::ForwardsUp);
            self.backoff.reset();

            // 4. Hold the session until shutdown — the actual liveness probe
            // would be `session.keepalive()` on a timer. For the foundation
            // crate we wait on shutdown.
            tokio::select! {
                _ = &mut shutdown => {
                    for r in runners {
                        r.stop().await;
                    }
                    let _ = session.close().await;
                    break;
                }
            }
        }

        self.fire(SmEvent::Stop);
        self.fire(SmEvent::Stopped);
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

    async fn sleep_or_shutdown(
        delay: Duration,
        shutdown: &mut oneshot::Receiver<()>,
    ) -> bool {
        tokio::select! {
            _ = tokio::time::sleep(delay) => false,
            _ = shutdown => true,
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

        // Wait for Active.
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
        let mut sup = ProfileSupervisor::spawn(
            "p",
            proto,
            auth(),
            vec![endpoint("a")],
            vec![],
            cfg,
        );
        let mut events = sup.take_events().unwrap();

        // Wait for backoff exhausted.
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
}
