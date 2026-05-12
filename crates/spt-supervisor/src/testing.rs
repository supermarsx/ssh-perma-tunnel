//! Test fixtures for [`spt_supervisor`] consumers.
//!
//! Behind `#[cfg(any(test, feature = "testing"))]` so other crates' tests can
//! reuse the helpers without copy-paste. The convention follows
//! `.orchestration/plans/test-facilities.md`.
//!
//! Highlights:
//!
//! * Re-exports of the existing test-only public types
//!   ([`EchoLiveConnector`], [`UnavailableConnector`], [`MockTunnelProtocol`],
//!   [`LiveReconnectTrigger`], [`SessionRegistry`]) so call sites can pick a
//!   single import path.
//! * [`OrchestratorBuilder`] — fluent constructor for an [`Orchestrator`] that
//!   supervises one or more profiles wired to mock backends.
//! * [`RecordingConnector`] — wraps any [`LiveConnector`] and records every
//!   `open_tcp` / `open_udp` call.
//! * [`wait_for_state`] — polls a profile's [`ProfileStateName`] watcher with
//!   a timeout.
//! * [`synthetic_stats_tick`] — a fixed [`StatsTick`] for sink/dispatcher
//!   tests.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use parking_lot::Mutex;
use spt_auth::AuthConfig;
use spt_config::schema::Profile;
use spt_core::{Error, Result};
use spt_protocol::{Endpoint, TunnelProtocol};
use tokio::time::Instant;

pub use crate::live_connector::{
    BoxedStream, EchoLiveConnector, LiveConnector, UdpEndpoint, UnavailableConnector,
};
pub use crate::profile::ProfileSupervisorConfig;
pub use crate::reconnect_trigger::{LiveReconnectTrigger, ReconnectTrigger};
pub use crate::session::SessionRegistry;
pub use crate::state_machine::ProfileStateName;
pub use crate::stats::{ProfileStats, StatsTick};
pub use spt_forward::testing::MockTunnelProtocol;

use crate::orchestrator::Orchestrator;

// -----------------------------------------------------------------------------
// OrchestratorBuilder
// -----------------------------------------------------------------------------

/// One pre-configured profile entry inside an [`OrchestratorBuilder`].
struct PendingProfile {
    profile: Profile,
    protocol: Arc<dyn TunnelProtocol>,
    auth: AuthConfig,
    endpoints: Vec<Endpoint>,
    cfg: ProfileSupervisorConfig,
}

/// Fluent builder for an [`Orchestrator`] pre-wired with mock protocols.
///
/// The builder keeps a list of `(Profile, protocol, auth, endpoints,
/// supervisor-config)` tuples; [`OrchestratorBuilder::build`] constructs a
/// fresh [`Orchestrator`] and immediately calls [`Orchestrator::start_profile`]
/// for each tuple.
///
/// ```no_run
/// # async fn ex() {
/// use spt_supervisor::testing::{MockTunnelProtocol, OrchestratorBuilder};
/// use std::sync::Arc;
/// let _orch = OrchestratorBuilder::new()
///     .with_profile_named("p", Arc::new(MockTunnelProtocol::new()))
///     .build();
/// # }
/// ```
pub struct OrchestratorBuilder {
    stats_cfg: crate::stats::StatsTickConfig,
    profiles: Vec<PendingProfile>,
}

impl Default for OrchestratorBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl OrchestratorBuilder {
    /// Empty builder.
    #[must_use]
    pub fn new() -> Self {
        Self {
            stats_cfg: crate::stats::StatsTickConfig::default(),
            profiles: Vec::new(),
        }
    }

    /// Override the [`crate::stats::StatsTickConfig`] used by the orchestrator.
    #[must_use]
    pub fn with_stats_config(mut self, cfg: crate::stats::StatsTickConfig) -> Self {
        self.stats_cfg = cfg;
        self
    }

    /// Add an explicit profile with full control over every parameter.
    #[must_use]
    pub fn with_profile(
        mut self,
        profile: Profile,
        protocol: Arc<dyn TunnelProtocol>,
        auth: AuthConfig,
        endpoints: Vec<Endpoint>,
        cfg: ProfileSupervisorConfig,
    ) -> Self {
        self.profiles.push(PendingProfile {
            profile,
            protocol,
            auth,
            endpoints,
            cfg,
        });
        self
    }

    /// Convenience: add a profile with sensible defaults — a single endpoint
    /// `{host=name, port=22}`, an empty [`AuthConfig`], and the default
    /// [`ProfileSupervisorConfig`].
    #[must_use]
    pub fn with_profile_named(self, name: &str, protocol: Arc<dyn TunnelProtocol>) -> Self {
        let mut profile = Profile {
            name: name.to_owned(),
            protocol: "mock".into(),
            host: Some(name.to_owned()),
            ..Profile::default()
        };
        // A `Profile` with no forwards is fine for testing — leave forwards empty.
        profile.port = Some(22);
        let endpoints = vec![Endpoint::new(name, 22)];
        let auth = AuthConfig::new("u", vec![]);
        self.with_profile(
            profile,
            protocol,
            auth,
            endpoints,
            ProfileSupervisorConfig::default(),
        )
    }

    /// Construct the orchestrator and start every queued profile.
    #[must_use]
    pub fn build(self) -> Orchestrator {
        let orch = Orchestrator::with_stats_config(self.stats_cfg);
        for p in self.profiles {
            orch.start_profile(&p.profile, p.protocol, p.auth, p.endpoints, p.cfg);
        }
        orch
    }
}

// -----------------------------------------------------------------------------
// RecordingConnector
// -----------------------------------------------------------------------------

/// One recorded entry from [`RecordingConnector`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectorCall {
    /// `open_tcp(host, port)` was invoked.
    Tcp {
        /// Target host string.
        host: String,
        /// Target port.
        port: u16,
    },
    /// `open_udp()` was invoked.
    Udp,
}

/// Wraps any [`LiveConnector`] and records every call. The inner connector is
/// invoked transparently — the recorder only observes.
///
/// ```
/// use spt_supervisor::testing::{EchoLiveConnector, RecordingConnector};
/// use std::sync::Arc;
/// let inner: Arc<dyn spt_supervisor::LiveConnector> = Arc::new(EchoLiveConnector::default());
/// let rec = RecordingConnector::new(inner);
/// assert!(rec.calls().is_empty());
/// ```
pub struct RecordingConnector {
    inner: Arc<dyn LiveConnector>,
    calls: Arc<Mutex<Vec<ConnectorCall>>>,
}

impl std::fmt::Debug for RecordingConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingConnector")
            .field("calls", &self.calls.lock().clone())
            .finish()
    }
}

impl RecordingConnector {
    /// Wrap `inner`. Calls are recorded into a shared [`Vec`].
    #[must_use]
    pub fn new(inner: Arc<dyn LiveConnector>) -> Self {
        Self {
            inner,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Snapshot of the recorded calls in invocation order.
    #[must_use]
    pub fn calls(&self) -> Vec<ConnectorCall> {
        self.calls.lock().clone()
    }

    /// Shared handle to the call log.
    #[must_use]
    pub fn log_handle(&self) -> Arc<Mutex<Vec<ConnectorCall>>> {
        Arc::clone(&self.calls)
    }
}

#[async_trait]
impl LiveConnector for RecordingConnector {
    async fn open_tcp(&self, host: &str, port: u16) -> Result<BoxedStream> {
        self.calls.lock().push(ConnectorCall::Tcp {
            host: host.to_owned(),
            port,
        });
        self.inner.open_tcp(host, port).await
    }

    async fn open_udp(&self) -> Result<UdpEndpoint> {
        self.calls.lock().push(ConnectorCall::Udp);
        self.inner.open_udp().await
    }
}

// -----------------------------------------------------------------------------
// wait_for_state
// -----------------------------------------------------------------------------

/// Poll the [`ProfileSupervisor`](crate::ProfileSupervisor) named `profile`
/// inside `orch` until it reaches `target` or `timeout` elapses.
///
/// Implementation uses [`tokio::sync::watch::Receiver::changed`] under a
/// [`tokio::time::timeout`], so it never busy-loops.
///
/// ```no_run
/// # async fn ex() {
/// use spt_supervisor::testing::{
///     OrchestratorBuilder, MockTunnelProtocol, ProfileStateName, wait_for_state,
/// };
/// use std::{sync::Arc, time::Duration};
/// let orch = OrchestratorBuilder::new()
///     .with_profile_named("p", Arc::new(MockTunnelProtocol::new()))
///     .build();
/// wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(2))
///     .await
///     .unwrap();
/// # }
/// ```
pub async fn wait_for_state(
    orch: &Orchestrator,
    profile: &str,
    target: ProfileStateName,
    timeout: Duration,
) -> Result<()> {
    let sup = orch
        .profile_handle(profile)
        .ok_or_else(|| Error::RuntimeFailure(format!("profile `{profile}` not running")))?;
    let mut rx = sup.watch_state();
    if *rx.borrow() == target {
        return Ok(());
    }
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::RuntimeFailure(format!(
                "profile `{profile}` did not reach {target:?} within {timeout:?}"
            )));
        }
        match tokio::time::timeout(remaining, rx.changed()).await {
            Ok(Ok(())) => {
                if *rx.borrow() == target {
                    return Ok(());
                }
            }
            Ok(Err(_)) => {
                return Err(Error::RuntimeFailure(format!(
                    "supervisor for `{profile}` stopped before reaching {target:?}"
                )));
            }
            Err(_) => {
                return Err(Error::RuntimeFailure(format!(
                    "profile `{profile}` did not reach {target:?} within {timeout:?}"
                )));
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Synthetic stats
// -----------------------------------------------------------------------------

/// Build a deterministic [`StatsTick`] for sink/dispatcher tests. The values
/// are fixed (no clock, no RNG) so golden assertions remain stable.
///
/// ```
/// use spt_supervisor::testing::synthetic_stats_tick;
/// let t = synthetic_stats_tick();
/// assert_eq!(t.total_sessions, 1);
/// assert_eq!(t.profiles.len(), 1);
/// ```
#[must_use]
pub fn synthetic_stats_tick() -> StatsTick {
    StatsTick {
        at: chrono::DateTime::<chrono::Utc>::from_timestamp(0, 0)
            .expect("epoch is a valid timestamp"),
        total_sessions: 1,
        total_conns_open: 2,
        total_bytes_in: 1024,
        total_bytes_out: 2048,
        profiles: vec![ProfileStats {
            profile: "synthetic".into(),
            sessions: 1,
            conns_open: 2,
            bytes_in: 1024,
            bytes_out: 2048,
            throughput_bps_ewma: 0.0,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn builder_starts_profile_and_wait_for_state_hits_active() {
        let proto = Arc::new(MockTunnelProtocol::new());
        let orch = OrchestratorBuilder::new()
            .with_profile_named("p", proto)
            .build();
        wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(2))
            .await
            .unwrap();
        orch.stop_profile("p").await;
    }

    #[tokio::test]
    async fn wait_for_state_unknown_profile_errors() {
        let orch = OrchestratorBuilder::new().build();
        let err = wait_for_state(
            &orch,
            "ghost",
            ProfileStateName::Active,
            Duration::from_millis(50),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, Error::RuntimeFailure(_)));
    }

    #[tokio::test]
    async fn recording_connector_records_each_call() {
        let inner: Arc<dyn LiveConnector> = Arc::new(EchoLiveConnector::default());
        let rec = RecordingConnector::new(inner);
        let _ = rec.open_tcp("h", 80).await.unwrap();
        let _ = rec.open_udp().await.unwrap();
        let calls = rec.calls();
        assert_eq!(
            calls,
            vec![
                ConnectorCall::Tcp {
                    host: "h".into(),
                    port: 80,
                },
                ConnectorCall::Udp,
            ]
        );
    }

    #[test]
    fn synthetic_stats_tick_is_deterministic() {
        let a = synthetic_stats_tick();
        let b = synthetic_stats_tick();
        assert_eq!(a, b);
    }
}
