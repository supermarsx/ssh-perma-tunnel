//! Live-tunnel adapter for the [`spt-benchmark`] `ReconnectTrigger` seam.
//!
//! [`LiveReconnectTrigger`] wraps an [`Arc<crate::ProfileSupervisor>`] and
//! exposes:
//!
//! * `wait_session_up` — blocks until the supervisor reaches
//!   [`crate::ProfileStateName::Active`].
//! * `trigger_drop` — sends a [`crate::control::Control::CloseSession`] over
//!   the supervisor's control channel, forcing a fresh reconnect cycle.
//!
//! The trait shape mirrors `spt_benchmark::ReconnectTrigger` so the bench
//! reconnect driver can consume one verbatim. We intentionally do **not**
//! depend on `spt-benchmark` from `spt-supervisor` (avoiding a dep cycle);
//! the bench wiring lives in `spt-bin` and adapts via a tiny bridge.

use std::sync::Arc;

use async_trait::async_trait;
use spt_core::{Error, Result};

use crate::profile::ProfileSupervisor;
use crate::state_machine::ProfileStateName;

/// Adapter trait — same shape as `spt_benchmark::ReconnectTrigger`. Defined
/// here so this crate stays free of a `spt-benchmark` dep.
#[async_trait]
pub trait ReconnectTrigger: Send + Sync {
    /// Block until the next session OPEN-handshake completes.
    async fn wait_session_up(&self) -> Result<()>;
    /// Cause the current session to drop. Returns when the loss has been
    /// signalled (not necessarily when the next reconnect has started).
    async fn trigger_drop(&self) -> Result<()>;
}

/// Live trigger driving a real [`ProfileSupervisor`].
pub struct LiveReconnectTrigger {
    sup: Arc<ProfileSupervisor>,
}

impl LiveReconnectTrigger {
    /// New trigger over `sup`.
    #[must_use]
    pub fn new(sup: Arc<ProfileSupervisor>) -> Self {
        Self { sup }
    }
}

#[async_trait]
impl ReconnectTrigger for LiveReconnectTrigger {
    async fn wait_session_up(&self) -> Result<()> {
        let mut rx = self.sup.watch_state();
        // If we are already Active, return immediately.
        if *rx.borrow() == ProfileStateName::Active {
            return Ok(());
        }
        loop {
            if rx.changed().await.is_err() {
                return Err(Error::runtime_failure(
                    spt_core::Diagnostic::what(
                        "Supervisor stopped before session reached Active state",
                    )
                    .why("the state channel was closed while waiting for reconnect")
                    .how_to_fix(
                        "Check the supervisor's recent log lines for the underlying \
                         shutdown cause (panic, signal, max-restart-budget exceeded). \
                         If unexpected, re-run with `--verbose` to capture state \
                         transitions.",
                    )
                    .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                    .build(),
                ));
            }
            if *rx.borrow() == ProfileStateName::Active {
                return Ok(());
            }
        }
    }

    async fn trigger_drop(&self) -> Result<()> {
        self.sup.close_session().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ProfileSupervisorConfig;
    use spt_auth::AuthConfig;
    use spt_forward::testing::MockTunnelProtocol;
    use spt_protocol::Endpoint;

    #[tokio::test]
    async fn live_reconnect_trigger_flows() {
        let proto = std::sync::Arc::new(MockTunnelProtocol::new());
        let sup = std::sync::Arc::new(ProfileSupervisor::spawn(
            "p",
            proto.clone(),
            AuthConfig::new("u", vec![]),
            vec![Endpoint::new("h", 22)],
            vec![],
            ProfileSupervisorConfig::default(),
        ));
        let trigger = LiveReconnectTrigger::new(sup.clone());

        // Wait until the first session is up.
        trigger.wait_session_up().await.unwrap();
        let count_before = proto.connect_count();

        // Force a drop.
        trigger.trigger_drop().await.unwrap();

        // Wait for the next session to come up (connect_count increments).
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            if proto.connect_count() > count_before {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "no reconnect observed"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        sup.stop().await;
    }

    // ──────── t8-A1: diagnostic regression tests ──────────────────────

    #[test]
    fn supervisor_stopped_diagnostic_carries_remediation() {
        // Mirrors the converted site in wait_session_up.
        let d =
            spt_core::Diagnostic::what("Supervisor stopped before session reached Active state")
                .why("the state channel was closed while waiting for reconnect")
                .how_to_fix(
                    "Check the supervisor's recent log lines for the underlying \
             shutdown cause (panic, signal, max-restart-budget exceeded). \
             If unexpected, re-run with `--verbose` to capture state \
             transitions.",
                )
                .retry_advice(spt_core::RetryAdvice::RetryWithBackoff)
                .build();
        let e = spt_core::Error::runtime_failure(d);
        spt_core::assert_diagnostic_contains!(e,
            what: "Supervisor stopped before session reached Active",
            how_to_fix: "max-restart-budget",
        );
        assert_eq!(e.exit_code(), spt_core::ExitCode::RuntimeFailure);
    }
}
