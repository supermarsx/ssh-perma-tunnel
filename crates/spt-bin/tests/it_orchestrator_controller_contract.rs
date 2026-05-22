//! Contract test: every default-impl method on
//! [`spt_mcp::Controller`] is overridden by the binary's
//! `OrchestratorController` — operators get real behavior on the four
//! "advanced" tools (session/stats/benchmark) rather than the trait's
//! `-32003 not implemented` fallback.
//!
//! `OrchestratorController` is binary-private (`spt-bin` has no lib
//! target, mirroring `it_controller_failover.rs`), so the integration
//! test cannot construct it directly. Instead, this test verifies the
//! **underlying orchestrator APIs** that the four overrides delegate to,
//! pinning the wiring contract from the supervisor side. The matching
//! unit tests inside `crates/spt-bin/src/controller.rs::tests` call the
//! overrides directly and assert no `McpError::NotImplemented` is
//! returned.
//!
//! When a new defaulted method is added to `Controller`, add:
//!   1. A `default_<method>_returns_not_implemented` test in
//!      `crates/spt-mcp/tests/it_controller_contract.rs`.
//!   2. An `orchestrator_<method>_overrides_default` unit test in
//!      `crates/spt-bin/src/controller.rs::tests` (it has direct access
//!      to `OrchestratorController`).
//!   3. A wiring smoke test in this file targeting the new
//!      `Orchestrator::*` method.

use std::sync::Arc;
use std::time::Duration;

use spt_auth::AuthConfig;
use spt_config::load::load_str;
use spt_forward::testing::MockTunnelProtocol;
use spt_protocol::Endpoint;
use spt_supervisor::{Orchestrator, ProfileSupervisorConfig};

const CFG: &str = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "a"
"#;

fn spawn_orchestrator() -> Arc<Orchestrator> {
    Arc::new(Orchestrator::new())
}

/// `OrchestratorController::session_close` delegates to
/// `Orchestrator::session_close`; missing sessions must surface as
/// `SessionNotFound` (mapped to `McpError::InvalidParams` by the
/// override), NOT `NotImplemented`.
#[tokio::test]
async fn orchestrator_session_close_wired_not_default() {
    let orch = spawn_orchestrator();
    let bogus = spt_core::SessionId::new_v4();
    let err = orch.session_close(&bogus).await.unwrap_err();
    assert!(
        matches!(err, spt_core::Error::SessionNotFound(_)),
        "expected SessionNotFound, got {err:?}"
    );
}

/// `OrchestratorController::session_drain` delegates to
/// `Orchestrator::session_drain`; unknown profiles error in the
/// supervisor (mapped to `McpError::InvalidParams`), not the trait's
/// `NotImplemented`.
#[tokio::test]
async fn orchestrator_session_drain_wired_not_default() {
    let orch = spawn_orchestrator();
    let err = orch
        .session_drain("ghost-profile", Duration::from_secs(1))
        .await
        .expect_err("drain on unknown profile must error");
    let msg = err.to_string();
    assert!(
        msg.contains("ghost-profile") || msg.to_lowercase().contains("profile"),
        "expected profile-not-found wording, got: {msg}"
    );
}

/// `OrchestratorController::session_drain` happy path: drain a running
/// profile returns a `DrainReport` (the override serializes it to JSON).
/// Pins the contract that drain is real, not a `NotImplemented` stub.
#[tokio::test]
async fn orchestrator_session_drain_happy_path_returns_report() {
    let proto = Arc::new(MockTunnelProtocol::new());
    let (cfg, _) = load_str(CFG, false).unwrap();
    let orch = spawn_orchestrator();
    orch.start_profile(
        &cfg.profiles[0],
        proto,
        AuthConfig::new("u", vec![]),
        vec![Endpoint::new("a", 22)],
        ProfileSupervisorConfig::default(),
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    while orch.session_list().is_empty() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "session never came up"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let report = orch
        .session_drain("p", Duration::from_millis(50))
        .await
        .expect("drain must succeed on a running profile");
    // Pin the field shape used by OrchestratorController::session_drain
    // (`drained` + `force_closed` + `already_closed` ints).
    let _: u32 = report.drained;
    let _: u32 = report.force_closed;
    let _: u32 = report.already_closed;

    orch.stop_profile("p").await;
}

/// `OrchestratorController::stats_subscribe` delegates to
/// `Orchestrator::stats_subscribe`, which is infallible — it returns a
/// `broadcast::Receiver<StatsTick>` directly. Pins the override's
/// "wired, not NotImplemented" contract from the supervisor side.
#[tokio::test]
async fn orchestrator_stats_subscribe_returns_receiver() {
    let orch = spawn_orchestrator();
    let rx = orch.stats_subscribe();
    // Channel must be open (receiver constructed); we don't await a tick
    // here because the production override spawns a relay task that the
    // OrchestratorController unit tests cover separately.
    drop(rx);
}

/// `OrchestratorController::run_benchmark` reaches
/// `Orchestrator::live_connector` for tunnel-aware drivers. Pin the
/// connector API exists and produces a `Box<dyn LiveConnector>` so a
/// future refactor of the orchestrator surface can't silently regress
/// the override into a `NotImplemented` path.
#[tokio::test]
async fn orchestrator_live_connector_wired_for_run_benchmark() {
    let orch = spawn_orchestrator();
    // No profile is running; `live_connector` returns a connector that
    // will surface "no profile" at use-time. The mere fact that the
    // method exists and returns is the wiring contract we're pinning.
    let _connector = orch.live_connector("ghost-profile", None);
}
