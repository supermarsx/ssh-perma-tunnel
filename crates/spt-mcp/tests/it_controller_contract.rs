//! Contract test: pin every default-impl method on the `Controller` trait
//! to its `Error::NotImplemented` behavior.
//!
//! The trait keeps `NotImplemented` defaults for the four "advanced"
//! methods (session/stats/benchmark) so that embedders implementing the
//! read-only mutator subset don't break — but a future refactor that
//! silently changes a default to `Ok(())` would mask a real wiring gap in
//! the production [`crate::OrchestratorController`] (see the companion
//! test in `spt-bin/tests/it_orchestrator_controller_contract.rs`).
//!
//! Each test below uses [`spt_mcp::NoopController`], which deliberately
//! does NOT override the four default-impl methods — exercising it
//! verifies the trait defaults themselves, not any concrete override.
//!
//! If you add a new defaulted method to `Controller`, add a matching test
//! here AND a corresponding override test in
//! `spt-bin/tests/it_orchestrator_controller_contract.rs`.

use spt_mcp::{Controller, Error, NoopController};

/// One-stop matcher that fails with a helpful message if `err` is not
/// `Error::NotImplemented(expected)`.
fn assert_not_implemented(err: Error, expected: &'static str) {
    match err {
        Error::NotImplemented(s) => assert_eq!(
            s, expected,
            "NotImplemented payload mismatch: got {s:?}, expected {expected:?}"
        ),
        other => panic!("expected NotImplemented({expected:?}), got {other:?}"),
    }
}

#[tokio::test]
async fn default_session_close_returns_not_implemented() {
    let c = NoopController;
    let err = c
        .session_close("any-session-id")
        .await
        .expect_err("default session_close must error");
    assert_not_implemented(err, "Controller::session_close");
}

#[tokio::test]
async fn default_session_drain_returns_not_implemented() {
    let c = NoopController;
    let err = c
        .session_drain("any-profile", 5)
        .await
        .expect_err("default session_drain must error");
    assert_not_implemented(err, "Controller::session_drain");
}

#[tokio::test]
async fn default_stats_subscribe_returns_not_implemented() {
    let c = NoopController;
    let (tx, _rx) = tokio::sync::mpsc::channel::<serde_json::Value>(8);
    let err = c
        .stats_subscribe(1_000, tx)
        .await
        .expect_err("default stats_subscribe must error");
    assert_not_implemented(err, "Controller::stats_subscribe");
}

#[tokio::test]
async fn default_run_benchmark_returns_not_implemented() {
    let c = NoopController;
    let err = c
        .run_benchmark(serde_json::json!({"driver": "noop"}))
        .await
        .expect_err("default run_benchmark must error");
    assert_not_implemented(err, "Controller::run_benchmark");
}

/// The six required (non-defaulted) methods on `NoopController` must also
/// return `NotImplemented` — but via the crate's explicit overrides on
/// `NoopController`, not via trait defaults. This pins the no-op semantics
/// that embedders rely on when constructing a `NoopController` as a
/// placeholder.
#[tokio::test]
async fn noop_controller_six_required_methods_return_not_implemented() {
    let c = NoopController;
    assert_not_implemented(
        c.reload().await.expect_err("reload"),
        "Controller::reload",
    );
    assert_not_implemented(
        c.failover("p", None).await.expect_err("failover"),
        "Controller::failover",
    );
    assert_not_implemented(
        c.profile_start("p").await.expect_err("profile_start"),
        "Controller::profile_start",
    );
    assert_not_implemented(
        c.profile_stop("p").await.expect_err("profile_stop"),
        "Controller::profile_stop",
    );
    let fwd = spt_config::schema::Forward::default();
    assert_not_implemented(
        c.forward_add("p", &fwd).await.expect_err("forward_add"),
        "Controller::forward_add",
    );
    assert_not_implemented(
        c.forward_remove("p", "f").await.expect_err("forward_remove"),
        "Controller::forward_remove",
    );
}
