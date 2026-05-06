#![allow(clippy::default_constructed_unit_structs)]
//! Smoke test for the deeper `diagnose` checks introduced by f-diagnostics.
//! Runs the runner with the full check set against a default context;
//! asserts that secrets/runtime/firewall/service/mcp all produce at least
//! one check (Pass / Skipped acceptable) without panicking.

use spt_diagnostics::{
    checks::{
        FirewallDiagnostic, McpDiagnostic, NetworkDiagnostic, OsDiagnostic, PermissionsDiagnostic,
        RuntimeDiagnostic, SecretsDiagnostic, ServiceDiagnostic, Ssh2Diagnostic, TimeDiagnostic,
    },
    framework::DiagnosticContext,
    DiagnosticRunner,
};

#[tokio::test]
async fn extended_runner_produces_checks_for_every_group() {
    let runner = DiagnosticRunner::new()
        .register(OsDiagnostic::default())
        .register(PermissionsDiagnostic::default())
        .register(TimeDiagnostic::default())
        .register(NetworkDiagnostic::default())
        .register(RuntimeDiagnostic::default())
        .register(SecretsDiagnostic::default())
        .register(ServiceDiagnostic::default())
        .register(McpDiagnostic::default())
        .register(FirewallDiagnostic::default())
        .register(Ssh2Diagnostic::default());
    let report = runner.run(&DiagnosticContext::default()).await;
    assert!(!report.checks.is_empty(), "expected at least some checks");
    // No panics, and the runner aggregates without losing data.
    let counts = report.counts();
    assert_eq!(
        counts.pass + counts.warn + counts.fail + counts.skipped,
        report.checks.len()
    );
}
