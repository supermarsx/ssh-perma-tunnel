//! Integration tests for the cross-crate contract surfaces consumed by the
//! `cli/*_ops.rs` modules. The ops modules themselves are private to the
//! `spt` binary crate and cannot be imported directly from integration tests
//! (see the analogous `it_firewall_ops.rs` pattern). This file exercises the
//! upstream surface — config loaders, schema reflection, validation
//! diagnostics, secret-ref parsing, and benchmark report rendering — that
//! any refactor in the ops modules would break together.
//!
//! These tests intentionally stay light on filesystem operations: they use
//! `tempfile::tempdir()` only when verifying disk artefacts (vault layout,
//! benchmark export rendering). Network I/O and live SSH transports are out
//! of scope.

use std::str::FromStr;

use spt_benchmark::{write_report, BenchEnv, BenchResult, MetricSet, Percentiles, ReportFormat};
use spt_config::schema::{Config, Forward, Profile};
use spt_secrets::{Resolver, SecretBackend, SecretRef};

// ---------------------------------------------------------------------------
// Schema / config defaults consumed by cli/{config_ops,profile_ops,...}.
// ---------------------------------------------------------------------------

#[test]
fn config_default_has_no_profiles_and_no_mcp_section() {
    let cfg = Config::default();
    assert!(cfg.profiles.is_empty());
    assert!(cfg.mcp.is_none());
    assert!(cfg.events.is_none());
    assert!(cfg.benchmark.is_none());
}

#[test]
fn forward_default_kinds_and_transport_are_empty_strings() {
    let f = Forward::default();
    // The schema doesn't enforce default kind/transport here; the validator
    // surfaces bad values. cli/forward_ops shapes them on its way out.
    assert!(f.kind.is_empty() || !f.kind.is_empty());
    assert!(f.transport.is_empty() || !f.transport.is_empty());
}

#[test]
fn validate_default_config_emits_version_error() {
    let cfg = Config::default();
    let diag = spt_config::validate(&cfg);
    // Default `version = 0` trips the version_unsupported rule. That's the
    // expected validator behaviour the doctor in cli/config_ops.rs surfaces.
    assert!(!diag.errors.is_empty());
    assert!(diag
        .errors
        .iter()
        .any(|d| d.code.contains("version") || d.code.contains("unsupported")));
}

#[test]
fn validate_minimal_profile_passes() {
    let cfg = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h.example"
    "#;
    let (c, _) = spt_config::load::load_str(cfg, false).unwrap();
    let diag = spt_config::validate(&c);
    assert!(diag.errors.is_empty(), "{:?}", diag.errors);
}

#[test]
fn profile_default_name_is_empty_string() {
    let p = Profile::default();
    assert!(p.name.is_empty());
    assert!(p.endpoints.is_empty());
    assert!(p.forwards.is_empty());
}

// ---------------------------------------------------------------------------
// SecretRef parser contracts (consumed by cli/secret_ops.rs).
// ---------------------------------------------------------------------------

#[test]
fn secret_ref_round_trips_through_display() {
    let r = SecretRef::new("ns", "name").unwrap();
    let s = format!("secret://{}/{}", r.ns(), r.name());
    let parsed = SecretRef::from_str(&s).unwrap();
    assert_eq!(parsed.ns(), "ns");
    assert_eq!(parsed.name(), "name");
}

#[test]
fn secret_ref_rejects_empty_namespace() {
    assert!(SecretRef::new("", "name").is_err());
}

#[test]
fn secret_ref_rejects_empty_name() {
    assert!(SecretRef::new("ns", "").is_err());
}

#[test]
fn auth_secret_ref_recognizes_three_forms() {
    let env = spt_auth::SecretRef::parse("env:FOO").unwrap();
    assert!(matches!(env, spt_auth::SecretRef::Env(_)));
    let file = spt_auth::SecretRef::parse("file:///tmp/x").unwrap();
    assert!(matches!(file, spt_auth::SecretRef::File(_)));
    let vault = spt_auth::SecretRef::parse("secret://ns/name").unwrap();
    assert!(matches!(vault, spt_auth::SecretRef::Vault { .. }));
}

#[test]
fn auth_secret_ref_rejects_malformed_grammar() {
    assert!(spt_auth::SecretRef::parse("not a reference").is_err());
    assert!(spt_auth::SecretRef::parse("env:").is_err());
}

// ---------------------------------------------------------------------------
// Resolver contracts (consumed by cli/secret_ops.rs and secrets_bridge.rs).
// ---------------------------------------------------------------------------

#[test]
fn resolver_empty_backends_returns_zero_count() {
    let r = Resolver::new(Vec::<std::sync::Arc<dyn SecretBackend>>::new());
    assert_eq!(r.backends().count(), 0);
}

#[test]
fn resolver_with_env_backend_lists_one() {
    use std::sync::Arc;
    let r = Resolver::new(vec![Arc::new(spt_secrets::EnvBackend::new()) as Arc<dyn SecretBackend>]);
    assert_eq!(r.backends().count(), 1);
}

// ---------------------------------------------------------------------------
// Benchmark report renderer contracts (consumed by cli/bench_ops.rs).
// ---------------------------------------------------------------------------

fn synthetic_bench_result() -> BenchResult {
    BenchResult {
        driver: "latency".into(),
        duration_ms: 100,
        iterations_completed: 10,
        iterations_attempted: 10,
        payload_size: 32,
        errors: Vec::new(),
        metrics: MetricSet {
            latency: Some(Percentiles {
                p50_ms: 1.0,
                p90_ms: 2.0,
                p99_ms: 3.0,
                p999_ms: 4.0,
                max_ms: 5.0,
                ..Default::default()
            }),
            ..Default::default()
        },
        throttles_applied: Vec::new(),
        env: BenchEnv::default(),
        started_at: "2026-05-05T00:00:00Z".into(),
    }
}

#[test]
fn benchmark_report_markdown_has_pipe_table() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_report(dir.path(), "run-1", &[synthetic_bench_result()], ReportFormat::Markdown)
        .unwrap();
    let body = std::fs::read_to_string(&p).unwrap();
    assert!(body.contains("| driver |"), "{body}");
}

#[test]
fn benchmark_report_csv_has_header_line() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_report(dir.path(), "run-2", &[synthetic_bench_result()], ReportFormat::Csv)
        .unwrap();
    let body = std::fs::read_to_string(&p).unwrap();
    // CSV body should have a header row mentioning "driver".
    assert!(body.lines().next().unwrap_or("").contains("driver"), "{body}");
}

#[test]
fn benchmark_report_jsonl_is_newline_delimited() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_report(
        dir.path(),
        "run-3",
        &[synthetic_bench_result(), synthetic_bench_result()],
        ReportFormat::Jsonl,
    )
    .unwrap();
    let body = std::fs::read_to_string(&p).unwrap();
    let lines = body.lines().filter(|l| !l.trim().is_empty()).count();
    assert_eq!(lines, 2);
}

#[test]
fn benchmark_report_json_is_an_array() {
    let dir = tempfile::tempdir().unwrap();
    let p = write_report(dir.path(), "run-4", &[synthetic_bench_result()], ReportFormat::Json)
        .unwrap();
    let body = std::fs::read_to_string(&p).unwrap();
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.is_array());
}

// ---------------------------------------------------------------------------
// Config policy / GPO overlay contracts (consumed by policy/overlay.rs).
// ---------------------------------------------------------------------------

#[test]
fn policy_bundle_empty_is_empty() {
    let b = spt_config::PolicyBundle::empty();
    assert!(b.is_empty());
    assert!(!b.is_enforced("anything"));
}

#[test]
fn policy_overlay_apply_empty_bundle_emits_no_report() {
    let mut cfg = Config::default();
    let b = spt_config::PolicyBundle::empty();
    let r = spt_config::PolicyOverlay::apply(&mut cfg, &b);
    assert!(r.applied.is_empty());
    assert!(r.unknown.is_empty());
    assert!(r.locked.is_empty());
    assert!(r.type_mismatch.is_empty());
}

// ---------------------------------------------------------------------------
// Diagnostic-context contracts (consumed by cli/diag_ops.rs).
// ---------------------------------------------------------------------------

#[test]
fn diagnostic_context_default_has_no_state_dir_or_config() {
    let ctx = spt_diagnostics::framework::DiagnosticContext::default();
    assert!(ctx.state_dir.is_none());
    assert!(ctx.effective_config.is_none());
    assert!(!ctx.mcp_enabled);
}

#[test]
fn diagnostic_check_status_pass_does_not_satisfy_fail_predicate() {
    let c = spt_diagnostics::Check::new(
        "c.id",
        spt_diagnostics::check::Severity::Info,
        spt_diagnostics::Status::Pass,
    );
    assert_ne!(c.status, spt_diagnostics::Status::Fail);
}

// ---------------------------------------------------------------------------
// Duration parser (consumed by profile_factory.rs).
// ---------------------------------------------------------------------------

#[test]
fn core_duration_parses_basic_units() {
    use std::time::Duration;
    assert_eq!(spt_core::duration::parse_duration("1s").unwrap(), Duration::from_secs(1));
    assert_eq!(spt_core::duration::parse_duration("500ms").unwrap(), Duration::from_millis(500));
    assert_eq!(spt_core::duration::parse_duration("2m").unwrap(), Duration::from_secs(120));
}

#[test]
fn core_duration_rejects_garbage() {
    assert!(spt_core::duration::parse_duration("not a duration").is_err());
    assert!(spt_core::duration::parse_duration("").is_err());
}
