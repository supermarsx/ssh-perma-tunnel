//! Parse-level integration coverage for the `spt` command-tree.
//!
//! The internal `cli_dispatch::dispatch` entry point is private to the
//! `spt` binary (no library re-export), so the bulk of routing coverage
//! lives inline at the bottom of `crates/spt-bin/src/cli_dispatch.rs`.
//! This file complements those inline tests with cross-crate
//! parse-then-pattern-match smoke tests that lock down the shape of
//! `Cli::command` for every top-level group. They keep the brief's
//! external integration-test file populated with meaningful assertions
//! without duplicating the inline dispatcher coverage.

use spt_cli::{groups, Cli, Command};
use clap::Parser;

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(args).expect("parse")
}

#[test]
fn parses_into_config_group() {
    let cli = parse(&["spt", "config", "validate", "--strict"]);
    assert!(matches!(cli.command, Command::Config(_)));
}

#[test]
fn parses_into_profile_group() {
    let cli = parse(&["spt", "profile", "list", "--json"]);
    assert!(matches!(cli.command, Command::Profile(_)));
}

#[test]
fn parses_into_forward_group() {
    let cli = parse(&["spt", "forward", "list"]);
    assert!(matches!(cli.command, Command::Forward(_)));
}

#[test]
fn parses_into_tunnel_group() {
    let cli = parse(&["spt", "tunnel", "status", "--json"]);
    match cli.command {
        Command::Tunnel(groups::tunnel::TunnelCmd {
            command: groups::tunnel::TunnelSub::Status(_),
        }) => {}
        other => panic!("expected tunnel.status, got {other:?}"),
    }
}

#[test]
fn parses_into_service_group() {
    let cli = parse(&[
        "spt",
        "service",
        "render",
        "--config",
        "spt.toml",
        "--system",
    ]);
    assert!(matches!(cli.command, Command::Service(_)));
}

#[test]
fn parses_into_key_group() {
    let cli = parse(&[
        "spt",
        "key",
        "generate",
        "--type",
        "ed25519",
        "--out",
        "id_test",
    ]);
    assert!(matches!(cli.command, Command::Key(_)));
}

#[test]
fn parses_into_secret_group() {
    let cli = parse(&["spt", "secret", "doctor"]);
    assert!(matches!(cli.command, Command::Secret(_)));
}

#[test]
fn parses_into_auth_group() {
    let cli = parse(&["spt", "auth", "test", "edge"]);
    assert!(matches!(cli.command, Command::Auth(_)));
}

#[test]
fn parses_into_dns_group() {
    let cli = parse(&["spt", "dns", "status", "--json"]);
    assert!(matches!(cli.command, Command::Dns(_)));
}

#[test]
fn parses_into_firewall_group() {
    let cli = parse(&["spt", "firewall", "plan"]);
    assert!(matches!(cli.command, Command::Firewall(_)));
}

#[test]
fn parses_into_log_group() {
    let cli = parse(&["spt", "log", "tail", "--since", "1h"]);
    assert!(matches!(cli.command, Command::Log(_)));
}

#[test]
fn parses_into_observe_group() {
    let cli = parse(&["spt", "observe", "metrics", "--format", "prometheus"]);
    assert!(matches!(cli.command, Command::Observe(_)));
}

#[test]
fn parses_into_event_group() {
    let cli = parse(&["spt", "event", "list", "--json"]);
    assert!(matches!(cli.command, Command::Event(_)));
}

#[test]
fn parses_into_stats_group() {
    let cli = parse(&["spt", "stats", "summary", "--json"]);
    assert!(matches!(cli.command, Command::Stats(_)));
}

#[test]
fn parses_into_session_group() {
    let cli = parse(&["spt", "session", "list"]);
    assert!(matches!(cli.command, Command::Session(_)));
}

#[test]
fn parses_into_diagnose_group() {
    let cli = parse(&["spt", "diagnose", "run"]);
    assert!(matches!(cli.command, Command::Diagnose(_)));
}

#[test]
fn parses_into_benchmark_group() {
    let cli = parse(&[
        "spt",
        "benchmark",
        "run",
        "--driver",
        "latency",
        "--count",
        "10",
    ]);
    assert!(matches!(cli.command, Command::Benchmark(_)));
}

#[test]
fn parses_into_mcp_group() {
    let cli = parse(&["spt", "mcp", "inspect", "--json"]);
    assert!(matches!(cli.command, Command::Mcp(_)));
}

#[test]
fn parses_into_completion_group() {
    let cli = parse(&["spt", "completion", "generate", "bash"]);
    assert!(matches!(cli.command, Command::Completion(_)));
}

#[test]
fn global_options_state_dir_propagates() {
    let cli = parse(&[
        "spt",
        "--state-dir",
        "/tmp/spt-test",
        "tunnel",
        "status",
    ]);
    assert_eq!(
        cli.global.state_dir.as_deref(),
        Some(std::path::Path::new("/tmp/spt-test")),
    );
}
