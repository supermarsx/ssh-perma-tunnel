//! Integration parse tests for `spt firewall` and `spt log` leaves.
//!
//! These exist primarily to lift coverage of
//! `crates/spt-cli/src/groups/{firewall,log}.rs` from 0% by exercising
//! clap's derive-generated parse machinery.

use clap::Parser;
use spt_cli::{
    Cli, Command,
    groups::firewall::{
        FirewallGateway, FirewallGatewaySub, FirewallPolicy, FirewallPolicyScope,
        FirewallPolicySub, FirewallSub,
    },
    groups::log::{LogExportFormat, LogRemote, LogRemoteSub, LogSub},
};

fn parse_ok(args: &[&str]) -> Cli {
    Cli::try_parse_from(args).unwrap_or_else(|e| panic!("parse failed for {args:?}: {e}"))
}

#[test]
fn firewall_plan_parses() {
    let cli = parse_ok(&["spt", "firewall", "plan"]);
    assert!(matches!(
        cli.command,
        Command::Firewall(ref f) if matches!(f.command, FirewallSub::Plan(_))
    ));
}

#[test]
fn firewall_apply_dry_run_parses() {
    let cli = parse_ok(&["spt", "firewall", "apply", "--system", "--dry-run"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Apply(a) => {
                assert!(a.system);
                assert!(a.dry_run);
            }
            other => panic!("expected Apply, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_remove_parses() {
    let cli = parse_ok(&["spt", "firewall", "remove", "--user"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Remove(a) => assert!(a.user),
            other => panic!("expected Remove, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_status_json_parses() {
    let cli = parse_ok(&["spt", "firewall", "status", "--json"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Status(s) => assert!(s.json),
            other => panic!("expected Status, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_bind_preview_parses() {
    let cli = parse_ok(&["spt", "firewall", "bind-preview", "--forward", "p/f"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::BindPreview(b) => assert_eq!(b.forward, "p/f"),
            other => panic!("expected BindPreview, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_gateway_show_parses() {
    let cli = parse_ok(&["spt", "firewall", "gateway", "show", "--json"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Gateway(FirewallGateway {
                command: FirewallGatewaySub::Show(s),
            }) => assert!(s.json),
            other => panic!("expected Gateway::Show, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_gateway_set_parses() {
    let cli = parse_ok(&[
        "spt",
        "firewall",
        "gateway",
        "set",
        "--default-interface",
        "eth0",
    ]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Gateway(FirewallGateway {
                command: FirewallGatewaySub::Set(s),
            }) => {
                assert_eq!(s.default_interface.as_deref(), Some("eth0"));
            }
            other => panic!("expected Gateway::Set, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_policy_list_parses() {
    let cli = parse_ok(&["spt", "firewall", "policy", "list", "--json"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Policy(FirewallPolicy {
                command: FirewallPolicySub::List(l),
            }) => assert!(l.json),
            other => panic!("expected Policy::List, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_policy_show_parses() {
    let cli = parse_ok(&["spt", "firewall", "policy", "show"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Policy(FirewallPolicy {
                command: FirewallPolicySub::Show(_),
            }) => {}
            other => panic!("expected Policy::Show, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_policy_set_machine_parses() {
    let cli = parse_ok(&[
        "spt", "firewall", "policy", "set", "Net.Default", "Ethernet", "--scope", "machine",
    ]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Policy(FirewallPolicy {
                command: FirewallPolicySub::Set(s),
            }) => {
                assert_eq!(s.key, "Net.Default");
                assert_eq!(s.value, "Ethernet");
                assert_eq!(s.scope, FirewallPolicyScope::Machine);
            }
            other => panic!("expected Policy::Set, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn firewall_policy_unset_parses() {
    let cli = parse_ok(&["spt", "firewall", "policy", "unset", "Net.Default"]);
    match cli.command {
        Command::Firewall(f) => match f.command {
            FirewallSub::Policy(FirewallPolicy {
                command: FirewallPolicySub::Unset(u),
            }) => assert_eq!(u.key, "Net.Default"),
            other => panic!("expected Policy::Unset, got {other:?}"),
        },
        _ => panic!("expected firewall"),
    }
}

#[test]
fn log_tail_parses() {
    let cli = parse_ok(&["spt", "log", "tail", "--follow"]);
    match cli.command {
        Command::Log(l) => match l.command {
            LogSub::Tail(t) => assert!(t.follow),
            other => panic!("expected Tail, got {other:?}"),
        },
        _ => panic!("expected log"),
    }
}

#[test]
fn log_test_parses() {
    let cli = parse_ok(&["spt", "log", "test", "--sink", "ops"]);
    match cli.command {
        Command::Log(l) => match l.command {
            LogSub::Test(t) => assert_eq!(t.sink, "ops"),
            other => panic!("expected Test, got {other:?}"),
        },
        _ => panic!("expected log"),
    }
}

#[test]
fn log_export_parses() {
    let cli = parse_ok(&["spt", "log", "export", "--format", "jsonl", "--since", "1h"]);
    match cli.command {
        Command::Log(l) => match l.command {
            LogSub::Export(e) => {
                assert_eq!(e.format, LogExportFormat::Jsonl);
                assert_eq!(e.since, "1h");
            }
            other => panic!("expected Export, got {other:?}"),
        },
        _ => panic!("expected log"),
    }
}

#[test]
fn log_remote_list_parses() {
    let cli = parse_ok(&["spt", "log", "remote", "list"]);
    match cli.command {
        Command::Log(l) => match l.command {
            LogSub::Remote(LogRemote {
                command: LogRemoteSub::List(_),
            }) => {}
            other => panic!("expected Remote::List, got {other:?}"),
        },
        _ => panic!("expected log"),
    }
}

#[test]
fn log_remote_test_parses() {
    let cli = parse_ok(&[
        "spt",
        "log",
        "remote",
        "test",
        "--sink",
        "syslog",
        "--send-test-record",
    ]);
    match cli.command {
        Command::Log(l) => match l.command {
            LogSub::Remote(LogRemote {
                command: LogRemoteSub::Test(t),
            }) => {
                assert_eq!(t.sink, "syslog");
                assert!(t.send_test_record);
            }
            other => panic!("expected Remote::Test, got {other:?}"),
        },
        _ => panic!("expected log"),
    }
}

#[test]
fn log_remote_status_parses() {
    let cli = parse_ok(&["spt", "log", "remote", "status", "--sink", "ops"]);
    match cli.command {
        Command::Log(l) => match l.command {
            LogSub::Remote(LogRemote {
                command: LogRemoteSub::Status(s),
            }) => assert_eq!(s.sink, "ops"),
            other => panic!("expected Remote::Status, got {other:?}"),
        },
        _ => panic!("expected log"),
    }
}

#[test]
fn log_remote_drain_parses() {
    let cli = parse_ok(&["spt", "log", "remote", "drain", "--sink", "ops", "--json"]);
    match cli.command {
        Command::Log(l) => match l.command {
            LogSub::Remote(LogRemote {
                command: LogRemoteSub::Drain(d),
            }) => {
                assert_eq!(d.sink, "ops");
                assert!(d.json);
            }
            other => panic!("expected Remote::Drain, got {other:?}"),
        },
        _ => panic!("expected log"),
    }
}
