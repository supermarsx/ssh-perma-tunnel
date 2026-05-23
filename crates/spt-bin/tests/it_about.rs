//! Integration tests for `spt about` (t10).
//!
//! All tests drive the compiled `spt` binary via subprocess. The build-time
//! `about_data.rs` static slice is exercised through every subcommand. Plus
//! a handful of CLI-parse tests against `spt-cli` directly.

use std::process::Command;

use spt_cli::{Cli, Command as CliCommand};

fn spt_bin() -> Command {
    let path = env!("CARGO_BIN_EXE_spt");
    Command::new(path)
}

// ---------------------------------------------------------------------------
// CLI parser tests (no subprocess).
// ---------------------------------------------------------------------------

#[test]
fn cli_about_no_subcommand_parses_as_overview() {
    use clap::Parser;
    let cli = Cli::try_parse_from(["spt", "about"]).expect("parse");
    match cli.command {
        CliCommand::About(c) => assert!(c.command.is_none()),
        other => panic!("expected About, got {other:?}"),
    }
}

#[test]
fn cli_about_list_with_format_json_parses() {
    use clap::Parser;
    let cli = Cli::try_parse_from(["spt", "about", "list", "--format", "json"]).expect("parse");
    match cli.command {
        CliCommand::About(c) => match c.command {
            Some(spt_cli::groups::about::AboutSub::List(args)) => {
                assert!(matches!(
                    args.format,
                    spt_cli::groups::about::AboutOutputFormat::Json
                ));
            }
            other => panic!("expected List, got {other:?}"),
        },
        other => panic!("expected About, got {other:?}"),
    }
}

#[test]
fn cli_about_show_requires_name() {
    use clap::Parser;
    let err = Cli::try_parse_from(["spt", "about", "show"]).unwrap_err();
    assert_eq!(err.kind(), clap::error::ErrorKind::MissingRequiredArgument);
}

#[test]
fn cli_about_export_takes_path() {
    use clap::Parser;
    let cli = Cli::try_parse_from(["spt", "about", "export", "out.md"]).expect("parse");
    match cli.command {
        CliCommand::About(c) => match c.command {
            Some(spt_cli::groups::about::AboutSub::Export(args)) => {
                assert_eq!(args.path.to_string_lossy(), "out.md");
            }
            other => panic!("expected Export, got {other:?}"),
        },
        _ => panic!("expected About"),
    }
}

// ---------------------------------------------------------------------------
// Subprocess smoke tests (exercise the dispatcher + ops + embedded data).
// ---------------------------------------------------------------------------

#[test]
fn about_overview_lists_workspace_info() {
    let out = spt_bin().arg("about").output().expect("spawn spt about");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("utf8");
    assert!(
        stdout.contains("spt-bin"),
        "overview should mention spt-bin"
    );
    assert!(
        stdout.contains("Bundled libraries"),
        "overview should announce bundled libraries section"
    );
}

#[test]
fn about_list_text_format_emits_one_line_per_crate() {
    let out = spt_bin().args(["about", "list"]).output().expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    // First line is the header, then one line per dep.
    let lines = stdout.lines().count();
    assert!(lines > 100, "expected many lines, got {lines}");
    // Spot-check a well-known crate.
    assert!(stdout.contains("clap"), "expected clap in listing");
}

#[test]
fn about_list_json_format_is_valid_json() {
    let out = spt_bin()
        .args(["about", "list", "--format", "json"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let parsed: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("output must be valid JSON");
    let arr = parsed.as_array().expect("JSON must be an array");
    assert!(arr.len() > 50, "want >50 entries, got {}", arr.len());
    let first = &arr[0];
    assert!(first.get("name").is_some());
    assert!(first.get("version").is_some());
    assert!(first.get("license").is_some());
    assert!(first.get("source").is_some());
}

#[test]
fn about_list_filter_by_license_narrows_results() {
    let unfiltered = run_count(&["about", "list"]);
    let filtered = run_count(&["about", "list", "--license", "MIT"]);
    let nope = run_count(&["about", "list", "--license", "ZZZZ-NOT-A-LICENSE"]);
    assert!(
        filtered > 0 && filtered <= unfiltered,
        "{filtered} vs {unfiltered}"
    );
    // The header line still appears; "Bundled libraries (0)" is the floor.
    assert!(
        nope <= 2,
        "ZZZZ-filter should produce only the header, got {nope} lines"
    );
}

fn run_count(args: &[&str]) -> usize {
    let out = spt_bin().args(args).output().expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().lines().count()
}

#[test]
fn about_show_unknown_crate_returns_error() {
    let out = spt_bin()
        .args(["about", "show", "this-crate-does-not-exist-xyzzy"])
        .output()
        .expect("spawn");
    assert!(!out.status.success(), "expected nonzero exit");
}

#[test]
fn about_show_known_crate_prints_details() {
    let out = spt_bin()
        .args(["about", "show", "clap"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("name:"));
    assert!(stdout.contains("version:"));
    assert!(stdout.contains("clap"));
}

#[test]
fn about_licenses_groups_by_spdx() {
    let out = spt_bin()
        .args(["about", "licenses"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("License distribution:"));
    assert!(stdout.contains("MIT"));
}

#[test]
fn about_export_md_writes_attribution_file() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("attribution.md");
    let out = spt_bin()
        .args(["about", "export"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(&path).expect("file written");
    assert!(body.starts_with("# Bundled libraries"));
    assert!(body.contains("clap"));
}

#[test]
fn about_export_json_extension_writes_valid_json() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("attribution.json");
    let out = spt_bin()
        .args(["about", "export"])
        .arg(&path)
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let body = std::fs::read_to_string(&path).unwrap();
    let _: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
}

#[test]
fn about_data_includes_vendor_forks_via_show() {
    let out = spt_bin()
        .args(["about", "show", "russh"])
        .output()
        .expect("spawn");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        stdout.contains("vendor") && stdout.contains("locally patched"),
        "russh should be flagged as a vendor fork: {stdout}"
    );
}
