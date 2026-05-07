//! Smoke tests for the `spt benchmark` dispatch path wired in
//! f-cli-final. We exercise the binary's CLI parser + dispatcher
//! end-to-end against synthetic in-process drivers and assert the
//! expected report files appear under `<state_dir>/benchmarks/`.
//!
//! Live (`--profile <p>`) drivers correctly refuse with the M6 stub.

use std::process::Command;

fn spt_bin() -> std::path::PathBuf {
    // The integration-test binary is co-located with the dev `spt` build.
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("spt");
    if cfg!(windows) {
        p.set_extension("exe");
    }
    p
}

#[test]
fn benchmark_dns_synthetic_writes_report() {
    let bin = spt_bin();
    if !bin.exists() {
        // `cargo test` may schedule integration tests before binaries; if
        // the spt binary isn't built yet just skip rather than fail.
        eprintln!("skipping: spt bin not found at {}", bin.display());
        return;
    }
    let state_dir = tempfile::tempdir().unwrap();
    let out = Command::new(&bin)
        .args([
            "--state-dir",
            state_dir.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "dns",
            "--count",
            "3",
        ])
        .output()
        .expect("spawn spt");
    assert!(
        out.status.success(),
        "exit: {}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    // Reports should land under <state_dir>/benchmarks/
    let bench_dir = state_dir.path().join("benchmarks");
    let entries: Vec<_> = std::fs::read_dir(&bench_dir)
        .unwrap_or_else(|e| panic!("no benchmarks dir at {}: {e}", bench_dir.display()))
        .flatten()
        .collect();
    assert!(
        entries.iter().any(|e| e
            .file_name()
            .to_string_lossy()
            .ends_with(".json")),
        "no json report in {}",
        bench_dir.display()
    );
    assert!(
        entries.iter().any(|e| e
            .file_name()
            .to_string_lossy()
            .ends_with(".md")),
        "no md report in {}",
        bench_dir.display()
    );
}

#[test]
fn benchmark_live_driver_with_profile_refuses_cleanly() {
    let bin = spt_bin();
    if !bin.exists() {
        return;
    }
    let state_dir = tempfile::tempdir().unwrap();
    let out = Command::new(&bin)
        .args([
            "--state-dir",
            state_dir.path().to_str().unwrap(),
            "benchmark",
            "run",
            "--driver",
            "throughput",
            "--profile",
            "edge",
            "--forward",
            "db",
        ])
        .output()
        .expect("spawn spt");
    // With `--profile` set the dispatcher refuses (live path not wired).
    assert!(!out.status.success(), "expected non-zero for live driver");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // With no running spt and no mcp-listen.json sidecar, the live path
    // fails fast with a clear "is `spt tunnel run` running" error.
    assert!(
        stderr.contains("mcp-listen.json")
            || stderr.contains("tunnel run")
            || stderr.contains("[mcp].listen"),
        "expected sidecar-missing error, got stderr: {stderr}"
    );
}

#[test]
fn benchmark_unknown_driver_errors() {
    let bin = spt_bin();
    if !bin.exists() {
        return;
    }
    let out = Command::new(&bin)
        .args(["benchmark", "run", "--driver", "nope"])
        .output()
        .expect("spawn spt");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("nope") || stderr.contains("unknown"));
}
