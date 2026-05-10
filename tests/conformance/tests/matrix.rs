//! Server-impl conformance matrix for spt.
//!
//! Iterates `(server, forward_kind, auth_method)` and drives the spt binary
//! against each fixture container brought up by `docker-compose.yml`.
//!
//! ## Gating
//!
//! Every test in this file is `#[ignore]` and additionally short-circuits on
//! `SPT_CONFORMANCE != "1"`. CI opt-in only; local devs run with:
//!
//! ```sh
//! docker compose -f tests/conformance/docker-compose.yml up -d
//! SPT_CONFORMANCE=1 cargo test -p spt-conformance-tests --test matrix -- --ignored
//! ```
//!
//! ## Reporting
//!
//! Every cell is appended to `target/conformance/conformance-matrix.csv`
//! with status `pass | fail | xfail | xpass`. The aggregate test then
//! asserts that:
//!
//! 1. Every documented expected-pass row passed.
//! 2. No expected-fail row unexpectedly passed (`xpass`) — that would mean
//!    the `EXPECTED_FAIL` table is stale and should be updated.
//!
//! ## No assert_cmd
//!
//! Per workspace MSRV constraint, `assert_cmd` is forbidden. We invoke the
//! `spt` binary directly via `tokio::process::Command`. The binary path is
//! resolved by walking up from `CARGO_MANIFEST_DIR` to the workspace root
//! and then into `target/{debug,release}/spt[.exe]`.

#![allow(clippy::missing_docs_in_private_items)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::uninlined_format_args)]

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

// ---------------------------------------------------------------------------
// Matrix axes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Server {
    Openssh,
    Dropbear,
    Libssh,
}

impl Server {
    const fn name(self) -> &'static str {
        match self {
            Self::Openssh => "openssh",
            Self::Dropbear => "dropbear",
            Self::Libssh => "libssh-server",
        }
    }
    const fn port(self) -> u16 {
        match self {
            Self::Openssh => 2231,
            Self::Dropbear => 2232,
            Self::Libssh => 2233,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ForwardKind {
    /// `-L` local→remote
    Local,
    /// `-R` remote→local
    Remote,
    /// `-D` dynamic SOCKS
    Dynamic,
    /// connection-only sanity (no forward); proves auth + transport
    None,
}

impl ForwardKind {
    const fn name(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Remote => "remote",
            Self::Dynamic => "dynamic",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Auth {
    Publickey,
    Password,
}

impl Auth {
    const fn name(self) -> &'static str {
        match self {
            Self::Publickey => "publickey",
            Self::Password => "password",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Cell {
    server: Server,
    forward: ForwardKind,
    auth: Auth,
}

// ---------------------------------------------------------------------------
// Expected-fail table
//
// Each entry is a (server, forward, auth) triple that we *expect* to fail.
// The aggregate matrix test treats:
//   - cell in EXPECTED_FAIL && observed fail  → `xfail`  (recorded, allowed)
//   - cell in EXPECTED_FAIL && observed pass  → `xpass`  (FAIL — table stale)
//   - cell not in table     && observed pass  → `pass`
//   - cell not in table     && observed fail  → `fail`   (FAIL — regression)
// ---------------------------------------------------------------------------

const EXPECTED_FAIL: &[(Server, ForwardKind, Auth)] = &[
    // Many busybox-style Dropbear builds compile out remote-forward (`-R`)
    // entirely: `tcpip-forward` global-request returns SSH_MSG_REQUEST_FAILURE.
    (Server::Dropbear, ForwardKind::Remote, Auth::Publickey),
    (Server::Dropbear, ForwardKind::Remote, Auth::Password),
    // The libssh `ssh_server_fork` example handles direct-tcpip but does
    // NOT implement the `tcpip-forward` global request — confirmed by
    // reading the upstream source. Remote-forward is therefore xfail.
    (Server::Libssh, ForwardKind::Remote, Auth::Publickey),
    (Server::Libssh, ForwardKind::Remote, Auth::Password),
    // Same example also lacks a SOCKS-style direct-tcpip-to-arbitrary-host
    // pathway in a way spt-forward's dynamic mode can drive end-to-end.
    (Server::Libssh, ForwardKind::Dynamic, Auth::Publickey),
    (Server::Libssh, ForwardKind::Dynamic, Auth::Password),
];

fn is_expected_fail(c: Cell) -> bool {
    EXPECTED_FAIL
        .iter()
        .any(|(s, f, a)| *s == c.server && *f == c.forward && *a == c.auth)
}

// ---------------------------------------------------------------------------
// Matrix construction
// ---------------------------------------------------------------------------

fn matrix() -> Vec<Cell> {
    let servers = [Server::Openssh, Server::Dropbear, Server::Libssh];
    let forwards = [
        ForwardKind::None,
        ForwardKind::Local,
        ForwardKind::Remote,
        ForwardKind::Dynamic,
    ];
    let auths = [Auth::Publickey, Auth::Password];

    let mut cells = Vec::with_capacity(servers.len() * forwards.len() * auths.len());
    for s in servers {
        for f in forwards {
            for a in auths {
                cells.push(Cell { server: s, forward: f, auth: a });
            }
        }
    }
    // Sanity: brief mandates ~20 cells. 3×4×2 = 24.
    assert!(cells.len() >= 18 && cells.len() <= 30, "matrix size: {}", cells.len());
    cells
}

// ---------------------------------------------------------------------------
// Result rows
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Pass,
    Fail,
    Xfail,
    Xpass,
}

impl Status {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Xfail => "xfail",
            Self::Xpass => "xpass",
        }
    }
}

struct Row {
    cell: Cell,
    status: Status,
    elapsed_ms: u128,
    detail: String,
}

// ---------------------------------------------------------------------------
// Binary + workspace path resolution
// ---------------------------------------------------------------------------

/// Walk up from this crate's manifest dir until we find the workspace root
/// (the directory holding the root `Cargo.toml` with `[workspace]`).
fn workspace_root() -> PathBuf {
    let mut p: PathBuf = env!("CARGO_MANIFEST_DIR").into();
    // tests/conformance → tests → repo root
    p.pop();
    p.pop();
    p
}

fn spt_binary() -> PathBuf {
    let exe = if cfg!(windows) { "spt.exe" } else { "spt" };
    let root = workspace_root();
    // Prefer release if present (CI builds it once); fall back to debug.
    for profile in ["release", "debug"] {
        let candidate = root.join("target").join(profile).join(exe);
        if candidate.exists() {
            return candidate;
        }
    }
    // Last resort: assume debug (will produce a useful error if absent).
    root.join("target").join("debug").join(exe)
}

fn output_csv() -> PathBuf {
    workspace_root().join("target").join("conformance").join("conformance-matrix.csv")
}

// ---------------------------------------------------------------------------
// Cell driver
// ---------------------------------------------------------------------------

/// Runs one matrix cell: synthesise a one-shot config, invoke `spt config
/// validate` followed by `spt diagnose ssh --once` (both M0 commands that
/// hit the wire and tear down cleanly), and return whether the round-trip
/// succeeded.
///
/// We deliberately avoid `spt tunnel run` here: that command is long-lived
/// and the SIGTERM teardown story is awkward on Windows. The conformance
/// signal we care about is wire interop — which `diagnose ssh --once`
/// fully covers (auth handshake + channel open + optional forward).
async fn run_cell(spt: &Path, cell: Cell) -> (bool, String) {
    let cfg_dir = match tempfile::tempdir() {
        Ok(d) => d,
        Err(e) => return (false, format!("tempdir: {e}")),
    };
    let cfg_path = cfg_dir.path().join("spt.toml");
    if let Err(e) = write_cell_config(&cfg_path, cell) {
        return (false, format!("write config: {e}"));
    }

    // Subcommand depends on the forward kind.
    let mut args: Vec<String> = vec![
        "--config".into(),
        cfg_path.display().to_string(),
        "diagnose".into(),
        "ssh".into(),
        "--once".into(),
        "--profile".into(),
        "matrix".into(),
    ];
    if cell.forward != ForwardKind::None {
        args.push("--forward".into());
        args.push(cell.forward.name().into());
    }

    let mut cmd = Command::new(spt);
    cmd.args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Prevent the binary from talking to the user's real keychain.
        .env("SPT_NO_KEYRING", "1")
        // Steer the diagnose command at the password (when relevant).
        .env("SPT_TEST_PASSWORD", "conformance");

    let child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (false, format!("spawn spt: {e}")),
    };

    // 30 s per cell is generous for a single round-trip handshake.
    let out = match timeout(Duration::from_secs(30), child.wait_with_output()).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return (false, format!("wait: {e}")),
        Err(_) => return (false, "timeout: cell exceeded 30s".into()),
    };

    if out.status.success() {
        (true, String::new())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: String = stderr.lines().rev().take(3).collect::<Vec<_>>().join(" | ");
        (
            false,
            format!("exit={}: {}", out.status.code().unwrap_or(-1), tail),
        )
    }
}

fn write_cell_config(path: &Path, cell: Cell) -> std::io::Result<()> {
    let key_path = workspace_root()
        .join("tests")
        .join("conformance")
        .join("fixtures")
        .join("spt_test_ed25519");
    let auth_block = match cell.auth {
        Auth::Publickey => format!(
            "auth.method = \"publickey\"\nauth.identity_file = \"{}\"\n",
            key_path.display().to_string().replace('\\', "/"),
        ),
        Auth::Password => "auth.method = \"password\"\nauth.password_env = \"SPT_TEST_PASSWORD\"\n".to_string(),
    };

    let forward_block = match cell.forward {
        ForwardKind::None => String::new(),
        ForwardKind::Local => "[[profiles.forwards]]\nkind = \"local\"\nlisten = \"127.0.0.1:0\"\nremote = \"127.0.0.1:80\"\n".into(),
        ForwardKind::Remote => "[[profiles.forwards]]\nkind = \"remote\"\nlisten = \"127.0.0.1:0\"\nremote = \"127.0.0.1:80\"\n".into(),
        ForwardKind::Dynamic => "[[profiles.forwards]]\nkind = \"dynamic\"\nlisten = \"127.0.0.1:0\"\n".into(),
    };

    let body = format!(
        r#"version = 1

[[profiles]]
name = "matrix"
protocol = "ssh2"
host = "127.0.0.1"
port = {port}
user = "spt"
{auth}{fwd}"#,
        port = cell.server.port(),
        auth = auth_block,
        fwd = forward_block,
    );

    let mut f = fs::File::create(path)?;
    f.write_all(body.as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CSV writer
// ---------------------------------------------------------------------------

fn write_csv(rows: &[Row]) -> std::io::Result<()> {
    let path = output_csv();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::File::create(&path)?;
    writeln!(f, "server,forward,auth,status,elapsed_ms,detail")?;
    for r in rows {
        let detail = r.detail.replace([',', '\n', '\r'], " ");
        writeln!(
            f,
            "{},{},{},{},{},{}",
            r.cell.server.name(),
            r.cell.forward.name(),
            r.cell.auth.name(),
            r.status.as_str(),
            r.elapsed_ms,
            detail,
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn gated() -> bool {
    std::env::var("SPT_CONFORMANCE").as_deref() == Ok("1")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "conformance: requires docker compose stack + SPT_CONFORMANCE=1"]
async fn matrix_full() {
    if !gated() {
        eprintln!("SPT_CONFORMANCE != 1 -- skipping conformance matrix");
        return;
    }
    let spt = spt_binary();
    assert!(
        spt.exists(),
        "spt binary not found at {}; build the workspace first (`cargo build`)",
        spt.display(),
    );

    let cells = matrix();
    let mut rows: Vec<Row> = Vec::with_capacity(cells.len());
    let mut unexpected_fails: Vec<Cell> = Vec::new();
    let mut unexpected_passes: Vec<Cell> = Vec::new();

    for cell in cells {
        let started = std::time::Instant::now();
        let (ok, detail) = run_cell(&spt, cell).await;
        let elapsed_ms = started.elapsed().as_millis();
        let xfail = is_expected_fail(cell);
        let status = match (ok, xfail) {
            (true, false) => Status::Pass,
            (true, true) => {
                unexpected_passes.push(cell);
                Status::Xpass
            }
            (false, true) => Status::Xfail,
            (false, false) => {
                unexpected_fails.push(cell);
                Status::Fail
            }
        };
        rows.push(Row { cell, status, elapsed_ms, detail });
    }

    write_csv(&rows).expect("write conformance CSV");

    // Sanity: every triple should be unique in the report.
    let mut seen: BTreeSet<(String, String, String)> = BTreeSet::new();
    for r in &rows {
        let k = (
            r.cell.server.name().to_string(),
            r.cell.forward.name().to_string(),
            r.cell.auth.name().to_string(),
        );
        assert!(seen.insert(k), "duplicate matrix cell in report");
    }

    if !unexpected_fails.is_empty() || !unexpected_passes.is_empty() {
        let csv = output_csv();
        panic!(
            "conformance regressions:\n  unexpected fails: {:?}\n  unexpected passes (stale EXPECTED_FAIL): {:?}\n  full matrix: {}",
            unexpected_fails, unexpected_passes, csv.display(),
        );
    }
}

/// Lightweight smoke test that the matrix definition itself is well-formed.
/// This one is ALSO `#[ignore]`'d to honour the brief's "All tests #[ignore]"
/// rule — but it does not require docker, so it can be unmuted manually
/// (`cargo test -p spt-conformance-tests -- --ignored matrix_shape`) for
/// a quick sanity check during development.
#[tokio::test]
#[ignore = "conformance: structural-only sanity, run with --ignored"]
async fn matrix_shape() {
    let cells = matrix();
    assert!(cells.len() >= 18, "matrix is unexpectedly small: {}", cells.len());
    // Every expected-fail entry must be present in the matrix.
    for (s, f, a) in EXPECTED_FAIL {
        assert!(
            cells.iter().any(|c| c.server == *s && c.forward == *f && c.auth == *a),
            "EXPECTED_FAIL references cell that is not in the matrix: ({:?},{:?},{:?})",
            s, f, a,
        );
    }
    // Make a no-op async use of the runtime to keep tokio happy.
    tokio::time::sleep(Duration::from_millis(1)).await;
}

