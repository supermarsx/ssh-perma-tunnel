//! Support helpers for the OpenSSH-interop test suite.
//!
//! Tests in `tests/*.rs` use these helpers to:
//!
//! * gate themselves on `SPT_OPENSSH_INTEROP=1` (`gated()`),
//! * locate the pre-built `spt` binary (`spt_bin()`),
//! * spawn `spt tunnel run --foreground` with a hand-written config
//!   (`SpawnedSpt`),
//! * read host-key SHA256 fingerprints from the fixture pubkey files
//!   (`fingerprint_sha256()`),
//! * poll-connect to a TCP port until it answers (`wait_for_port()`),
//! * tear down spawned processes deterministically on drop.
//!
//! No assert_cmd: the project's MSRV (1.83) is incompatible with the
//! current assert_cmd release tree. Everything is plain
//! `tokio::process::Command`.

#![allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::time::{sleep, timeout, Instant};

/// Returns true iff the `SPT_OPENSSH_INTEROP=1` opt-in is present.
///
/// Every `#[test]` body should early-return on `!gated()` so a plain
/// `cargo test --ignored` against a developer machine with no Docker
/// stack still passes (rather than hanging on connect).
#[must_use]
pub fn gated() -> bool {
    std::env::var("SPT_OPENSSH_INTEROP").ok().as_deref() == Some("1")
}

/// Locate the built `spt` binary.
///
/// Resolution order:
///
/// 1. `SPT_BIN` env var (CI sets this after `cargo build -p spt-bin --release`).
/// 2. `<workspace_root>/target/release/spt[.exe]`
/// 3. `<workspace_root>/target/debug/spt[.exe]`
///
/// Walks up from `CARGO_MANIFEST_DIR` until it finds a `target/` directory.
/// Returns an error (rather than panicking) so callers can surface a clear
/// failure when the binary genuinely isn't built.
pub fn spt_bin() -> Result<PathBuf> {
    if let Ok(p) = std::env::var("SPT_BIN") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Ok(path);
        }
        bail!(
            "SPT_BIN set to `{}` but the file does not exist",
            path.display()
        );
    }

    let exe = if cfg!(windows) { "spt.exe" } else { "spt" };
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Walk up looking for a `target/` sibling.
    for ancestor in manifest.ancestors() {
        let target = ancestor.join("target");
        if target.is_dir() {
            for profile in ["release", "debug"] {
                let candidate = target.join(profile).join(exe);
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    bail!(
        "could not locate the `spt` binary; set SPT_BIN or run \
         `cargo build -p spt-bin --release` from the workspace root"
    );
}

/// Path to the `tests/openssh-interop/fixtures/` directory.
///
/// Relative to `CARGO_MANIFEST_DIR`, which Cargo always sets when running
/// tests for this crate.
#[must_use]
pub fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Client key fixture that works with the default SSH2 backend on this OS.
///
/// Windows libssh2/WinCNG builds do not expose in-memory ED25519 key auth
/// through the Rust wrapper, so default Windows interop uses the RSA fixture.
/// Unix/OpenSSL builds keep the ED25519 coverage.
#[must_use]
pub fn default_client_key() -> PathBuf {
    fixtures_dir().join("keys").join(if cfg!(windows) {
        "test_rsa"
    } else {
        "test_ed25519"
    })
}

/// Host address reachable from inside the OpenSSH interop containers.
#[must_use]
pub fn host_gateway() -> String {
    std::env::var("SPT_HOST_GATEWAY").unwrap_or_else(|_| "host.docker.internal".to_string())
}

/// Read a host-key public file and compute the SHA256 fingerprint in the
/// `SHA256:base64nopadding` form that `spt`'s pinning logic expects.
///
/// Implementation detail: shells out to `ssh-keygen -lf <path>`, which is
/// always available on the CI runner because Docker / openssh-server
/// require it. Parses the second whitespace-separated field of the output:
///
/// ```text
/// 256 SHA256:abc...== comment (ED25519)
/// ```
pub async fn fingerprint_sha256(pubkey_path: &Path) -> Result<String> {
    let output = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(pubkey_path)
        .output()
        .await
        .with_context(|| format!("ssh-keygen -lf {}", pubkey_path.display()))?;
    if !output.status.success() {
        bail!(
            "ssh-keygen -lf {} failed: stdout={} stderr={}",
            pubkey_path.display(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    let line = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 2 || !parts[1].starts_with("SHA256:") {
        bail!("ssh-keygen -lf produced unexpected output: `{line}`");
    }
    Ok(parts[1].to_string())
}

/// Wait until `addr` accepts a TCP connection, or `deadline` elapses.
///
/// Polls every 100 ms. Used both to wait for the docker sshd ports to
/// come up and to wait for `spt`'s forward listener to bind.
pub async fn wait_for_port(addr: SocketAddr, deadline: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        match timeout(Duration::from_millis(500), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return Ok(()),
            _ => {
                if start.elapsed() >= deadline {
                    bail!(
                        "timed out after {:?} waiting for {addr} to accept TCP",
                        deadline
                    );
                }
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

/// One side of an in-process echo server we spin up to act as the *target*
/// of a local-forward (or the *source* of a remote-forward).
///
/// Spawns a tokio task that accepts a single connection, reads bytes, and
/// echoes them straight back. Returns the bound `SocketAddr`. The task
/// lives until the test process exits — for a roundtrip-once test that is
/// the simplest thing that works.
pub async fn spawn_echo_server() -> Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(p) => p,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if sock.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

/// Open a TCP connection, send `payload`, read exactly `payload.len()`
/// bytes back, assert byte-for-byte equality. The "1 MiB roundtrip" used
/// by the forward tests.
pub async fn roundtrip(addr: SocketAddr, payload: &[u8]) -> Result<()> {
    let mut s = TcpStream::connect(addr).await?;
    // Concurrent write + read so kernel send/recv buffers don't deadlock
    // for payload sizes larger than a single buffer.
    let payload_owned = payload.to_vec();
    let (mut r, mut w) = s.split();
    let writer = async {
        w.write_all(&payload_owned).await?;
        w.shutdown().await?;
        anyhow::Ok(())
    };
    let mut received = Vec::with_capacity(payload.len());
    let reader = async {
        r.read_to_end(&mut received).await?;
        anyhow::Ok(())
    };
    tokio::try_join!(writer, reader)?;
    if received.len() != payload.len() {
        bail!(
            "roundtrip length mismatch: sent {}, got {}",
            payload.len(),
            received.len()
        );
    }
    if received != payload {
        bail!(
            "roundtrip payload mismatch (lengths matched at {})",
            payload.len()
        );
    }
    Ok(())
}

/// A guarded `spt tunnel run --foreground` child process plus its
/// supporting tempdir (config + state).
///
/// `Drop` kills the child eagerly via `Child::start_kill` — we also set
/// `kill_on_drop(true)` on the `Command` for belt-and-suspenders.
pub struct SpawnedSpt {
    /// The `tokio::process::Child`. `Option` so `shutdown()` can take it.
    child: Option<Child>,
    /// Tempdir holding `config.toml` + `state/`. Kept alive for the
    /// lifetime of the child; `Drop` order is `child` → `_tmp` so the
    /// child sees its config until the very end.
    _tmp: TempDir,
    /// Path to the rendered config (handy for diagnostics).
    pub config_path: PathBuf,
    /// Path to the `state_dir` inside the tempdir.
    pub state_dir: PathBuf,
}

impl SpawnedSpt {
    /// Spawn `spt tunnel run --foreground --config <config>`.
    ///
    /// Stdout + stderr inherit so failures surface in the test log; if
    /// you need to assert on stderr content, prefer running `spt` once
    /// in non-daemon mode (e.g. `spt config validate`) via [`run_once`].
    pub async fn spawn_tunnel_run(config_body: &str) -> Result<Self> {
        let bin = spt_bin()?;
        let tmp = tempfile::tempdir().context("tempdir")?;
        let state_dir = tmp.path().join("state");
        std::fs::create_dir_all(&state_dir)?;

        // Substitute `${STATE_DIR}` so callers can keep their config
        // template path-free.
        let body = config_body.replace(
            "${STATE_DIR}",
            // TOML strings on Windows need forward slashes or escaped
            // backslashes; forward slashes work on both platforms.
            &state_dir.to_string_lossy().replace('\\', "/"),
        );
        let config_path = tmp.path().join("spt.toml");
        std::fs::write(&config_path, body)?;

        let mut cmd = Command::new(&bin);
        cmd.arg("--config")
            .arg(&config_path)
            .arg("tunnel")
            .arg("run")
            .arg("--foreground")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true);

        let child = cmd
            .spawn()
            .with_context(|| format!("spawn {} tunnel run", bin.display()))?;

        Ok(Self {
            child: Some(child),
            _tmp: tmp,
            config_path,
            state_dir,
        })
    }

    /// Best-effort shutdown: send SIGKILL (or TerminateProcess on Windows)
    /// and reap. Idempotent; safe to call from `Drop`.
    pub async fn shutdown(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.start_kill();
            let _ = timeout(Duration::from_secs(5), c.wait()).await;
        }
    }
}

impl Drop for SpawnedSpt {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            // We're in sync Drop; can't await. start_kill + non-blocking
            // try_wait is the most we can do. `kill_on_drop(true)` on
            // the Command provides the actual cleanup guarantee from
            // tokio's side.
            let _ = c.start_kill();
        }
    }
}

/// Run `spt <args>` once with the given config and return
/// `(status, stdout, stderr)`. For commands that exit on their own
/// (validate, config, --help, etc.) — *not* for `tunnel run`.
pub async fn run_once(config_path: Option<&Path>, args: &[&str]) -> Result<RunOutput> {
    let bin = spt_bin()?;
    let mut cmd = Command::new(&bin);
    if let Some(p) = config_path {
        cmd.arg("--config").arg(p);
    }
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let out = cmd
        .output()
        .await
        .with_context(|| format!("run {} {}", bin.display(), args.join(" ")))?;
    Ok(RunOutput {
        status: out.status.code(),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    })
}

/// Captured output of a single `spt` invocation.
#[derive(Debug, Clone)]
pub struct RunOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}
