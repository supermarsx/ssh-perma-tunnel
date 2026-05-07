//! Process-runner abstraction for service-manager backends.
//!
//! Most service-manager backends (`launchctl`, `schtasks`, `service`,
//! `rc-service`, ...) work by shelling out to a canonical OS CLI. To keep
//! tests hermetic this module exposes a [`CommandRunner`] trait with two
//! implementations:
//!
//! * [`TokioRunner`] — production: spawns `tokio::process::Command`,
//!   races against a per-call timeout, captures stdout/stderr lossily as
//!   UTF-8.
//! * [`MockRunner`] — tests: records every call and returns canned
//!   [`RunOutput`] values from a FIFO queue.
//!
//! Backends take an `Arc<dyn CommandRunner>` so a test can substitute the
//! mock and assert on exact argument lists without touching the real OS.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use spt_core::error::{Error, Result};

/// Captured outcome of a single command invocation.
///
/// A non-zero `status` is **not** itself an error — many CLIs use exit
/// codes as semantic signals (e.g. `systemctl is-active` returns 3 for
/// "inactive"). Each backend interprets `status` in context.
#[derive(Debug, Clone)]
pub struct RunOutput {
    /// Process exit code. -1 if the child was killed by a signal or
    /// otherwise terminated without an exit code (Unix only).
    pub status: i32,
    /// Captured standard output, decoded lossily as UTF-8.
    pub stdout: String,
    /// Captured standard error, decoded lossily as UTF-8.
    pub stderr: String,
}

impl RunOutput {
    /// Returns `true` iff the process exited with status 0.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// Run a child process and return its captured output.
///
/// Implementations MUST honour `timeout`: if the child has not exited
/// within the budget, the implementation kills it and returns
/// [`Error::ServiceManagerFailed`] tagged with the program name and
/// elapsed timeout.
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync + std::fmt::Debug {
    /// Spawn `prog` with `args`, wait up to `timeout`, and return the
    /// captured output (stdout/stderr/status).
    async fn run(&self, prog: &str, args: &[&str], timeout: Duration) -> Result<RunOutput>;
}

/// Production [`CommandRunner`] backed by `tokio::process::Command`.
#[derive(Debug, Default, Clone, Copy)]
pub struct TokioRunner;

impl TokioRunner {
    /// Construct a new runner. Equivalent to `TokioRunner::default()`.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl CommandRunner for TokioRunner {
    async fn run(&self, prog: &str, args: &[&str], timeout: Duration) -> Result<RunOutput> {
        use std::process::Stdio;
        use tokio::process::Command;

        let mut cmd = Command::new(prog);
        cmd.args(args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());
        cmd.kill_on_drop(true);

        let child = cmd
            .spawn()
            .map_err(|e| Error::ServiceManagerFailed(format!("failed to spawn {prog}: {e}")))?;

        let wait_fut = child.wait_with_output();
        match tokio::time::timeout(timeout, wait_fut).await {
            Ok(Ok(output)) => {
                let status = output.status.code().unwrap_or(-1);
                let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                Ok(RunOutput {
                    status,
                    stdout,
                    stderr,
                })
            }
            Ok(Err(e)) => Err(Error::ServiceManagerFailed(format!(
                "failed to wait on {prog}: {e}"
            ))),
            Err(_elapsed) => {
                // tokio::process::Child::wait_with_output consumed the child;
                // kill_on_drop above ensures the OS process is reaped when
                // the future is dropped.
                Err(Error::ServiceManagerFailed(format!(
                    "{prog} timed out after {}s",
                    timeout.as_secs_f32()
                )))
            }
        }
    }
}

/// In-memory [`CommandRunner`] for hermetic tests.
///
/// Records every call (program + args) and returns canned
/// [`RunOutput`]s in FIFO order. If a test calls [`MockRunner::run`]
/// without first having pushed an output, the call panics — that
/// indicates a missing test fixture.
#[derive(Debug, Default, Clone)]
pub struct MockRunner {
    inner: Arc<Mutex<MockState>>,
}

#[derive(Debug, Default)]
struct MockState {
    /// Calls received, in order: (program, args).
    calls: Vec<(String, Vec<String>)>,
    /// FIFO queue of canned outputs to return.
    canned: VecDeque<RunOutput>,
}

impl MockRunner {
    /// Construct a new mock with no recorded calls and no canned outputs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a canned [`RunOutput`] onto the FIFO queue. The next
    /// [`MockRunner::run`] call returns this output.
    pub fn push_output(&self, out: RunOutput) {
        self.inner.lock().canned.push_back(out);
    }

    /// Snapshot of all calls observed so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<(String, Vec<String>)> {
        self.inner.lock().calls.clone()
    }

    /// The most recently observed call, or `None` if nothing has run.
    #[must_use]
    pub fn last_call(&self) -> Option<(String, Vec<String>)> {
        self.inner.lock().calls.last().cloned()
    }

    /// Assert that *some* recorded call matches `prog` + `args` exactly.
    /// Panics with a diagnostic message otherwise.
    pub fn assert_called(&self, prog: &str, args: &[&str]) {
        let want_args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let calls = self.inner.lock().calls.clone();
        let hit = calls
            .iter()
            .any(|(p, a)| p == prog && a.as_slice() == want_args.as_slice());
        assert!(
            hit,
            "expected call to {prog:?} with args {want_args:?}, observed: {calls:?}"
        );
    }
}

#[async_trait::async_trait]
impl CommandRunner for MockRunner {
    async fn run(&self, prog: &str, args: &[&str], _timeout: Duration) -> Result<RunOutput> {
        let owned_args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
        let mut state = self.inner.lock();
        state.calls.push((prog.to_string(), owned_args));
        let out = state.canned.pop_front().unwrap_or_else(|| {
            panic!(
                "MockRunner: no canned output queued for call to {prog:?} (args {args:?}); \
                 push_output() before run()"
            )
        });
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tokio_runner_captures_stdout_for_rustc_version() {
        let runner = TokioRunner::new();
        let out = runner
            .run("rustc", &["--version"], Duration::from_secs(30))
            .await
            .expect("rustc --version must succeed in a Rust toolchain");
        assert_eq!(out.status, 0, "rustc --version exit status");
        assert!(out.ok());
        assert!(
            out.stdout.contains("rustc"),
            "stdout should contain `rustc`, got: {:?}",
            out.stdout
        );
    }

    #[tokio::test]
    async fn tokio_runner_returns_nonzero_status_without_error() {
        let runner = TokioRunner::new();
        // `rustc` with a nonexistent flag exits non-zero but does not
        // fail to spawn — runner returns Ok with the status.
        let out = runner
            .run(
                "rustc",
                &["--this-flag-does-not-exist-xyz"],
                Duration::from_secs(30),
            )
            .await
            .expect("spawn should succeed even if rustc rejects args");
        assert_ne!(out.status, 0);
        assert!(!out.ok());
    }

    #[tokio::test]
    async fn tokio_runner_errors_when_program_missing() {
        let runner = TokioRunner::new();
        let err = runner
            .run(
                "spt-definitely-not-a-real-binary-7d8b2c",
                &[],
                Duration::from_secs(5),
            )
            .await
            .expect_err("missing binary should produce a spawn error");
        let msg = format!("{err}");
        assert!(
            msg.contains("failed to spawn"),
            "error should mention spawn failure, got: {msg}"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn tokio_runner_honors_timeout_unix() {
        let runner = TokioRunner::new();
        let start = std::time::Instant::now();
        let err = runner
            .run("sleep", &["5"], Duration::from_millis(100))
            .await
            .expect_err("100ms timeout against `sleep 5` must fire");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "timeout should fire fast, took {elapsed:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("timed out"), "got: {msg}");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn tokio_runner_honors_timeout_windows() {
        let runner = TokioRunner::new();
        let start = std::time::Instant::now();
        // `ping -n 6 127.0.0.1` takes ~5s; portable on every Windows.
        let err = runner
            .run(
                "ping",
                &["-n", "6", "127.0.0.1"],
                Duration::from_millis(100),
            )
            .await
            .expect_err("100ms timeout against multi-second `ping` must fire");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "timeout should fire fast, took {elapsed:?}"
        );
        let msg = format!("{err}");
        assert!(msg.contains("timed out"), "got: {msg}");
    }

    #[tokio::test]
    async fn mock_runner_round_trip() {
        let mock = MockRunner::new();
        mock.push_output(RunOutput {
            status: 0,
            stdout: "hello\n".into(),
            stderr: String::new(),
        });
        let out = mock
            .run("svc", &["status", "foo"], Duration::from_secs(1))
            .await
            .expect("mock run");
        assert_eq!(out.status, 0);
        assert_eq!(out.stdout, "hello\n");
        mock.assert_called("svc", &["status", "foo"]);
        let last = mock.last_call().expect("one call recorded");
        assert_eq!(last.0, "svc");
        assert_eq!(last.1, vec!["status".to_string(), "foo".to_string()]);
        assert_eq!(mock.calls().len(), 1);
    }

    #[tokio::test]
    async fn mock_runner_fifo_order() {
        let mock = MockRunner::new();
        mock.push_output(RunOutput {
            status: 0,
            stdout: "first".into(),
            stderr: String::new(),
        });
        mock.push_output(RunOutput {
            status: 1,
            stdout: "second".into(),
            stderr: "boom".into(),
        });
        let a = mock.run("a", &[], Duration::from_secs(1)).await.unwrap();
        let b = mock.run("b", &[], Duration::from_secs(1)).await.unwrap();
        assert_eq!(a.stdout, "first");
        assert_eq!(b.stdout, "second");
        assert_eq!(b.status, 1);
    }

    #[tokio::test]
    #[should_panic(expected = "no canned output")]
    async fn mock_runner_panics_without_canned_output() {
        let mock = MockRunner::new();
        let _ = mock.run("nope", &[], Duration::from_secs(1)).await;
    }
}
