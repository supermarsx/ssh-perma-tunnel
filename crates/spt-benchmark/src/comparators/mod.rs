//! Comparative benchmark harness — drives `spt`, `OpenSSH`, and `autossh`
//! through the same load profile so spec §13.13 can publish a side-by-side
//! perf baseline.
//!
//! # Design
//!
//! A [`Comparator`] is an async trait abstracting "an SSH client that can set
//! up a local→remote TCP forward, push load through it, and rebuild itself
//! after a forced reconnect". The matrix runner ([`drive_one_cell`]) walks
//! every implementation through the same four-phase lifecycle:
//!
//! 1. [`Comparator::setup`] — spawn the client subprocess (or driver task)
//!    and wait until the local forward port is connectable.
//! 2. [`Comparator::measure_throughput`] — push `bytes` through the forward,
//!    sample round-trip latency, return a [`ThroughputSample`].
//! 3. [`Comparator::measure_reconnect_cost`] — interrupt the session and
//!    time the recovery.
//! 4. [`Comparator::shutdown`] — tear the subprocess down, capture stderr.
//!
//! # Context vs. `BenchContext`
//!
//! Note that the existing [`crate::driver::BenchContext`] is a *driver*
//! context (iterations, payload size, [`crate::driver::Connector`]). The
//! comparator harness needs a different shape — it owns the subprocess and
//! the chaos-proxy upstream — so we ship [`ComparatorContext`] alongside
//! rather than shadow the existing name.
//!
//! # Binary discovery
//!
//! Both [`openssh::OpenSshClient`] and [`autossh::AutosshClient`] need to
//! resolve their binary on `PATH`. Rather than add the `which` crate (which
//! is not currently in `Cargo.lock`), we ship [`locate_binary`] — a small
//! `std`-only PATH scan that honours platform exe suffixes.

use async_trait::async_trait;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

pub mod autossh;
pub mod openssh;

pub use autossh::AutosshClient;
pub use openssh::OpenSshClient;

/// Per-cell context handed to every [`Comparator`].
///
/// The matrix runner owns the chaos proxy and the destination forward; each
/// comparator only sees the *effective* endpoints it needs to dial.
#[derive(Debug, Clone)]
pub struct ComparatorContext {
    /// SSH endpoint the comparator should connect to. In the matrix runner
    /// this is the local bind of the chaos proxy, which forwards to the
    /// real SSH server, applying [`LatencyMs`] / [`LossPct`] in between.
    ///
    /// [`LatencyMs`]: spt_chaos_proxy::ChaosBehaviour::LatencyMs
    /// [`LossPct`]: spt_chaos_proxy::ChaosBehaviour::LossPct
    pub upstream_addr: SocketAddr,
    /// `127.0.0.1:0` style address the client should bind for the local
    /// half of the `-L` forward. Port 0 means "let the OS pick".
    pub forward_local: SocketAddr,
    /// Remote `host:port` the client should map the local forward to.
    pub forward_remote: SocketAddr,
    /// Directory the comparator may write logs / pid files into.
    pub log_dir: PathBuf,
    /// SSH user to authenticate as (informational; comparators may ignore
    /// when running against a stub server that accepts everything).
    pub ssh_user: String,
    /// Optional explicit binary override. When set, replaces PATH discovery
    /// — primarily a test seam so unit tests can force a "missing binary"
    /// fallback by passing a deliberately bogus path.
    pub binary_override: Option<PathBuf>,
}

impl ComparatorContext {
    /// Construct a context targeting `upstream` with a free OS-chosen
    /// forward port, `ssh_user = "spt"`, no binary override.
    #[must_use]
    pub fn for_upstream(
        upstream: SocketAddr,
        forward_remote: SocketAddr,
        log_dir: PathBuf,
    ) -> Self {
        Self {
            upstream_addr: upstream,
            forward_local: "127.0.0.1:0".parse().expect("hard-coded literal"),
            forward_remote,
            log_dir,
            ssh_user: "spt".into(),
            binary_override: None,
        }
    }
}

/// A single throughput observation produced by [`Comparator::measure_throughput`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThroughputSample {
    /// Bytes pushed end-to-end (sum of write + readback if applicable).
    pub bytes: usize,
    /// Wall-clock duration of the push.
    pub elapsed: Duration,
    /// P50 single-chunk round-trip in microseconds.
    pub p50_latency_us: u64,
    /// P99 single-chunk round-trip in microseconds.
    pub p99_latency_us: u64,
}

impl ThroughputSample {
    /// Bytes-per-second derived from `bytes` / `elapsed`.
    #[must_use]
    pub fn throughput_bps(&self) -> f64 {
        let secs = self.elapsed.as_secs_f64().max(0.000_001);
        self.bytes as f64 / secs
    }
}

/// Errors produced by a [`Comparator`].
#[derive(Debug, thiserror::Error)]
pub enum ComparatorError {
    /// The comparator's underlying binary (`ssh`, `autossh`) is not on
    /// `PATH`. The matrix runner treats this as a *soft* failure: the cell
    /// is recorded with `skipped = true` and the run continues.
    #[error("binary not installed: {0}")]
    NotInstalled(String),
    /// Subprocess spawn / wait failed.
    #[error("subprocess: {0}")]
    Subprocess(String),
    /// Setup (port-bind, handshake) failed within the timeout.
    #[error("setup: {0}")]
    Setup(String),
    /// I/O over the forward failed mid-measurement.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Generic catch-all for backend-specific failures.
    #[error("{0}")]
    Other(String),
}

/// Result alias for comparator operations.
pub type ComparatorResult<T> = std::result::Result<T, ComparatorError>;

/// Abstraction over "an SSH client that maintains a single TCP forward".
///
/// Object-safe: the matrix runner stores comparators as `Box<dyn Comparator>`
/// so the same loop can drive heterogeneous backends. `shutdown` takes
/// `self: Box<Self>` (not `self`) to keep the trait dyn-compatible while
/// still consuming the value.
#[async_trait]
pub trait Comparator: Send {
    /// Stable kebab-case identifier (`spt`, `openssh`, `autossh`). Used as
    /// the cell-key prefix in the matrix runner output.
    fn name(&self) -> &'static str;

    /// Spawn the client and block until the local forward is reachable.
    ///
    /// On `Err(ComparatorError::NotInstalled)`, the matrix runner records
    /// the cell as skipped and continues — see [`drive_one_cell`].
    async fn setup(&mut self, ctx: &ComparatorContext) -> ComparatorResult<()>;

    /// Push `bytes` through the forward and return a single sample.
    async fn measure_throughput(&mut self, bytes: usize) -> ComparatorResult<ThroughputSample>;

    /// Disrupt the session and measure how long the client takes to make
    /// the forward usable again.
    async fn measure_reconnect_cost(&mut self) -> ComparatorResult<Duration>;

    /// Tear the subprocess down. Consumes the value to enforce a single
    /// shutdown call. `Box<Self>` rather than `self` so the trait remains
    /// object-safe.
    async fn shutdown(self: Box<Self>) -> ComparatorResult<()>;
}

/// One cell of the comparative matrix.
#[derive(Debug, Clone)]
pub struct CellOutcome {
    /// Comparator that produced this cell (e.g. `"openssh"`).
    pub tool: String,
    /// Latency injected at the chaos proxy, in milliseconds.
    pub latency_ms: u64,
    /// Loss injected at the chaos proxy, in percent.
    pub loss_pct: u8,
    /// `idle` or `saturated`.
    pub load: String,
    /// `true` when the comparator was unavailable (e.g. binary missing);
    /// `throughput` and `reconnect_cost` will be `None`.
    pub skipped: bool,
    /// Free-form reason when `skipped` or errored.
    pub skip_reason: Option<String>,
    /// Throughput sample, when reached.
    pub throughput_bps: Option<f64>,
    /// p50 single-chunk round-trip in microseconds.
    pub p50_us: Option<u64>,
    /// p99 single-chunk round-trip in microseconds.
    pub p99_us: Option<u64>,
    /// Reconnect cost in milliseconds, when reached.
    pub reconnect_ms: Option<u64>,
    /// Extra scalars (peak RSS, retries, etc.) for downstream renderers.
    pub extras: BTreeMap<String, f64>,
}

impl CellOutcome {
    /// Skeleton outcome (everything `None`, `skipped = false`).
    #[must_use]
    pub fn new(tool: &str, latency_ms: u64, loss_pct: u8, load: &str) -> Self {
        Self {
            tool: tool.into(),
            latency_ms,
            loss_pct,
            load: load.into(),
            skipped: false,
            skip_reason: None,
            throughput_bps: None,
            p50_us: None,
            p99_us: None,
            reconnect_ms: None,
            extras: BTreeMap::new(),
        }
    }

    /// Convert to a serialisable JSON value (intentionally not using serde
    /// derives on this struct — keeps the schema decoupled from the
    /// in-memory shape so the C4 dashboard can evolve independently).
    #[must_use]
    pub fn to_json(&self) -> serde_json::Value {
        let mut extras = serde_json::Map::new();
        for (k, v) in &self.extras {
            extras.insert(k.clone(), serde_json::json!(v));
        }
        serde_json::json!({
            "tool":           self.tool,
            "latency_ms":     self.latency_ms,
            "loss_pct":       self.loss_pct,
            "load":           self.load,
            "skipped":        self.skipped,
            "skip_reason":    self.skip_reason,
            "throughput_bps": self.throughput_bps,
            "p50_us":         self.p50_us,
            "p99_us":         self.p99_us,
            "reconnect_ms":   self.reconnect_ms,
            "extras":         serde_json::Value::Object(extras),
        })
    }
}

/// Cell-level knobs passed to [`drive_one_cell`].
#[derive(Debug, Clone)]
pub struct CellPlan {
    /// Comparator label (recorded in [`CellOutcome::tool`]).
    pub tool: String,
    /// Injected latency, used by callers for bookkeeping; the actual chaos
    /// proxy is configured by the caller before invoking `drive_one_cell`.
    pub latency_ms: u64,
    /// Injected loss percent (0..=100).
    pub loss_pct: u8,
    /// `idle` or `saturated` — saturated cells push more bytes.
    pub load: String,
    /// Bytes to push through the forward in [`Comparator::measure_throughput`].
    pub throughput_bytes: usize,
}

impl CellPlan {
    /// Convenience constructor with default byte budgets per load level.
    /// Idle cells push 64 KiB; saturated cells push 4 MiB.
    #[must_use]
    pub fn from_axes(tool: &str, latency_ms: u64, loss_pct: u8, load: &str) -> Self {
        let throughput_bytes = if load == "saturated" {
            4 * 1024 * 1024
        } else {
            64 * 1024
        };
        Self {
            tool: tool.into(),
            latency_ms,
            loss_pct,
            load: load.into(),
            throughput_bytes,
        }
    }
}

/// Drive `comparator` through the full lifecycle for one matrix cell.
///
/// This is the single source of truth for the cell sequence — both the
/// `matrix_cell` binary and the trait-object test harness call it.
///
/// Failure modes:
/// - `ComparatorError::NotInstalled` from `setup` → returns a skipped cell.
/// - Any other error from any phase → records `skip_reason` and returns.
pub async fn drive_one_cell<C: Comparator + ?Sized>(
    comparator: Box<C>,
    ctx: &ComparatorContext,
    plan: &CellPlan,
) -> CellOutcome {
    let mut outcome = CellOutcome::new(&plan.tool, plan.latency_ms, plan.loss_pct, &plan.load);

    // We need to call `&mut self` methods AND a `Box<Self>` consuming
    // shutdown, so keep the box and re-borrow.
    let mut boxed = comparator;

    if let Err(e) = boxed.setup(ctx).await {
        outcome.skipped = matches!(e, ComparatorError::NotInstalled(_));
        outcome.skip_reason = Some(e.to_string());
        // Even if setup failed for a non-installed reason, try to shut
        // down cleanly — ignore the inner error.
        let _ = boxed.shutdown().await;
        return outcome;
    }

    match boxed.measure_throughput(plan.throughput_bytes).await {
        Ok(sample) => {
            outcome.throughput_bps = Some(sample.throughput_bps());
            outcome.p50_us = Some(sample.p50_latency_us);
            outcome.p99_us = Some(sample.p99_latency_us);
            outcome.extras.insert(
                "bytes_pushed".into(),
                #[allow(clippy::cast_precision_loss)]
                {
                    sample.bytes as f64
                },
            );
        }
        Err(e) => {
            outcome.skip_reason = Some(format!("throughput: {e}"));
            let _ = boxed.shutdown().await;
            return outcome;
        }
    }

    match boxed.measure_reconnect_cost().await {
        Ok(d) => outcome.reconnect_ms = Some(u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
        Err(e) => {
            outcome
                .skip_reason
                .get_or_insert_with(|| format!("reconnect: {e}"));
        }
    }

    if let Err(e) = boxed.shutdown().await {
        outcome
            .skip_reason
            .get_or_insert_with(|| format!("shutdown: {e}"));
    }

    outcome
}

// --------------------------------------------------------------------------
// Binary discovery — std-only PATH scan to avoid pulling the `which` crate.
// --------------------------------------------------------------------------

/// Resolve `name` against `PATH`, returning the first executable match.
///
/// On Windows, also tries each `PATHEXT` suffix (`.EXE`, `.CMD`, ...). On
/// Unix, the bare name is tried first (a candidate is "executable" if it
/// exists and is a regular file — the bench harness leans on this rather
/// than `Metadata::permissions().mode() & 0o111` to stay cross-platform).
#[must_use]
pub fn locate_binary(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let pathext = if cfg!(windows) {
        std::env::var_os("PATHEXT").map_or_else(
            || vec![".exe".into(), ".cmd".into(), ".bat".into()],
            |v| {
                v.to_string_lossy()
                    .split(';')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            },
        )
    } else {
        Vec::new()
    };

    for dir in std::env::split_paths(&path) {
        let direct = dir.join(name);
        if direct.is_file() {
            return Some(direct);
        }
        if cfg!(windows) {
            for ext in &pathext {
                let mut candidate = dir.join(name);
                let stem = candidate
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default();
                candidate.set_file_name(format!("{stem}{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Arc;

    /// In-memory `Comparator` that records the order of calls so the test
    /// can assert the lifecycle invariant.
    struct MockComparator {
        calls: Arc<AtomicU32>,
        setup_err: Option<ComparatorError>,
    }

    #[async_trait]
    impl Comparator for MockComparator {
        fn name(&self) -> &'static str {
            "mock"
        }
        async fn setup(&mut self, _ctx: &ComparatorContext) -> ComparatorResult<()> {
            self.calls.fetch_or(0b0001, Ordering::SeqCst);
            if let Some(e) = self.setup_err.take() {
                return Err(e);
            }
            Ok(())
        }
        async fn measure_throughput(&mut self, bytes: usize) -> ComparatorResult<ThroughputSample> {
            // Must happen AFTER setup bit was set.
            assert!(self.calls.load(Ordering::SeqCst) & 0b0001 != 0);
            self.calls.fetch_or(0b0010, Ordering::SeqCst);
            Ok(ThroughputSample {
                bytes,
                elapsed: Duration::from_millis(10),
                p50_latency_us: 100,
                p99_latency_us: 500,
            })
        }
        async fn measure_reconnect_cost(&mut self) -> ComparatorResult<Duration> {
            assert!(self.calls.load(Ordering::SeqCst) & 0b0010 != 0);
            self.calls.fetch_or(0b0100, Ordering::SeqCst);
            Ok(Duration::from_millis(42))
        }
        async fn shutdown(self: Box<Self>) -> ComparatorResult<()> {
            // Shutdown is also reached when setup fails before reconnect —
            // the order invariant we assert is only "setup happened-before
            // shutdown".
            assert!(self.calls.load(Ordering::SeqCst) & 0b0001 != 0);
            self.calls.fetch_or(0b1000, Ordering::SeqCst);
            Ok(())
        }
    }

    fn ctx() -> ComparatorContext {
        ComparatorContext::for_upstream(
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.1:2".parse().unwrap(),
            std::env::temp_dir(),
        )
    }

    #[tokio::test]
    async fn drive_one_cell_runs_setup_throughput_reconnect_shutdown_in_order() {
        let calls = Arc::new(AtomicU32::new(0));
        let mock = MockComparator {
            calls: calls.clone(),
            setup_err: None,
        };
        let plan = CellPlan::from_axes("mock", 0, 0, "idle");
        let outcome = drive_one_cell(Box::new(mock), &ctx(), &plan).await;

        assert_eq!(calls.load(Ordering::SeqCst), 0b1111);
        assert!(!outcome.skipped);
        assert_eq!(outcome.tool, "mock");
        assert!(outcome.throughput_bps.unwrap() > 0.0);
        assert_eq!(outcome.p50_us, Some(100));
        assert_eq!(outcome.p99_us, Some(500));
        assert_eq!(outcome.reconnect_ms, Some(42));
    }

    #[tokio::test]
    async fn drive_one_cell_marks_skipped_when_binary_missing() {
        let calls = Arc::new(AtomicU32::new(0));
        let mock = MockComparator {
            calls: calls.clone(),
            setup_err: Some(ComparatorError::NotInstalled("foo".into())),
        };
        let plan = CellPlan::from_axes("mock", 10, 0, "idle");
        let outcome = drive_one_cell(Box::new(mock), &ctx(), &plan).await;

        assert!(outcome.skipped);
        assert!(outcome.skip_reason.as_deref().unwrap().contains("foo"));
        assert!(outcome.throughput_bps.is_none());
        assert!(outcome.reconnect_ms.is_none());
    }

    #[test]
    fn cell_plan_load_default_bytes() {
        assert_eq!(
            CellPlan::from_axes("x", 0, 0, "saturated").throughput_bytes,
            4 * 1024 * 1024
        );
        assert_eq!(
            CellPlan::from_axes("x", 0, 0, "idle").throughput_bytes,
            64 * 1024
        );
    }

    #[test]
    fn cell_outcome_to_json_includes_axes() {
        let mut o = CellOutcome::new("openssh", 100, 5, "saturated");
        o.throughput_bps = Some(123_456.0);
        let v = o.to_json();
        assert_eq!(v["tool"], "openssh");
        assert_eq!(v["latency_ms"], 100);
        assert_eq!(v["loss_pct"], 5);
        assert_eq!(v["load"], "saturated");
        assert!((v["throughput_bps"].as_f64().unwrap() - 123_456.0).abs() < f64::EPSILON);
    }

    #[test]
    fn locate_binary_handles_missing_gracefully() {
        // Random unlikely name — must return None on any sane PATH.
        assert!(locate_binary("definitely-not-a-real-binary-xyz123").is_none());
    }

    #[test]
    fn comparator_is_object_safe() {
        // The point of this test is that the line compiles: it confirms
        // `dyn Comparator` is valid, which is what the matrix runner needs.
        fn _accepts(_b: Box<dyn Comparator>) {}
    }
}
