//! Integration tests for the comparator harness (t8-C3).
//!
//! These exercise the public surface of `spt_benchmark::comparators` —
//! the trait, the matrix driver, and the missing-binary fallback — without
//! requiring `ssh` or `autossh` to be installed on the test host.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use spt_benchmark::comparators::{
    drive_one_cell, AutosshClient, CellPlan, Comparator, ComparatorContext, ComparatorError,
    ComparatorResult, OpenSshClient, ThroughputSample,
};

fn ctx() -> ComparatorContext {
    ComparatorContext::for_upstream(
        "127.0.0.1:1".parse().unwrap(),
        "127.0.0.1:2".parse().unwrap(),
        std::env::temp_dir(),
    )
}

#[test]
fn comparator_is_trait_object_safe() {
    fn _accepts(_b: Box<dyn Comparator>) {}
}

#[tokio::test]
async fn openssh_comparator_falls_back_when_binary_missing() {
    // Use a constructor-supplied bogus name AND a deliberately-missing
    // override path: both pathways must report NotInstalled rather than
    // panicking or returning a generic IO error.
    let mut c = OpenSshClient::with_binary_name("ssh-does-not-exist-aaaaa");
    let res = c.setup(&ctx()).await;
    assert!(
        matches!(res, Err(ComparatorError::NotInstalled(_))),
        "expected NotInstalled, got {res:?}"
    );

    let mut c = OpenSshClient::new();
    let mut ctx = ctx();
    ctx.binary_override = Some(PathBuf::from("/this/path/does/not/exist/ssh"));
    let res = c.setup(&ctx).await;
    assert!(matches!(res, Err(ComparatorError::NotInstalled(_))));
}

#[tokio::test]
async fn autossh_comparator_falls_back_when_binary_missing() {
    let mut c = AutosshClient::with_binary_name("autossh-does-not-exist-bbbbb");
    let res = c.setup(&ctx()).await;
    assert!(
        matches!(res, Err(ComparatorError::NotInstalled(_))),
        "expected NotInstalled, got {res:?}"
    );

    let mut c = AutosshClient::new();
    let mut ctx = ctx();
    ctx.binary_override = Some(PathBuf::from("/this/path/does/not/exist/autossh"));
    let res = c.setup(&ctx).await;
    assert!(matches!(res, Err(ComparatorError::NotInstalled(_))));
}

/// Mock comparator that records lifecycle bits.
struct LifecycleMock {
    bits: Arc<AtomicU32>,
}

#[async_trait]
impl Comparator for LifecycleMock {
    fn name(&self) -> &'static str {
        "lifecycle-mock"
    }
    async fn setup(&mut self, _ctx: &ComparatorContext) -> ComparatorResult<()> {
        self.bits.fetch_or(1 << 0, Ordering::SeqCst);
        Ok(())
    }
    async fn measure_throughput(&mut self, bytes: usize) -> ComparatorResult<ThroughputSample> {
        // setup must already have set bit 0.
        assert_ne!(self.bits.load(Ordering::SeqCst) & 1, 0, "throughput before setup");
        self.bits.fetch_or(1 << 1, Ordering::SeqCst);
        Ok(ThroughputSample {
            bytes,
            elapsed: Duration::from_millis(5),
            p50_latency_us: 1,
            p99_latency_us: 9,
        })
    }
    async fn measure_reconnect_cost(&mut self) -> ComparatorResult<Duration> {
        assert_ne!(self.bits.load(Ordering::SeqCst) & 2, 0, "reconnect before throughput");
        self.bits.fetch_or(1 << 2, Ordering::SeqCst);
        Ok(Duration::from_millis(7))
    }
    async fn shutdown(self: Box<Self>) -> ComparatorResult<()> {
        assert_ne!(self.bits.load(Ordering::SeqCst) & 4, 0, "shutdown before reconnect");
        self.bits.fetch_or(1 << 3, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn matrix_runner_invokes_comparator_setup_then_throughput_then_shutdown() {
    let bits = Arc::new(AtomicU32::new(0));
    let mock = LifecycleMock { bits: bits.clone() };
    let plan = CellPlan::from_axes("lifecycle-mock", 100, 1, "idle");
    let outcome = drive_one_cell(Box::new(mock), &ctx(), &plan).await;

    // All four phases ran in order.
    assert_eq!(bits.load(Ordering::SeqCst), 0b1111);
    assert!(!outcome.skipped);
    assert_eq!(outcome.tool, "lifecycle-mock");
    assert_eq!(outcome.latency_ms, 100);
    assert_eq!(outcome.loss_pct, 1);
    assert_eq!(outcome.load, "idle");
    assert_eq!(outcome.reconnect_ms, Some(7));
    assert!(outcome.throughput_bps.is_some());
}

/// Mock that errors during setup with a non-NotInstalled error. The runner
/// should still call shutdown (best-effort) and surface the error in
/// `skip_reason` without marking the cell as `skipped`.
struct SetupErrMock {
    shutdown_called: Arc<AtomicU32>,
}

#[async_trait]
impl Comparator for SetupErrMock {
    fn name(&self) -> &'static str {
        "setup-err-mock"
    }
    async fn setup(&mut self, _ctx: &ComparatorContext) -> ComparatorResult<()> {
        Err(ComparatorError::Setup("forced".into()))
    }
    async fn measure_throughput(&mut self, _bytes: usize) -> ComparatorResult<ThroughputSample> {
        unreachable!("must not be called when setup fails")
    }
    async fn measure_reconnect_cost(&mut self) -> ComparatorResult<Duration> {
        unreachable!()
    }
    async fn shutdown(self: Box<Self>) -> ComparatorResult<()> {
        self.shutdown_called.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[tokio::test]
async fn matrix_runner_calls_shutdown_even_when_setup_errors() {
    let cnt = Arc::new(AtomicU32::new(0));
    let mock = SetupErrMock {
        shutdown_called: cnt.clone(),
    };
    let plan = CellPlan::from_axes("setup-err-mock", 0, 0, "idle");
    let outcome = drive_one_cell(Box::new(mock), &ctx(), &plan).await;
    assert!(!outcome.skipped); // generic Setup error is not "NotInstalled"
    assert!(outcome.skip_reason.as_deref().unwrap().contains("forced"));
    assert_eq!(cnt.load(Ordering::SeqCst), 1);
}
