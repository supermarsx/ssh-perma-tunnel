//! Background remote-config poll driver.
//!
//! This module owns the *mechanics* of periodically refreshing a remote
//! config — the tick loop, exponential backoff with jitter, change detection,
//! and graceful shutdown — while staying **agnostic** to what a "config" even
//! is. It knows nothing about `Config`, `ConfigCell`, or the `Orchestrator`.
//!
//! The caller supplies an async *apply callback* that receives the raw body
//! bytes whenever a genuinely *new* config is observed. The driver invokes it
//! **only** when the fetched body's SHA-256 differs from the last body it
//! handed to the callback. In particular it does NOT invoke the callback on:
//! - `304 Not Modified` (the body is the unchanged cached one), or
//! - `StaleFromCache` fallbacks whose body matches the last applied one.
//!
//! # Entry points
//! - [`spawn`] — production: builds the pinned fetcher from a
//!   [`RemoteConfigPlan`] via [`crate::fetch::fetcher_for_plan`].
//! - [`spawn_with_fetcher`] — test seam: takes any [`HttpFetcher`] so tests
//!   can drive the loop with a fake.
//!
//! Both return a [`RemoteConfigPollHandle`]; call [`RemoteConfigPollHandle::shutdown`]
//! to stop the loop and await the task.
//!
//! # No new dependencies
//! Jitter is derived deterministically from the consecutive-failure counter
//! (a cheap LCG-style hash) rather than pulling in `rand`/`fastrand`.

use std::future::Future;
use std::path::PathBuf;
use std::time::Duration;

use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::cache::hex_sha256;
use crate::fetch::{fetch, fetcher_for_plan, FetchOutcome};
use crate::http::HttpFetcher;
use spt_config::remote::RemoteConfigPlan;

/// Handle to a running background poll task.
///
/// Dropping the handle does NOT stop the task on its own (the shutdown sender
/// is consumed by [`shutdown`](Self::shutdown)); prefer calling
/// [`shutdown`](Self::shutdown) during teardown so the loop exits promptly and
/// the task is awaited to completion.
#[derive(Debug)]
pub struct RemoteConfigPollHandle {
    shutdown_tx: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl RemoteConfigPollHandle {
    /// Signal the loop to stop and await the task.
    ///
    /// Sends the shutdown signal (ignoring the error if the task already
    /// exited) and then awaits the [`JoinHandle`]. A `JoinError` from a
    /// panicked/aborted task is swallowed: shutdown is best-effort teardown.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
        let _ = self.task.await;
    }
}

/// Build the production poll driver, constructing a TLS-pinned fetcher from
/// `plan` via [`crate::fetch::fetcher_for_plan`].
///
/// Errors only if the pinned fetcher cannot be constructed (bad pin set /
/// TLS config); on success the background task is spawned and a handle
/// returned. `apply_cb` is invoked with the body bytes on every *new* config.
///
/// See [`spawn_with_fetcher`] for the parameter semantics.
pub fn spawn<C, Fut>(
    plan: RemoteConfigPlan,
    state_dir: impl Into<PathBuf>,
    interval: Duration,
    apply_cb: C,
) -> Result<RemoteConfigPollHandle, crate::fetch::RemoteConfigError>
where
    C: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let fetcher = fetcher_for_plan(&plan)?;
    Ok(spawn_with_fetcher(
        plan, state_dir, interval, fetcher, apply_cb,
    ))
}

/// Spawn the background poll driver with an injected [`HttpFetcher`].
///
/// This is the test seam: production code uses [`spawn`], which builds a
/// pinned [`crate::http::ReqwestFetcher`]; tests pass a fake.
///
/// # Parameters
/// - `plan`: the verified remote-config plan; only `plan.spec` is used by the
///   fetch path (the pin surface is already baked into `fetcher`).
/// - `state_dir`: cache directory passed to [`crate::fetch::fetch`].
/// - `interval`: the steady-state poll period and the **upper bound** on
///   backoff after failures.
/// - `fetcher`: the HTTP transport (owned by the task for its lifetime).
/// - `apply_cb`: invoked with the raw body bytes **only** when the fetched
///   body differs (by SHA-256) from the last body applied. Boxed internally so
///   large callback futures don't bloat the loop future (clippy
///   `large_futures`).
///
/// # Loop semantics
/// `select! { shutdown => return, sleep(delay) => fetch }`. On `Ok` the
/// backoff resets; if the body is new the callback runs and the recorded SHA
/// advances. On `Err` a bounded log is emitted (first at `warn`, repeats at
/// `debug`, recovery at `warn`) and the next delay grows exponentially with
/// jitter, capped at `interval`.
pub fn spawn_with_fetcher<F, C, Fut>(
    plan: RemoteConfigPlan,
    state_dir: impl Into<PathBuf>,
    interval: Duration,
    fetcher: F,
    apply_cb: C,
) -> RemoteConfigPollHandle
where
    F: HttpFetcher + Send + Sync + 'static,
    C: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let state_dir = state_dir.into();
    let task = tokio::spawn(run_loop(
        plan,
        state_dir,
        interval,
        fetcher,
        apply_cb,
        shutdown_rx,
    ));
    RemoteConfigPollHandle { shutdown_tx, task }
}

/// The driver loop, factored out so it is a plain `async fn` (testable shape).
async fn run_loop<F, C, Fut>(
    plan: RemoteConfigPlan,
    state_dir: PathBuf,
    interval: Duration,
    fetcher: F,
    apply_cb: C,
    mut shutdown_rx: oneshot::Receiver<()>,
) where
    F: HttpFetcher + Send + Sync + 'static,
    C: Fn(Vec<u8>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut last_body_sha: Option<String> = None;
    // Consecutive failure counter: 0 == healthy. Drives both backoff and the
    // log-dedup state machine.
    let mut failures: u32 = 0;
    // Tracks whether we previously logged an error so we can announce recovery
    // exactly once and demote repeated identical failures to debug.
    let mut last_error: Option<String> = None;

    loop {
        let delay = next_delay(interval, failures);
        tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                debug!("remote-config poll loop shutting down");
                return;
            }
            () = tokio::time::sleep(delay) => {}
        }

        match fetch(&plan.spec, &state_dir, &fetcher).await {
            Ok(res) => {
                // Recovery announcement (exactly once).
                if last_error.take().is_some() {
                    warn!("remote-config fetch recovered");
                }
                failures = 0;

                match res.outcome {
                    FetchOutcome::NotModified => {
                        debug!("remote-config unchanged (304)");
                    }
                    FetchOutcome::Fresh | FetchOutcome::StaleFromCache => {
                        let outcome = res.outcome;
                        let sha = hex_sha256(&res.body);
                        if last_body_sha.as_deref() == Some(sha.as_str()) {
                            debug!(?outcome, "remote-config body unchanged; skipping apply");
                        } else {
                            debug!(?outcome, "remote-config body changed; applying");
                            apply_cb(res.body).await;
                            last_body_sha = Some(sha);
                        }
                    }
                }
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                let msg = e.to_string();
                // First occurrence (or a *different* error) → warn; identical
                // repeats → debug. This keeps a flapping/offline origin from
                // flooding the log while still surfacing the initial failure
                // and any change in failure mode.
                if last_error.as_deref() == Some(msg.as_str()) {
                    debug!(error = %msg, failures, "remote-config fetch still failing");
                } else {
                    warn!(error = %msg, failures, "remote-config fetch failed");
                    last_error = Some(msg);
                }
            }
        }
    }
}

/// Compute the next sleep before a fetch attempt.
///
/// `failures == 0` → the steady-state `interval`. Otherwise an exponential
/// backoff `base * 2^(failures-1)` capped at `interval`, with a small
/// deterministic jitter derived from `failures` (no RNG dependency) to avoid
/// synchronized retries across instances.
fn next_delay(interval: Duration, failures: u32) -> Duration {
    if failures == 0 {
        return interval;
    }
    // Base backoff unit: 1s, but never larger than the interval itself.
    let base_ms = 1000u64.min(interval.as_millis().max(1) as u64);
    // Exponential growth, saturating, capped at the interval.
    let shift = (failures - 1).min(20);
    let grown_ms = base_ms.saturating_mul(1u64 << shift);
    let cap_ms = interval.as_millis().max(1) as u64;
    let bounded_ms = grown_ms.min(cap_ms);

    // Deterministic jitter in [0, bounded_ms/4): cheap LCG hash of `failures`.
    let jitter_span = (bounded_ms / 4).max(1);
    let jitter = lcg_jitter(failures) % jitter_span;
    // Subtract jitter so we never exceed the cap.
    Duration::from_millis(bounded_ms.saturating_sub(jitter))
}

/// Cheap deterministic-ish nudge derived from the failure counter. Not for
/// cryptographic use — purely to desynchronize retry storms without adding an
/// RNG crate.
fn lcg_jitter(seed: u32) -> u64 {
    // Numerical Recipes LCG constants on a 64-bit widened seed.
    let x = (u64::from(seed))
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    // Take the high bits (better distributed than the low bits of an LCG).
    x >> 33
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{HttpError, HttpResponse};
    use async_trait::async_trait;
    use spt_config::remote::RemoteConfigSpec;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    /// Test fetcher — replays a queue of responses/errors, then repeats the
    /// last response forever (so a long-running loop keeps observing a stable
    /// state rather than erroring once the queue drains).
    struct FakeFetcher {
        queue: Mutex<Vec<Result<HttpResponse, HttpError>>>,
        last: Mutex<Option<Result<HttpResponse, HttpError>>>,
        calls: AtomicUsize,
    }

    impl FakeFetcher {
        fn new(responses: Vec<Result<HttpResponse, HttpError>>) -> Self {
            // Reverse so we can pop() in submission order.
            let mut q = responses;
            q.reverse();
            Self {
                queue: Mutex::new(q),
                last: Mutex::new(None),
                calls: AtomicUsize::new(0),
            }
        }
        fn ok(status: u16, body: &[u8], etag: Option<&str>) -> HttpResponse {
            HttpResponse {
                status,
                etag: etag.map(str::to_owned),
                body: body.to_vec(),
            }
        }
        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    fn clone_result(r: &Result<HttpResponse, HttpError>) -> Result<HttpResponse, HttpError> {
        match r {
            Ok(resp) => Ok(resp.clone()),
            Err(e) => Err(HttpError::Transport(e.to_string())),
        }
    }

    #[async_trait]
    impl HttpFetcher for FakeFetcher {
        async fn get(
            &self,
            _url: &str,
            _if_none_match: Option<&str>,
            _max_bytes: u64,
            _timeout: Duration,
        ) -> Result<HttpResponse, HttpError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(next) = self.queue.lock().unwrap().pop() {
                *self.last.lock().unwrap() = Some(clone_result(&next));
                next
            } else if let Some(last) = self.last.lock().unwrap().as_ref() {
                clone_result(last)
            } else {
                Err(HttpError::Transport("fake exhausted".into()))
            }
        }
    }

    fn plan_for(body: &[u8]) -> RemoteConfigPlan {
        RemoteConfigPlan {
            spec: RemoteConfigSpec {
                url: "https://x.example.com/c.toml".into(),
                fingerprint_sha256: hex_sha256(body),
                allow_cached_on_failure: true,
                max_size_bytes: Some(1_000_000),
                etag_cache: None,
            },
            ..Default::default()
        }
    }

    /// Collects the bodies handed to the apply callback.
    type Sink = Arc<Mutex<Vec<Vec<u8>>>>;

    fn sink_cb(sink: Sink) -> impl Fn(Vec<u8>) -> std::future::Ready<()> + Send + Sync + 'static {
        move |body: Vec<u8>| {
            sink.lock().unwrap().push(body);
            std::future::ready(())
        }
    }

    #[tokio::test]
    async fn changed_body_invokes_apply_once() {
        let body = b"version = 1\n".to_vec();
        let d = tempdir().unwrap();
        let f = FakeFetcher::new(vec![Ok(FakeFetcher::ok(200, &body, Some("\"v1\"")))]);
        let sink: Sink = Arc::new(Mutex::new(Vec::new()));

        let handle = spawn_with_fetcher(
            plan_for(&body),
            d.path().to_path_buf(),
            Duration::from_millis(20),
            f,
            sink_cb(sink.clone()),
        );

        // Let the loop tick a few times; the body never changes so apply must
        // fire exactly once.
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.shutdown().await;

        let got = sink.lock().unwrap();
        assert_eq!(
            got.len(),
            1,
            "apply_cb must fire exactly once for a stable body"
        );
        assert_eq!(got[0], body);
    }

    #[tokio::test]
    async fn not_modified_does_not_invoke_apply() {
        let body = b"version = 1\n".to_vec();
        let d = tempdir().unwrap();
        // Seed the cache so a 304 has something to return.
        crate::cache::save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        // Always 304.
        let f = FakeFetcher::new(vec![Ok(FakeFetcher::ok(304, b"", None))]);
        let sink: Sink = Arc::new(Mutex::new(Vec::new()));

        let handle = spawn_with_fetcher(
            plan_for(&body),
            d.path().to_path_buf(),
            Duration::from_millis(20),
            f,
            sink_cb(sink.clone()),
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.shutdown().await;

        assert!(
            sink.lock().unwrap().is_empty(),
            "apply_cb must not fire on 304 Not Modified"
        );
    }

    #[tokio::test]
    async fn unchanged_fresh_body_applies_once_only() {
        // Two distinct 200 fetches with the SAME body → apply once.
        let body = b"version = 2\n".to_vec();
        let d = tempdir().unwrap();
        let f = FakeFetcher::new(vec![
            Ok(FakeFetcher::ok(200, &body, None)),
            Ok(FakeFetcher::ok(200, &body, None)),
        ]);
        let sink: Sink = Arc::new(Mutex::new(Vec::new()));

        let handle = spawn_with_fetcher(
            plan_for(&body),
            d.path().to_path_buf(),
            Duration::from_millis(15),
            f,
            sink_cb(sink.clone()),
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.shutdown().await;

        assert_eq!(
            sink.lock().unwrap().len(),
            1,
            "identical body across ticks must apply only once"
        );
    }

    #[tokio::test]
    async fn fetch_error_does_not_stop_loop_or_apply() {
        let body = b"version = 1\n".to_vec();
        let d = tempdir().unwrap();
        // No cache on disk + transport error + allow_cached_on_failure=true →
        // NoCacheFallback error every tick. Loop must keep running.
        let f = Arc::new(FakeFetcher::new(vec![Err(HttpError::Transport(
            "dns".into(),
        ))]));
        let sink: Sink = Arc::new(Mutex::new(Vec::new()));

        let f_for_handle = f.clone();
        let handle = spawn_with_fetcher(
            plan_for(&body),
            d.path().to_path_buf(),
            Duration::from_millis(10),
            ArcFetcher(f_for_handle),
            sink_cb(sink.clone()),
        );
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.shutdown().await;

        assert!(sink.lock().unwrap().is_empty(), "no apply on error");
        assert!(
            f.calls() >= 1,
            "loop must have attempted at least one fetch and survived the error"
        );
    }

    #[tokio::test]
    async fn shutdown_returns_promptly() {
        let body = b"version = 1\n".to_vec();
        let d = tempdir().unwrap();
        // Long interval so the task is parked in sleep when we shut down.
        let f = FakeFetcher::new(vec![Ok(FakeFetcher::ok(200, &body, None))]);
        let sink: Sink = Arc::new(Mutex::new(Vec::new()));

        let handle = spawn_with_fetcher(
            plan_for(&body),
            d.path().to_path_buf(),
            Duration::from_secs(3600),
            f,
            sink_cb(sink.clone()),
        );

        let start = std::time::Instant::now();
        // shutdown must not wait out the hour-long interval.
        tokio::time::timeout(Duration::from_secs(2), handle.shutdown())
            .await
            .expect("shutdown should return promptly, not block on the interval");
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    // The driver must actually tick on its interval. We avoid tokio's paused
    // clock (it needs the `test-util` feature, an extra dep we don't pull in)
    // and instead use a tiny interval with a window many multiples larger, so
    // the lower-bound assertion holds with a wide margin even under the heavy
    // concurrent-test load this workspace runs.
    #[tokio::test]
    async fn loop_ticks_on_interval() {
        let body = b"version = 1\n".to_vec();
        let d = tempdir().unwrap();
        let f = Arc::new(FakeFetcher::new(vec![Ok(FakeFetcher::ok(
            200, &body, None,
        ))]));
        let sink: Sink = Arc::new(Mutex::new(Vec::new()));

        let handle = spawn_with_fetcher(
            plan_for(&body),
            d.path().to_path_buf(),
            // 5ms interval; the 300ms window is a 60x margin.
            Duration::from_millis(5),
            ArcFetcher(f.clone()),
            sink_cb(sink.clone()),
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        handle.shutdown().await;

        assert!(
            f.calls() >= 2,
            "expected the driver to tick more than once over a 300ms window at a 5ms interval, got {}",
            f.calls()
        );
    }

    #[test]
    fn next_delay_steady_state_is_interval() {
        let i = Duration::from_secs(60);
        assert_eq!(next_delay(i, 0), i);
    }

    #[test]
    fn next_delay_backs_off_and_is_bounded() {
        let i = Duration::from_secs(60);
        // Backoff grows but never exceeds the interval.
        for failures in 1..=10u32 {
            let d = next_delay(i, failures);
            assert!(
                d <= i,
                "backoff {d:?} exceeded cap {i:?} at failures={failures}"
            );
        }
        // Early backoff (1 failure) should be well under the cap.
        assert!(next_delay(i, 1) < i);
    }

    /// Newtype so an `Arc<FakeFetcher>` can be moved into the task while the
    /// test retains a clone to assert on call counts.
    struct ArcFetcher(Arc<FakeFetcher>);

    #[async_trait]
    impl HttpFetcher for ArcFetcher {
        async fn get(
            &self,
            url: &str,
            inm: Option<&str>,
            max: u64,
            to: Duration,
        ) -> Result<HttpResponse, HttpError> {
            self.0.get(url, inm, max, to).await
        }
    }
}
