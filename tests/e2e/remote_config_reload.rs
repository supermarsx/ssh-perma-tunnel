//! e2e (Wave G): remote-config poller live-reload.
//!
//! Drives the real background poll loop ([`spt_remote_config::spawn_with_fetcher`])
//! with an in-process [`HttpFetcher`] fake, asserting the fingerprint-pin +
//! conditional-GET + apply-on-change contract end-to-end:
//!
//! * **Detect + apply the new body** — the poller is pinned (body
//!   `fingerprint_sha256`) to the *target* config version. While the origin
//!   still serves the previous (stale) body, the pin rejects it and the apply
//!   callback does NOT fire; once the origin flips to the pinned body, the pin
//!   passes and the apply callback fires exactly once with the NEW body. The
//!   callback parses the TOML into a `Config` and swaps a shared cell, so the
//!   "running config set" is observably reloaded. This is the realistic model:
//!   the body fingerprint pins exactly one config version (a re-pin is part of
//!   any genuine config rollout — `spt_config::remote::RemoteConfigSpec::check`
//!   mandates a 64-hex pin, so the pin cannot be disabled).
//! * **No spurious reload** — a body that never changes applies exactly once
//!   across many ticks (the SHA-dedup in the poll loop).
//! * **Fetch failure → serve cache** — with `allow_cached_on_failure = true`
//!   and a verified cache on disk, a transport error yields the cached body
//!   (`StaleFromCache`); the apply callback fires once with the cached body and
//!   the loop survives the error.
//!
//! Hermetic: no HTTP, ephemeral unique state dirs, bounded awaits on the apply
//! signal (no fixed sleeps gating correctness — the poll interval is tiny and
//! we await a `Notify`/poll a shared sink within a deadline).

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use spt_config::schema::Config;
use spt_remote_config::{
    save_atomic, spawn_with_fetcher, HttpFetcher, HttpResponse, RemoteConfigPlan, RemoteConfigSpec,
};
use tokio::sync::Notify;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}

/// A unique, ephemeral state dir under the OS temp root. Avoids a `tempfile`
/// dev-dep edge (mirrors `cfgcrypt_tunnel_up.rs`).
fn unique_state_dir() -> std::path::PathBuf {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let dir = std::env::temp_dir().join(format!("spt-rcfg-reload-{pid}-{n}-{nanos}"));
    std::fs::create_dir_all(&dir).expect("create state dir");
    dir
}

/// Build a plan whose body fingerprint pins `pinned_body`.
fn plan_pinned_to(pinned_body: &[u8]) -> RemoteConfigPlan {
    RemoteConfigPlan {
        spec: RemoteConfigSpec {
            url: "https://cfg.example.invalid/c.toml".into(),
            fingerprint_sha256: sha256_hex(pinned_body),
            allow_cached_on_failure: true,
            max_size_bytes: Some(1_000_000),
            etag_cache: None,
        },
        ..Default::default()
    }
}

/// A minimal but real config TOML carrying a single profile named `name`.
fn config_toml(name: &str) -> String {
    format!(
        r#"version = 1

[[profiles]]
name = "{name}"
enabled = true
protocol = "ssh2"
host = "127.0.0.1"
port = 22
user = "tester"
"#
    )
}

/// Captures bodies handed to the apply callback and the parsed running config.
#[derive(Default)]
struct ApplyState {
    bodies: Mutex<Vec<Vec<u8>>>,
    /// The "running config set" — reloaded by the apply callback.
    running: Mutex<Option<Config>>,
}

impl ApplyState {
    fn body_count(&self) -> usize {
        self.bodies.lock().unwrap().len()
    }
    fn running_profile_name(&self) -> Option<String> {
        self.running
            .lock()
            .unwrap()
            .as_ref()
            .and_then(|c| c.profiles.first())
            .map(|p| p.name.clone())
    }
}

/// Build an apply callback that records the body, parses it into a `Config`,
/// swaps the running cell, and notifies the waiter. Mirrors the production
/// `apply_cb` → config-reload chain (parse + replace the running config set).
fn apply_cb(
    state: Arc<ApplyState>,
    notify: Arc<Notify>,
) -> impl Fn(Vec<u8>) -> std::future::Ready<bool> + Send + Sync + 'static {
    move |body: Vec<u8>| {
        state.bodies.lock().unwrap().push(body.clone());
        if let Ok(text) = std::str::from_utf8(&body) {
            if let Ok((cfg, _warns)) = spt_config::load_str(text, false) {
                *state.running.lock().unwrap() = Some(cfg);
            }
        }
        notify.notify_one();
        // Apply succeeded -> the poller may advance its last-applied hash (the
        // M2 contract: callback returns whether the apply was accepted).
        std::future::ready(true)
    }
}

/// Await the apply callback firing (or time out). No fixed correctness sleep:
/// the loop ticks on a tiny interval and we await the `Notify`.
async fn await_apply(notify: &Notify, state: &ApplyState, want: usize, deadline: Duration) {
    let _ = tokio::time::timeout(deadline, async {
        loop {
            if state.body_count() >= want {
                return;
            }
            notify.notified().await;
        }
    })
    .await;
}

// -----------------------------------------------------------------------------
// Fakes
// -----------------------------------------------------------------------------

/// Replays a queue of bodies, repeating the last one forever once drained, so a
/// long-running loop keeps observing a stable terminal state.
struct QueueFetcher {
    queue: Mutex<Vec<Result<HttpResponse, spt_remote_config::http::HttpError>>>,
    last: Mutex<Option<Result<HttpResponse, spt_remote_config::http::HttpError>>>,
    calls: AtomicUsize,
}

impl QueueFetcher {
    fn new(responses: Vec<Result<HttpResponse, spt_remote_config::http::HttpError>>) -> Self {
        let mut q = responses;
        q.reverse();
        Self {
            queue: Mutex::new(q),
            last: Mutex::new(None),
            calls: AtomicUsize::new(0),
        }
    }
    #[allow(clippy::unnecessary_wraps)] // mirrors err(); both build Result-typed queue entries
    fn ok(body: &[u8]) -> Result<HttpResponse, spt_remote_config::http::HttpError> {
        Ok(HttpResponse {
            status: 200,
            etag: None,
            body: body.to_vec(),
        })
    }
    fn err() -> Result<HttpResponse, spt_remote_config::http::HttpError> {
        Err(spt_remote_config::http::HttpError::Transport(
            "offline".into(),
        ))
    }
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn clone_result(
    r: &Result<HttpResponse, spt_remote_config::http::HttpError>,
) -> Result<HttpResponse, spt_remote_config::http::HttpError> {
    match r {
        Ok(resp) => Ok(resp.clone()),
        Err(e) => Err(spt_remote_config::http::HttpError::Transport(e.to_string())),
    }
}

#[async_trait]
impl HttpFetcher for QueueFetcher {
    async fn get(
        &self,
        _url: &str,
        _if_none_match: Option<&str>,
        _max_bytes: u64,
        _timeout: Duration,
    ) -> Result<HttpResponse, spt_remote_config::http::HttpError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(next) = self.queue.lock().unwrap().pop() {
            *self.last.lock().unwrap() = Some(clone_result(&next));
            next
        } else if let Some(last) = self.last.lock().unwrap().as_ref() {
            clone_result(last)
        } else {
            Err(spt_remote_config::http::HttpError::Transport(
                "fake exhausted".into(),
            ))
        }
    }
}

/// Newtype so an `Arc<QueueFetcher>` can move into the task while the test keeps
/// a clone to assert on call counts.
struct ArcFetcher(Arc<QueueFetcher>);

#[async_trait]
impl HttpFetcher for ArcFetcher {
    async fn get(
        &self,
        url: &str,
        inm: Option<&str>,
        max: u64,
        to: Duration,
    ) -> Result<HttpResponse, spt_remote_config::http::HttpError> {
        self.0.get(url, inm, max, to).await
    }
}

// =============================================================================
// Tests
// =============================================================================

/// Live-reload: pin to the *new* config version (v2). The origin first serves
/// the old version (v1, which fails the pin and is NOT applied), then flips to
/// v2. The apply callback fires exactly once, with v2, and the running config
/// set observably reloads to the v2 profile.
#[tokio::test]
async fn body_change_detected_and_applied_with_new_body() {
    let v1 = config_toml("profile-v1").into_bytes();
    let v2 = config_toml("profile-v2").into_bytes();
    assert_ne!(v1, v2);

    let state = Arc::new(ApplyState::default());
    let notify = Arc::new(Notify::new());
    let dir = unique_state_dir();

    // Pin to v2. Origin serves v1 twice (rejected by the pin), then v2 forever.
    let plan = plan_pinned_to(&v2);
    let fetcher = Arc::new(QueueFetcher::new(vec![
        QueueFetcher::ok(&v1),
        QueueFetcher::ok(&v1),
        QueueFetcher::ok(&v2),
    ]));

    let handle = spawn_with_fetcher(
        plan,
        dir.clone(),
        Duration::from_millis(10),
        ArcFetcher(fetcher.clone()),
        apply_cb(state.clone(), notify.clone()),
    );

    await_apply(&notify, &state, 1, Duration::from_secs(5)).await;
    // Let a few more ticks pass to prove v2 is not re-applied and the loop is
    // stable on the terminal body.
    tokio::time::sleep(Duration::from_millis(80)).await;
    handle.shutdown().await;

    let bodies = state.bodies.lock().unwrap().clone();
    assert_eq!(
        bodies.len(),
        1,
        "apply must fire exactly once (only for the pinned v2 body); got {} applies",
        bodies.len()
    );
    assert_eq!(
        bodies[0], v2,
        "the applied body must be the NEW (v2) config"
    );
    assert_eq!(
        state.running_profile_name().as_deref(),
        Some("profile-v2"),
        "running config set must reload to the v2 profile"
    );
    assert!(
        fetcher.calls() >= 3,
        "loop must have polled through the v1 rejections to reach v2"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// No spurious reload: an unchanged (pinned) body served on every tick applies
/// exactly once across many ticks.
#[tokio::test]
async fn unchanged_body_applies_once_only() {
    let body = config_toml("stable").into_bytes();
    let state = Arc::new(ApplyState::default());
    let notify = Arc::new(Notify::new());
    let dir = unique_state_dir();

    let plan = plan_pinned_to(&body);
    // One queued OK; QueueFetcher repeats it forever.
    let fetcher = Arc::new(QueueFetcher::new(vec![QueueFetcher::ok(&body)]));

    let handle = spawn_with_fetcher(
        plan,
        dir.clone(),
        Duration::from_millis(8),
        ArcFetcher(fetcher.clone()),
        apply_cb(state.clone(), notify.clone()),
    );

    await_apply(&notify, &state, 1, Duration::from_secs(5)).await;
    // Soak across many ticks; the body never changes so apply must stay at 1.
    tokio::time::sleep(Duration::from_millis(120)).await;
    handle.shutdown().await;

    assert_eq!(
        state.body_count(),
        1,
        "a stable body must apply exactly once across many ticks"
    );
    assert!(
        fetcher.calls() >= 2,
        "the loop must have ticked multiple times over the soak window"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Fetch failure with `allow_cached_on_failure = true` and a verified cache on
/// disk → the poller serves the cached body (`StaleFromCache`), applies it once,
/// and the loop survives the transport error.
#[tokio::test]
async fn fetch_failure_serves_cache() {
    let body = config_toml("cached").into_bytes();
    let state = Arc::new(ApplyState::default());
    let notify = Arc::new(Notify::new());
    let dir = unique_state_dir();

    // Seed a verified cache that matches the pin, so the fallback arm can return
    // it after the fetch error.
    save_atomic(&dir, &body, Some("\"etag-v1\"")).expect("seed cache");

    let plan = plan_pinned_to(&body);
    // Always a transport error → forces the cache-fallback arm every tick.
    let fetcher = Arc::new(QueueFetcher::new(vec![QueueFetcher::err()]));

    let handle = spawn_with_fetcher(
        plan,
        dir.clone(),
        Duration::from_millis(10),
        ArcFetcher(fetcher.clone()),
        apply_cb(state.clone(), notify.clone()),
    );

    await_apply(&notify, &state, 1, Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(80)).await;
    handle.shutdown().await;

    let bodies = state.bodies.lock().unwrap().clone();
    assert_eq!(
        bodies.len(),
        1,
        "cached body must apply exactly once despite repeated fetch errors"
    );
    assert_eq!(bodies[0], body, "applied body must be the cached body");
    assert_eq!(
        state.running_profile_name().as_deref(),
        Some("cached"),
        "running config set must reload from the cached body"
    );
    assert!(
        fetcher.calls() >= 1,
        "loop must have attempted at least one fetch and survived the error"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Sanity: a pin mismatch on every tick (origin never serves the pinned body)
/// must NEVER apply — proving the pin gates the apply path (no spurious reload
/// from an unverified body).
#[tokio::test]
async fn pin_mismatch_never_applies() {
    let pinned = config_toml("expected").into_bytes();
    let served = config_toml("imposter").into_bytes();
    assert_ne!(pinned, served);

    let state = Arc::new(ApplyState::default());
    let notify = Arc::new(Notify::new());
    let dir = unique_state_dir();

    // Pin to `pinned`, but the origin only ever serves `served` (wrong sha) and
    // allow_cached_on_failure has no cache to fall back to.
    let mut plan = plan_pinned_to(&pinned);
    plan.spec.allow_cached_on_failure = false;
    let fetcher = Arc::new(QueueFetcher::new(vec![QueueFetcher::ok(&served)]));

    let handle = spawn_with_fetcher(
        plan,
        dir.clone(),
        Duration::from_millis(8),
        ArcFetcher(fetcher.clone()),
        apply_cb(state.clone(), notify.clone()),
    );

    // Give the loop ample ticks; nothing should ever apply.
    tokio::time::sleep(Duration::from_millis(120)).await;
    handle.shutdown().await;

    assert_eq!(
        state.body_count(),
        0,
        "a body that fails the fingerprint pin must never be applied"
    );
    assert!(
        state.running.lock().unwrap().is_none(),
        "running config set must stay empty when the pin never matches"
    );
    assert!(fetcher.calls() >= 1, "loop must have attempted a fetch");

    let _ = std::fs::remove_dir_all(&dir);
}
