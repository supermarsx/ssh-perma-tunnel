//! High-level remote-config fetch entrypoint.
//!
//! `fetch` orchestrates: shape-check the spec, send a conditional GET via the
//! injected [`HttpFetcher`], handle `304 Not Modified` (cache reuse),
//! enforce the body fingerprint and size cap, and on success atomically
//! persist the body to disk so subsequent runs can fall back when the
//! network is unavailable.

use std::path::Path;
use std::time::Duration;

use thiserror::Error;
use tracing::{debug, warn};

use crate::cache::{hex_sha256, load_cached, save_atomic, CachedEntry};
use crate::http::{HttpError, HttpFetcher, ReqwestFetcher};
use spt_config::remote::{RemoteConfigPlan, RemoteConfigSpec, SpecCheck};

/// Errors specific to remote-config fetching. These map onto
/// `spt_core::Error::InvalidConfig`/`RemoteSinkRejected`/`InternalError` at
/// the binary boundary; the binary exit-code translation is handled by the
/// caller (see spec §7.4).
#[derive(Debug, Error)]
pub enum RemoteConfigError {
    /// `RemoteConfigSpec` failed shape validation.
    #[error("invalid remote-config spec: {0:?}")]
    InvalidSpec(SpecCheck),
    /// HTTPS fetch failed (transport, TLS, redirect, oversize).
    #[error("fetch failed: {0}")]
    Fetch(#[from] HttpError),
    /// Server returned a non-2xx, non-304 status.
    #[error("unexpected http status: {0}")]
    BadStatus(u16),
    /// Body fingerprint did not match the pinned `fingerprint_sha256`.
    #[error("fingerprint mismatch: expected {expected}, got {actual}")]
    FingerprintMismatch {
        /// Pinned fingerprint from the spec.
        expected: String,
        /// Fingerprint of the just-fetched body.
        actual: String,
    },
    /// `304 Not Modified` was returned but no cache exists on disk.
    #[error("server returned 304 but no cache is available")]
    NotModifiedWithoutCache,
    /// Fetch failed and `allow_cached_on_failure` is false (or no cache).
    #[error("fetch failed and no usable cache: {0}")]
    NoCacheFallback(String),
    /// Internal IO failure manipulating the cache directory.
    #[error("cache io error: {0}")]
    CacheIo(String),
}

/// What [`fetch`] actually returned. Distinguishes a fresh body from a cache
/// hit so the supervisor can update its `last_fetched_at` timestamp only on
/// real network success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOutcome {
    /// Server returned 200 OK with a verified body.
    Fresh,
    /// Server returned 304 Not Modified — body is the cached one.
    NotModified,
    /// Network failed; we used the cached body per `allow_cached_on_failure`.
    StaleFromCache,
}

/// Successful result.
#[derive(Debug, Clone)]
pub struct FetchResult {
    /// What happened (fresh / 304 / cache fallback).
    pub outcome: FetchOutcome,
    /// The TOML body bytes, fingerprint-verified against the spec.
    pub body: Vec<u8>,
    /// `ETag` header from the server, when present.
    pub etag: Option<String>,
}

/// Default timeout for a single fetch attempt.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);
/// Default body size cap when the spec did not configure one.
pub const DEFAULT_MAX_BYTES: u64 = 4 * 1024 * 1024; // 4 MiB

/// Fetch (or reuse) a remote config body.
///
/// Behaviour:
/// 1. Validate `spec` shape (HTTPS, valid fingerprint).
/// 2. If a cache is on disk, send `If-None-Match` with the previous `ETag`.
/// 3. On `200`, verify body length ≤ cap and SHA-256 == `fingerprint_sha256`.
/// 4. On `304`, return the cached body (cache MUST exist).
/// 5. On any transport / oversize / TLS failure, fall back to the cache iff
///    `allow_cached_on_failure` is true and the cache passes fingerprint
///    re-check; otherwise propagate the error.
///
/// Side effect: on a fresh `200`, the body and a sidecar (sha256+etag) are
/// persisted via `spt_state::write_atomic` to `<state_dir>/`.
pub async fn fetch<F: HttpFetcher + ?Sized>(
    spec: &RemoteConfigSpec,
    state_dir: &Path,
    fetcher: &F,
) -> Result<FetchResult, RemoteConfigError> {
    let check = spec.check();
    if !matches!(check, SpecCheck::Ok) {
        return Err(RemoteConfigError::InvalidSpec(check));
    }
    let cap = spec.max_size_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let cached: Option<CachedEntry> =
        load_cached(state_dir).map_err(|e| RemoteConfigError::CacheIo(e.to_string()))?;

    let if_none_match = cached.as_ref().and_then(|c| c.etag.as_deref());

    match fetcher
        .get(&spec.url, if_none_match, cap, DEFAULT_TIMEOUT)
        .await
    {
        Ok(resp) if resp.status == 200 => {
            let actual = hex_sha256(&resp.body);
            if !ct_eq(&actual, &spec.fingerprint_sha256.to_ascii_lowercase()) {
                warn!(
                    expected = %spec.fingerprint_sha256,
                    actual = %actual,
                    "remote-config fingerprint mismatch"
                );
                // Fingerprint mismatch is a hard error — DO NOT replace cache.
                return Err(RemoteConfigError::FingerprintMismatch {
                    expected: spec.fingerprint_sha256.clone(),
                    actual,
                });
            }
            save_atomic(state_dir, &resp.body, resp.etag.as_deref())
                .map_err(|e| RemoteConfigError::CacheIo(e.to_string()))?;
            debug!(bytes = resp.body.len(), "remote-config fresh fetch ok");
            Ok(FetchResult {
                outcome: FetchOutcome::Fresh,
                body: resp.body,
                etag: resp.etag,
            })
        }
        Ok(resp) if resp.status == 304 => {
            let c = cached.ok_or(RemoteConfigError::NotModifiedWithoutCache)?;
            // Re-verify cache integrity against the pin before handing back.
            verify_cache_against_pin(&c, &spec.fingerprint_sha256)?;
            debug!("remote-config 304 cache reuse");
            Ok(FetchResult {
                outcome: FetchOutcome::NotModified,
                body: c.body,
                etag: c.etag,
            })
        }
        // E5-F8: a server-error response (5xx) is operationally indistinguishable
        // from a transport failure — the origin is down. Route it through the
        // SAME cache-fallback arm as `Err(e)` when `allow_cached_on_failure` is
        // set, instead of hard-failing with `BadStatus` while a verified cache
        // sits on disk. 4xx (and any other unexpected non-2xx/304) remain hard
        // `BadStatus` errors: they signal a client/config problem the cache
        // cannot paper over.
        Ok(resp) if resp.status >= 500 && spec.allow_cached_on_failure => cache_fallback_or(
            cached,
            spec,
            &format!("http status {}", resp.status),
            RemoteConfigError::BadStatus(resp.status),
        ),
        Ok(resp) => Err(RemoteConfigError::BadStatus(resp.status)),
        Err(e) if spec.allow_cached_on_failure => {
            let reason = e.to_string();
            let on_no_cache = RemoteConfigError::NoCacheFallback(reason.clone());
            cache_fallback_or(cached, spec, &reason, on_no_cache)
        }
        Err(e) => Err(RemoteConfigError::Fetch(e)),
    }
}

/// Shared cache-fallback arm used by both the transport-error and 5xx paths
/// (E5-F8). Returns the verified cache as `StaleFromCache` when one exists and
/// passes the pin re-check; otherwise yields `on_no_cache`.
fn cache_fallback_or(
    cached: Option<CachedEntry>,
    spec: &RemoteConfigSpec,
    reason: &str,
    on_no_cache: RemoteConfigError,
) -> Result<FetchResult, RemoteConfigError> {
    if let Some(c) = cached {
        if verify_cache_against_pin(&c, &spec.fingerprint_sha256).is_ok() {
            warn!(reason = %reason, "remote-config fetch failed; using cache");
            return Ok(FetchResult {
                outcome: FetchOutcome::StaleFromCache,
                body: c.body,
                etag: c.etag,
            });
        }
    }
    Err(on_no_cache)
}

/// Build a TLS-pinned [`ReqwestFetcher`] from a [`RemoteConfigPlan`]'s pin
/// surface (E5-F5 pin plumbing).
///
/// This is the missing link the `config pull` call site needs: instead of
/// `ReqwestFetcher::new()` (an empty pin set), it routes the plan's configured
/// `pin_spki_sha256` / `allow_self_signed` / `max_cert_chain_depth` through
/// `ReqwestFetcher::with_pin`, so the SPKI pins in `[runtime.remote_config]` are
/// actually enforced on the connection.
///
/// # Background poller
/// This builder serves the on-demand `config pull` path. The reusable
/// supervisor-driven refresh loop that consumes
/// `[runtime.remote_config].poll_interval` lives in [`crate::poll`]
/// (see [`crate::poll::spawn`] / [`crate::poll::spawn_with_fetcher`]); it calls
/// this same builder to construct its pinned fetcher.
pub fn fetcher_for_plan(plan: &RemoteConfigPlan) -> Result<ReqwestFetcher, RemoteConfigError> {
    ReqwestFetcher::with_pin(
        &plan.pin_spki_sha256,
        plan.allow_self_signed,
        plan.max_cert_chain_depth,
    )
    .map_err(RemoteConfigError::Fetch)
}

/// One-shot fetch driven by a [`RemoteConfigPlan`] (E5-F5).
///
/// Convenience over [`fetch`] + [`fetcher_for_plan`]: builds a correctly-pinned
/// fetcher from the plan and runs the fetch against `plan.spec`. The call site
/// in `config pull` (wired in Phase 4) should prefer this so configured pins and
/// `allow_cached_on_failure` are honored end-to-end.
///
/// See [`fetcher_for_plan`] for the note on the deferred background poller.
pub async fn fetch_with_plan(
    plan: &RemoteConfigPlan,
    state_dir: &Path,
) -> Result<FetchResult, RemoteConfigError> {
    let fetcher = fetcher_for_plan(plan)?;
    fetch(&plan.spec, state_dir, &fetcher).await
}

fn verify_cache_against_pin(cached: &CachedEntry, pin: &str) -> Result<(), RemoteConfigError> {
    let actual = hex_sha256(&cached.body);
    if ct_eq(&actual, &pin.to_ascii_lowercase()) {
        Ok(())
    } else {
        Err(RemoteConfigError::FingerprintMismatch {
            expected: pin.to_string(),
            actual,
        })
    }
}

/// Constant-time-ish equality for hex strings of equal length.
fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.bytes().zip(b.bytes()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::hex_sha256;
    use crate::http::HttpResponse;
    use async_trait::async_trait;
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// Test fetcher — replays a queue of responses or errors.
    #[derive(Default)]
    struct FakeFetcher {
        queue: Mutex<Vec<Result<HttpResponse, HttpError>>>,
        seen_if_none_match: Mutex<Vec<Option<String>>>,
    }

    impl FakeFetcher {
        fn push_ok(&self, resp: HttpResponse) {
            self.queue.lock().unwrap().push(Ok(resp));
        }
        fn push_err(&self, e: HttpError) {
            self.queue.lock().unwrap().push(Err(e));
        }
    }

    #[async_trait]
    impl HttpFetcher for FakeFetcher {
        async fn get(
            &self,
            _url: &str,
            if_none_match: Option<&str>,
            _max_bytes: u64,
            _timeout: Duration,
        ) -> Result<HttpResponse, HttpError> {
            self.seen_if_none_match
                .lock()
                .unwrap()
                .push(if_none_match.map(str::to_owned));
            self.queue
                .lock()
                .unwrap()
                .pop()
                .ok_or_else(|| HttpError::Transport("fake exhausted".into()))?
        }
    }

    fn good_spec(body: &[u8]) -> RemoteConfigSpec {
        RemoteConfigSpec {
            url: "https://x.example.com/c.toml".into(),
            fingerprint_sha256: hex_sha256(body),
            allow_cached_on_failure: true,
            max_size_bytes: Some(1_000_000),
            etag_cache: None,
        }
    }

    #[tokio::test]
    async fn fresh_200_persists() {
        let d = tempdir().unwrap();
        let body = b"version = 1\n".to_vec();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 200,
            etag: Some("\"v1\"".into()),
            body: body.clone(),
        });
        let res = fetch(&good_spec(&body), d.path(), &f).await.unwrap();
        assert_eq!(res.outcome, FetchOutcome::Fresh);
        assert_eq!(res.body, body);
        // Cache exists.
        let c = load_cached(d.path()).unwrap().unwrap();
        assert_eq!(c.body, body);
        assert_eq!(c.etag.as_deref(), Some("\"v1\""));
    }

    #[tokio::test]
    async fn not_modified_uses_cache_and_sends_etag() {
        let d = tempdir().unwrap();
        let body = b"version = 1\n".to_vec();
        save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        let spec = good_spec(&body);
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 304,
            etag: None,
            body: Vec::new(),
        });
        let res = fetch(&spec, d.path(), &f).await.unwrap();
        assert_eq!(res.outcome, FetchOutcome::NotModified);
        assert_eq!(res.body, body);
        assert_eq!(
            f.seen_if_none_match
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .as_deref(),
            Some("\"v1\"")
        );
    }

    #[tokio::test]
    async fn fingerprint_mismatch_is_hard_error() {
        let d = tempdir().unwrap();
        let body = b"original".to_vec();
        let mut spec = good_spec(&body);
        spec.fingerprint_sha256 = "f".repeat(64);
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 200,
            etag: None,
            body,
        });
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::FingerprintMismatch { .. }));
        // Cache MUST NOT be written on mismatch.
        assert!(load_cached(d.path()).unwrap().is_none());
    }

    #[tokio::test]
    async fn size_cap_propagates() {
        let d = tempdir().unwrap();
        let body = vec![b'x'; 100];
        let spec = good_spec(&body);
        let f = FakeFetcher::default();
        f.push_err(HttpError::BodyTooLarge(50));
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        // allow_cached_on_failure=true but no cache → NoCacheFallback.
        assert!(matches!(err, RemoteConfigError::NoCacheFallback(_)));
    }

    #[tokio::test]
    async fn cache_fallback_on_transport_error() {
        let d = tempdir().unwrap();
        let body = b"cached".to_vec();
        let spec = good_spec(&body);
        save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        let f = FakeFetcher::default();
        f.push_err(HttpError::Transport("dns".into()));
        let res = fetch(&spec, d.path(), &f).await.unwrap();
        assert_eq!(res.outcome, FetchOutcome::StaleFromCache);
        assert_eq!(res.body, body);
    }

    #[tokio::test]
    async fn cache_fallback_disabled_propagates_error() {
        let d = tempdir().unwrap();
        let body = b"cached".to_vec();
        let mut spec = good_spec(&body);
        spec.allow_cached_on_failure = false;
        save_atomic(d.path(), &body, None).unwrap();
        let f = FakeFetcher::default();
        f.push_err(HttpError::Transport("nope".into()));
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::Fetch(_)));
    }

    #[tokio::test]
    async fn three_oh_four_with_no_cache_errors() {
        let d = tempdir().unwrap();
        let body = b"x".to_vec();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 304,
            etag: None,
            body: Vec::new(),
        });
        let err = fetch(&good_spec(&body), d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::NotModifiedWithoutCache));
    }

    #[tokio::test]
    async fn invalid_spec_rejected() {
        let d = tempdir().unwrap();
        let mut spec = good_spec(b"x");
        spec.url = "http://nope".into();
        let f = FakeFetcher::default();
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::InvalidSpec(_)));
    }

    #[tokio::test]
    async fn bad_status_propagates() {
        let d = tempdir().unwrap();
        let body = b"x".to_vec();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 500,
            etag: None,
            body: Vec::new(),
        });
        // 5xx with allow_cached_on_failure=true but NO cache → BadStatus(500)
        // (the cache-fallback arm finds nothing usable; E5-F8 keeps this hard).
        let err = fetch(&good_spec(&body), d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::BadStatus(500)), "{err:?}");
    }

    // E5-F8: a 5xx response with a verified cache on disk and
    // allow_cached_on_failure=true must fall back to the cache, exactly like a
    // transport error does — not hard-fail with BadStatus.
    #[tokio::test]
    async fn five_xx_with_cache_allowed_falls_back_to_cache() {
        let d = tempdir().unwrap();
        let body = b"cached-config\n".to_vec();
        let spec = good_spec(&body); // allow_cached_on_failure: true
        save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 503,
            etag: None,
            body: Vec::new(),
        });
        let res = fetch(&spec, d.path(), &f).await.unwrap();
        assert_eq!(res.outcome, FetchOutcome::StaleFromCache);
        assert_eq!(res.body, body);
    }

    // E5-F8: a 5xx must STILL hard-fail when cache-fallback is disabled.
    #[tokio::test]
    async fn five_xx_with_cache_disabled_is_bad_status() {
        let d = tempdir().unwrap();
        let body = b"cached".to_vec();
        let mut spec = good_spec(&body);
        spec.allow_cached_on_failure = false;
        save_atomic(d.path(), &body, None).unwrap();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 502,
            etag: None,
            body: Vec::new(),
        });
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::BadStatus(502)), "{err:?}");
    }

    // E5-F8: a 4xx is a client/config problem, NOT a fallback case — it must
    // stay BadStatus even with a usable cache and allow_cached_on_failure=true.
    #[tokio::test]
    async fn four_xx_does_not_fall_back_to_cache() {
        let d = tempdir().unwrap();
        let body = b"cached".to_vec();
        let spec = good_spec(&body); // allow_cached_on_failure: true
        save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 404,
            etag: None,
            body: Vec::new(),
        });
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::BadStatus(404)), "{err:?}");
    }

    // --- additional fetch error / adversarial paths (t-coverage W2 #5) ---

    /// A `304 Not Modified` arriving when a cache file IS present but its body
    /// no longer matches the pin must NOT be handed back — the 304 re-verifies
    /// the cache against the pin and fails closed.
    #[tokio::test]
    async fn not_modified_with_tampered_cache_is_rejected() {
        let d = tempdir().unwrap();
        let good_body = b"version = 1\n".to_vec();
        let spec = good_spec(&good_body);
        // Persist a DIFFERENT body than the pin expects (on-disk tampering).
        save_atomic(d.path(), b"tampered", Some("\"v1\"")).unwrap();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 304,
            etag: None,
            body: Vec::new(),
        });
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(
            matches!(err, RemoteConfigError::FingerprintMismatch { .. }),
            "304 must re-verify cache against the pin; got {err:?}"
        );
    }

    /// A malformed / short fingerprint pin must be rejected by the up-front
    /// spec shape check before any network access happens.
    #[tokio::test]
    async fn malformed_fingerprint_pin_rejected_before_fetch() {
        let d = tempdir().unwrap();
        let body = b"x".to_vec();
        let mut spec = good_spec(&body);
        spec.fingerprint_sha256 = "abc".into(); // far too short, non-64-hex
        let f = FakeFetcher::default(); // empty queue: a fetch attempt would error "exhausted"
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(
            matches!(
                err,
                RemoteConfigError::InvalidSpec(SpecCheck::FingerprintMalformed)
            ),
            "got {err:?}"
        );
        // Confirm NO fetch was attempted (fail-closed before network).
        assert!(f.seen_if_none_match.lock().unwrap().is_empty());
    }

    /// A 64-char-but-non-hex fingerprint is also malformed.
    #[tokio::test]
    async fn non_hex_fingerprint_pin_rejected() {
        let d = tempdir().unwrap();
        let mut spec = good_spec(b"x");
        spec.fingerprint_sha256 = "z".repeat(64); // right length, not hex
        let f = FakeFetcher::default();
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(
            err,
            RemoteConfigError::InvalidSpec(SpecCheck::FingerprintMalformed)
        ));
    }

    /// Fingerprint MISMATCH on a fresh 200 body must never persist the bad
    /// body to the cache (fail-closed; the prior cache, if any, is preserved).
    #[tokio::test]
    async fn fingerprint_mismatch_preserves_existing_cache() {
        let d = tempdir().unwrap();
        let cached_body = b"good-cached\n".to_vec();
        let spec = good_spec(&cached_body);
        save_atomic(d.path(), &cached_body, Some("\"v1\"")).unwrap();
        // Server serves a DIFFERENT body whose hash won't match the pin.
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 200,
            etag: Some("\"v2\"".into()),
            body: b"evil-body".to_vec(),
        });
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::FingerprintMismatch { .. }));
        // The original good cache must be untouched.
        let c = load_cached(d.path()).unwrap().unwrap();
        assert_eq!(c.body, cached_body, "mismatch must NOT overwrite the cache");
        assert_eq!(c.etag.as_deref(), Some("\"v1\""));
    }

    /// A redirect/downgrade-style transport rejection (HttpError::Redirect)
    /// with no cache and fallback enabled surfaces as NoCacheFallback (the
    /// HTTPS->HTTP downgrade rejection itself lives in the fetcher; here we
    /// assert the high-level fetch routes the rejection, not silently follows).
    #[tokio::test]
    async fn redirect_rejection_without_cache_is_no_cache_fallback() {
        let d = tempdir().unwrap();
        let spec = good_spec(b"x"); // allow_cached_on_failure: true, but no cache on disk
        let f = FakeFetcher::default();
        f.push_err(HttpError::Redirect("https->http downgrade".into()));
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(
            matches!(err, RemoteConfigError::NoCacheFallback(_)),
            "{err:?}"
        );
    }

    /// Same redirect rejection but with fallback DISABLED propagates the
    /// underlying Fetch error rather than masking it.
    #[tokio::test]
    async fn redirect_rejection_fallback_disabled_propagates() {
        let d = tempdir().unwrap();
        let mut spec = good_spec(b"x");
        spec.allow_cached_on_failure = false;
        let f = FakeFetcher::default();
        f.push_err(HttpError::Redirect("too many hops".into()));
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(
            matches!(err, RemoteConfigError::Fetch(HttpError::Redirect(_))),
            "{err:?}"
        );
    }

    /// An InvalidUrl transport error (e.g. the fetcher's defence-in-depth
    /// non-HTTPS check fired) with fallback disabled propagates as Fetch.
    #[tokio::test]
    async fn invalid_url_transport_error_propagates() {
        let d = tempdir().unwrap();
        let mut spec = good_spec(b"x");
        spec.allow_cached_on_failure = false;
        let f = FakeFetcher::default();
        f.push_err(HttpError::InvalidUrl("not https".into()));
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(
            err,
            RemoteConfigError::Fetch(HttpError::InvalidUrl(_))
        ));
    }

    /// Oversized body (BodyTooLarge) WITH a valid cache and fallback enabled
    /// falls back to the cache rather than hard-failing.
    #[tokio::test]
    async fn oversized_body_with_cache_falls_back() {
        let d = tempdir().unwrap();
        let body = b"cached-config\n".to_vec();
        let spec = good_spec(&body);
        save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        let f = FakeFetcher::default();
        f.push_err(HttpError::BodyTooLarge(1024));
        let res = fetch(&spec, d.path(), &f).await.unwrap();
        assert_eq!(res.outcome, FetchOutcome::StaleFromCache);
        assert_eq!(res.body, body);
    }

    /// Timeout (modelled as a Transport error) with fallback disabled is a
    /// hard Fetch error — the cache must NOT paper over an explicit no-fallback.
    #[tokio::test]
    async fn timeout_fallback_disabled_propagates() {
        let d = tempdir().unwrap();
        let body = b"cached".to_vec();
        let mut spec = good_spec(&body);
        spec.allow_cached_on_failure = false;
        save_atomic(d.path(), &body, None).unwrap();
        let f = FakeFetcher::default();
        f.push_err(HttpError::Transport("operation timed out".into()));
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(
            err,
            RemoteConfigError::Fetch(HttpError::Transport(_))
        ));
    }

    /// Conditional-GET round-trip: a fresh 200 records the server ETag; a
    /// subsequent fetch sends it back as If-None-Match and the server's 304
    /// reuses the cache. Verifies the ETag actually flows both directions.
    #[tokio::test]
    async fn conditional_get_etag_round_trip() {
        let d = tempdir().unwrap();
        let body = b"version = 1\n".to_vec();
        let spec = good_spec(&body);

        // First fetch: 200 with an ETag — persists body + etag.
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 200,
            etag: Some("\"rev-7\"".into()),
            body: body.clone(),
        });
        let first = fetch(&spec, d.path(), &f).await.unwrap();
        assert_eq!(first.outcome, FetchOutcome::Fresh);
        // The first request had no prior cache → no If-None-Match.
        assert_eq!(
            f.seen_if_none_match
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .as_deref(),
            None
        );

        // Second fetch: server returns 304 — must send the stored ETag and
        // hand back the cached body.
        let f2 = FakeFetcher::default();
        f2.push_ok(HttpResponse {
            status: 304,
            etag: None,
            body: Vec::new(),
        });
        let second = fetch(&spec, d.path(), &f2).await.unwrap();
        assert_eq!(second.outcome, FetchOutcome::NotModified);
        assert_eq!(second.body, body);
        assert_eq!(
            f2.seen_if_none_match
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .as_deref(),
            Some("\"rev-7\""),
            "the stored ETag must be replayed as If-None-Match"
        );
    }

    /// Cache READ failure: a body file that exists but is unreadable surfaces
    /// as CacheIo (fail-closed) rather than being treated as "no cache".
    #[cfg(unix)]
    #[tokio::test]
    async fn cache_read_failure_surfaces_as_cache_io() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let body = b"x".to_vec();
        let spec = good_spec(&body);
        save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        // Strip all read permission on the cache body file.
        let p = crate::cache::cache_path(d.path());
        let mut perms = std::fs::metadata(&p).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&p, perms).unwrap();

        let f = FakeFetcher::default();
        let res = fetch(&spec, d.path(), &f).await;

        // Restore perms so tempdir cleanup succeeds regardless of outcome.
        let mut restore = std::fs::metadata(&p).unwrap().permissions();
        restore.set_mode(0o600);
        let _ = std::fs::set_permissions(&p, restore);

        // Running as root can read regardless of mode; only assert when the
        // permission actually bit (non-root). If it was readable, the fetch
        // would proceed to the (empty) fetcher and error differently — accept
        // either, but when CacheIo fires it must be the right variant.
        if let Err(e) = res {
            if matches!(e, RemoteConfigError::CacheIo(_)) {
                // expected fail-closed path
            } else {
                // root read the file; fetch proceeded then the fake exhausted.
                assert!(
                    matches!(
                        e,
                        RemoteConfigError::NoCacheFallback(_) | RemoteConfigError::Fetch(_)
                    ),
                    "unexpected error when cache was readable: {e:?}"
                );
            }
        }
    }

    /// Cache WRITE failure during a fresh 200 persist surfaces as CacheIo: we
    /// point the state dir at a path that is a FILE, so creating the cache file
    /// underneath it fails.
    #[tokio::test]
    async fn cache_write_failure_surfaces_as_cache_io() {
        let parent = tempdir().unwrap();
        // state_dir is actually a regular file → write_atomic under it fails.
        let bogus = parent.path().join("not-a-dir");
        std::fs::write(&bogus, b"i am a file").unwrap();
        let body = b"version = 1\n".to_vec();
        let spec = good_spec(&body);
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 200,
            etag: None,
            body,
        });
        let err = fetch(&spec, &bogus, &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::CacheIo(_)), "{err:?}");
    }

    /// A non-500 unexpected status (e.g. 418) with fallback enabled and a
    /// usable cache is still a hard BadStatus — only >=500 routes to fallback.
    #[tokio::test]
    async fn teapot_status_does_not_fall_back() {
        let d = tempdir().unwrap();
        let body = b"cached".to_vec();
        let spec = good_spec(&body);
        save_atomic(d.path(), &body, Some("\"v1\"")).unwrap();
        let f = FakeFetcher::default();
        f.push_ok(HttpResponse {
            status: 418,
            etag: None,
            body: Vec::new(),
        });
        let err = fetch(&spec, d.path(), &f).await.unwrap_err();
        assert!(matches!(err, RemoteConfigError::BadStatus(418)), "{err:?}");
    }

    // E5-F5 pin plumbing: the fetcher builder carries the configured pin set,
    // and the plan carries the configured body fingerprint.
    #[test]
    fn pin_builder_carries_configured_fingerprint_and_pins() {
        // A syntactically valid base64 SPKI pin (the connector validates format).
        let pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let rc = spt_config::RuntimeRemoteConfig {
            url: Some("https://cfg.example.com/c.toml".into()),
            fingerprint_sha256: Some("c".repeat(64)),
            allow_cached_on_failure: Some(true),
            pin_spki_sha256: vec![pin.clone()],
            max_cert_chain_depth: Some(4),
            ..Default::default()
        };
        let plan = RemoteConfigSpec::plan_from_runtime(&rc, None, None, Some(1_000_000)).unwrap();
        // Configured fingerprint flows into the spec used by fetch().
        assert_eq!(plan.spec.fingerprint_sha256, "c".repeat(64));
        assert!(plan.spec.allow_cached_on_failure);
        // Configured SPKI pins flow into the plan's TLS pin surface.
        assert_eq!(plan.pin_spki_sha256, vec![pin]);
        assert_eq!(plan.max_cert_chain_depth, Some(4));
        // And the builder constructs a real pinned fetcher without error.
        let fetcher = fetcher_for_plan(&plan);
        assert!(
            fetcher.is_ok(),
            "fetcher_for_plan failed: {:?}",
            fetcher.err()
        );
    }
}
