//! Real-TLS fetch error/adversarial path tests (t-coverage W2 #5).
//!
//! These drive `spt_remote_config::fetch::fetch` against the in-process
//! `AxumHttpsServer` rig (behind the `testing` feature) over genuine TLS, so
//! the `ReqwestFetcher` transport — status mapping, body cap enforcement,
//! HTTPS-only / downgrade rejection, and the conditional-GET `ETag` round-trip —
//! is exercised end-to-end rather than through a fake.
//!
//! The rig serves a self-signed `localhost` cert; we use a permissive client
//! (the body-fingerprint pin, not the cert, is the integrity control here) so
//! the tests focus on the fetch state machine rather than cert trust.

#![cfg(feature = "testing")]

use std::time::Duration;

use spt_config::remote::RemoteConfigSpec;
use spt_remote_config::fetch::{fetch, FetchOutcome, RemoteConfigError};
use spt_remote_config::http::{HttpError, HttpFetcher, ReqwestFetcher};
use spt_remote_config::testing::AxumHttpsServer;
use tempfile::tempdir;

fn sha256_hex(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(body);
    hex::encode(h.finalize())
}

fn permissive_fetcher() -> ReqwestFetcher {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .https_only(true)
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    ReqwestFetcher::with_client(client)
}

fn spec_for(url: &str, body: &[u8], allow_cached: bool) -> RemoteConfigSpec {
    RemoteConfigSpec {
        url: url.to_string(),
        fingerprint_sha256: sha256_hex(body),
        allow_cached_on_failure: allow_cached,
        max_size_bytes: Some(1_000_000),
        etag_cache: None,
    }
}

// ---------------------------------------------------------------------------
// non-2xx statuses over real TLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_server_404_is_bad_status() {
    let body = "version = 1\n";
    let server = AxumHttpsServer::builder()
        .with_config_response(body)
        .with_status(404)
        .start()
        .await;
    let url = format!("https://localhost:{}/c.toml", server.addr().port());
    let spec = spec_for(&url, body.as_bytes(), false);
    let d = tempdir().unwrap();
    let err = fetch(&spec, d.path(), &permissive_fetcher())
        .await
        .unwrap_err();
    assert!(matches!(err, RemoteConfigError::BadStatus(404)), "{err:?}");
}

#[tokio::test]
async fn real_server_503_without_cache_is_no_cache_fallback() {
    let body = "version = 1\n";
    let server = AxumHttpsServer::builder()
        .with_config_response(body)
        .with_status(503)
        .start()
        .await;
    let url = format!("https://localhost:{}/c.toml", server.addr().port());
    // allow_cached_on_failure=true but no cache on disk → 5xx routes to the
    // fallback arm, which finds nothing usable → BadStatus(503).
    let spec = spec_for(&url, body.as_bytes(), true);
    let d = tempdir().unwrap();
    let err = fetch(&spec, d.path(), &permissive_fetcher())
        .await
        .unwrap_err();
    assert!(matches!(err, RemoteConfigError::BadStatus(503)), "{err:?}");
}

// ---------------------------------------------------------------------------
// HTTPS-only / downgrade rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn plain_http_url_rejected_by_fetcher() {
    // The fetcher's defence-in-depth check rejects a non-HTTPS URL before any
    // socket is opened; the high-level fetch surfaces it (no cache → NoCache).
    let body = b"x";
    let spec = spec_for("http://example.com/c.toml", body, false);
    // Note: the spec shape check ALSO rejects non-HTTPS up front
    // (SpecCheck::UrlNotHttps), which is the first gate hit here.
    let d = tempdir().unwrap();
    let err = fetch(&spec, d.path(), &permissive_fetcher())
        .await
        .unwrap_err();
    assert!(
        matches!(err, RemoteConfigError::InvalidSpec(_)),
        "non-https must be rejected before fetch: {err:?}"
    );
}

#[tokio::test]
async fn fetcher_get_rejects_non_https_directly() {
    // Drive the transport directly to prove the fetcher (not just the spec
    // check) refuses a plain-HTTP URL — the HTTPS-downgrade guard.
    let f = permissive_fetcher();
    let err = f
        .get("http://example.com/x", None, 1024, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::InvalidUrl(_)), "{err:?}");
}

// ---------------------------------------------------------------------------
// oversized body enforcement over real TLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_server_body_over_cap_is_too_large() {
    let big = "x".repeat(4096);
    let server = AxumHttpsServer::builder()
        .with_config_response(&big)
        .start()
        .await;
    let url = format!("https://localhost:{}/c.toml", server.addr().port());
    // Set the cap below the served size so the streaming reader trips it.
    let mut spec = spec_for(&url, big.as_bytes(), false);
    spec.max_size_bytes = Some(1024);
    let d = tempdir().unwrap();
    let err = fetch(&spec, d.path(), &permissive_fetcher())
        .await
        .unwrap_err();
    // No cache + fallback disabled → the BodyTooLarge transport error
    // propagates as Fetch.
    assert!(
        matches!(err, RemoteConfigError::Fetch(HttpError::BodyTooLarge(1024))),
        "{err:?}"
    );
}

#[tokio::test]
async fn fetcher_enforces_cap_directly() {
    let big = "y".repeat(2048);
    let server = AxumHttpsServer::builder()
        .with_config_response(&big)
        .start()
        .await;
    let url = format!("https://localhost:{}/c.toml", server.addr().port());
    let f = permissive_fetcher();
    let err = f
        .get(&url, None, 512, Duration::from_secs(5))
        .await
        .unwrap_err();
    assert!(matches!(err, HttpError::BodyTooLarge(512)), "{err:?}");
}

// ---------------------------------------------------------------------------
// conditional-GET ETag round-trip over real TLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_etag_conditional_get_round_trip() {
    let body = "version = 1\n";
    let server = AxumHttpsServer::builder()
        .with_config_response(body)
        .with_etag("\"etag-1\"")
        .start()
        .await;
    let url = format!("https://localhost:{}/c.toml", server.addr().port());
    let spec = spec_for(&url, body.as_bytes(), false);
    let d = tempdir().unwrap();
    let f = permissive_fetcher();

    // First fetch: 200, persists body + ETag.
    let first = fetch(&spec, d.path(), &f).await.expect("first fetch ok");
    assert_eq!(first.outcome, FetchOutcome::Fresh);
    assert_eq!(first.etag.as_deref(), Some("\"etag-1\""));

    // Second fetch: the rig's serve_handler returns 304 when If-None-Match
    // matches the stored ETag, so the client must reuse its cache.
    let second = fetch(&spec, d.path(), &f).await.expect("second fetch ok");
    assert_eq!(second.outcome, FetchOutcome::NotModified);
    assert_eq!(second.body, body.as_bytes());
}

// ---------------------------------------------------------------------------
// fingerprint MISMATCH over real TLS does not poison cache
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_server_fingerprint_mismatch_is_hard_error() {
    let body = "version = 1\n";
    let server = AxumHttpsServer::builder()
        .with_config_response(body)
        .start()
        .await;
    let url = format!("https://localhost:{}/c.toml", server.addr().port());
    let mut spec = spec_for(&url, body.as_bytes(), false);
    spec.fingerprint_sha256 = "f".repeat(64); // wrong pin
    let d = tempdir().unwrap();
    let err = fetch(&spec, d.path(), &permissive_fetcher())
        .await
        .unwrap_err();
    assert!(matches!(err, RemoteConfigError::FingerprintMismatch { .. }));
    // Nothing was written to the cache.
    assert!(spt_remote_config::cache::load_cached(d.path())
        .unwrap()
        .is_none());
}

// ---------------------------------------------------------------------------
// happy path sanity over real TLS (anchors the negative tests)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_server_fresh_200_persists_and_verifies() {
    let body = "version = 1\nfoo = \"bar\"\n";
    let server = AxumHttpsServer::builder()
        .with_config_response(body)
        .with_etag("\"v9\"")
        .start()
        .await;
    let url = format!("https://localhost:{}/c.toml", server.addr().port());
    let spec = spec_for(&url, body.as_bytes(), false);
    let d = tempdir().unwrap();
    let res = fetch(&spec, d.path(), &permissive_fetcher())
        .await
        .expect("fresh fetch ok");
    assert_eq!(res.outcome, FetchOutcome::Fresh);
    assert_eq!(res.body, body.as_bytes());
    let cached = spt_remote_config::cache::load_cached(d.path())
        .unwrap()
        .unwrap();
    assert_eq!(cached.body, body.as_bytes());
    assert_eq!(cached.etag.as_deref(), Some("\"v9\""));
}
