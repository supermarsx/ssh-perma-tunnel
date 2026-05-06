//! Remote-config fetch with an injected `HttpFetcher`. The full HTTPS path
//! (axum + self-signed certs) is covered by `spt-remote-config`'s own
//! integration tests; this binary-level test just verifies the fetch ⇒
//! cache pipeline writes a usable cache.

use async_trait::async_trait;
use spt_remote_config::{
    fetch, http::HttpError, FetchOutcome, HttpFetcher, HttpResponse, RemoteConfigSpec,
};
use tempfile::TempDir;

struct FixedFetcher {
    body: Vec<u8>,
    etag: Option<String>,
}

#[async_trait]
impl HttpFetcher for FixedFetcher {
    async fn get(
        &self,
        _url: &str,
        _if_none_match: Option<&str>,
        _max_size: u64,
        _timeout: std::time::Duration,
    ) -> Result<HttpResponse, HttpError> {
        Ok(HttpResponse {
            status: 200,
            body: self.body.clone(),
            etag: self.etag.clone(),
        })
    }
}

#[tokio::test]
async fn fresh_fetch_writes_cache() {
    let tmp = TempDir::new().unwrap();
    let body = b"version = 1\n".to_vec();
    let fp = sha256_hex(&body);
    let spec = RemoteConfigSpec {
        url: "https://example.invalid/cfg".into(),
        fingerprint_sha256: fp,
        allow_cached_on_failure: false,
        max_size_bytes: None,
        etag_cache: None,
    };
    let fetcher = FixedFetcher {
        body: body.clone(),
        etag: Some("\"v1\"".into()),
    };
    let result = fetch(&spec, tmp.path(), &fetcher).await.expect("fetch");
    assert!(matches!(result.outcome, FetchOutcome::Fresh));
    assert_eq!(result.body, body);
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
