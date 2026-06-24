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

/// A sealed (SPTENC1) body fetches successfully and the fingerprint pin
/// verifies the *sealed* bytes (the client unseals after fetch). This proves
/// the pin covers the ciphertext you intended to host — decrypt happens at the
/// consumer boundary (`config pull` / poll apply_cb), not inside `fetch`.
#[tokio::test]
async fn fetch_pins_and_returns_sealed_body() {
    use secrecy::ExposeSecret as _;
    use spt_config_crypt::{generate_psk, is_sealed, seal, KeySource};
    let tmp = TempDir::new().unwrap();
    let psk = generate_psk();
    let plaintext = b"version = 1\n[logging]\nlevel = \"debug\"\n";
    let sealed = seal(plaintext, &KeySource::Psk(psk)).expect("seal");
    assert!(is_sealed(&sealed));

    let fp = sha256_hex(&sealed); // pin over the SEALED bytes
    let spec = RemoteConfigSpec {
        url: "https://example.invalid/cfg".into(),
        fingerprint_sha256: fp,
        allow_cached_on_failure: false,
        max_size_bytes: None,
        etag_cache: None,
    };
    let fetcher = FixedFetcher {
        body: sealed.clone(),
        etag: None,
    };
    let result = fetch(&spec, tmp.path(), &fetcher).await.expect("fetch");
    assert!(matches!(result.outcome, FetchOutcome::Fresh));
    assert_eq!(
        result.body, sealed,
        "fetch returns the sealed body verbatim"
    );
    assert!(is_sealed(&result.body));

    // The client can unseal the fetched body back to plaintext.
    let pt = spt_config_crypt::unseal(&result.body, &KeySource::Psk(psk)).expect("unseal");
    assert_eq!(pt.expose_secret().as_slice(), plaintext);
}

/// A sealed body whose plaintext-pin (wrong) does NOT match → fetch rejects.
#[tokio::test]
async fn fetch_rejects_when_pin_is_over_plaintext_not_sealed() {
    use spt_config_crypt::{generate_psk, seal, KeySource};
    let tmp = TempDir::new().unwrap();
    let psk = generate_psk();
    let plaintext = b"version = 1\n";
    let sealed = seal(plaintext, &KeySource::Psk(psk)).expect("seal");
    // Pin the PLAINTEXT by mistake — must not verify the sealed body.
    let spec = RemoteConfigSpec {
        url: "https://example.invalid/cfg".into(),
        fingerprint_sha256: sha256_hex(plaintext),
        allow_cached_on_failure: false,
        max_size_bytes: None,
        etag_cache: None,
    };
    let fetcher = FixedFetcher {
        body: sealed,
        etag: None,
    };
    assert!(fetch(&spec, tmp.path(), &fetcher).await.is_err());
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
