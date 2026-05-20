//! HTTP fetcher abstraction.
//!
//! The [`HttpFetcher`] trait isolates the HTTP transport so unit tests can
//! plug in a fake without spinning up a TLS server. The default
//! implementation is [`ReqwestFetcher`], built with `rustls-tls` and the
//! system root certificate store (strict verification by default).

use async_trait::async_trait;
use std::time::Duration;
use thiserror::Error;

/// Outcome of an [`HttpFetcher::get`] call.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// The response `ETag` header, if present.
    pub etag: Option<String>,
    /// Response body. Empty on `304 Not Modified`.
    pub body: Vec<u8>,
}

/// Errors a fetcher may report.
#[derive(Debug, Error)]
pub enum HttpError {
    /// Transport-level failure (DNS, TLS, IO).
    #[error("transport error: {0}")]
    Transport(String),
    /// Body exceeded the configured size cap. The cap is in bytes.
    #[error("body exceeded {0} bytes")]
    BodyTooLarge(u64),
    /// Redirect that would have downgraded to HTTP, or too many redirects.
    #[error("disallowed redirect: {0}")]
    Redirect(String),
    /// URL did not pass shape checks (e.g. not HTTPS).
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

/// Pluggable HTTP fetcher. Tests inject a fake; production uses
/// [`ReqwestFetcher`].
#[async_trait]
pub trait HttpFetcher: Send + Sync {
    /// Issue a GET. The fetcher MUST stop reading at `max_bytes` and return
    /// [`HttpError::BodyTooLarge`] if exceeded. If `if_none_match` is
    /// provided it MUST be sent as an `If-None-Match` request header so the
    /// server may return `304 Not Modified` with an empty body.
    async fn get(
        &self,
        url: &str,
        if_none_match: Option<&str>,
        max_bytes: u64,
        timeout: Duration,
    ) -> Result<HttpResponse, HttpError>;
}

/// Default `reqwest`-backed implementation. Built with `rustls-tls` and the
/// system root store (strict TLS verification). Redirects are limited to two
/// hops and HTTP downgrades are rejected.
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    /// Build a default client. Returns an error only if the underlying
    /// `reqwest::ClientBuilder` fails (e.g. unable to load system roots).
    pub fn new() -> Result<Self, HttpError> {
        Self::with_pin(&[], false, None)
    }

    /// Build with optional SPKI pin set, allow-self-signed flag, and
    /// chain-depth cap (t5-e2). When `pin_strings` is empty,
    /// `allow_self_signed` is `false`, and `max_cert_chain_depth` is
    /// `None`, this still routes through `spt_trust::PinnedTlsConnector`
    /// to enforce the default chain-depth cap (`Some(5)`).
    pub fn with_pin(
        pin_strings: &[String],
        allow_self_signed: bool,
        max_cert_chain_depth: Option<u32>,
    ) -> Result<Self, HttpError> {
        let rustls_cfg = spt_trust::PinnedTlsConnector::from_config_parts(
            pin_strings,
            allow_self_signed,
            max_cert_chain_depth,
        )
        .map_err(|e| HttpError::Transport(format!("pinned tls: {e}")))?;
        let cfg_inner = (*rustls_cfg).clone();
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(cfg_inner)
            .https_only(true)
            // Spec §14.3: redirects MUST be limited and MUST never downgrade.
            // reqwest enforces no scheme downgrade by default for cross-origin
            // redirects to less-secure schemes; we additionally cap to 2.
            .redirect(reqwest::redirect::Policy::limited(2))
            .timeout(Duration::from_secs(30))
            .user_agent(concat!("spt-remote-config/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        Ok(Self { client })
    }

    /// Replace the underlying client (escape hatch for advanced users such as
    /// tests that want a non-HTTPS-only client). The new client is used as-is.
    pub fn with_client(client: reqwest::Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl HttpFetcher for ReqwestFetcher {
    async fn get(
        &self,
        url: &str,
        if_none_match: Option<&str>,
        max_bytes: u64,
        timeout: Duration,
    ) -> Result<HttpResponse, HttpError> {
        // Defence-in-depth shape check — reqwest's https_only also enforces.
        if !url.starts_with("https://") {
            return Err(HttpError::InvalidUrl(format!("not https: {url}")));
        }

        let mut req = self.client.get(url).timeout(timeout);
        if let Some(etag) = if_none_match {
            req = req.header(reqwest::header::IF_NONE_MATCH, etag);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        if status == 304 {
            return Ok(HttpResponse {
                status,
                etag,
                body: Vec::new(),
            });
        }

        // Bound the in-memory body. We use chunked reading to enforce the cap
        // before we accept arbitrary bytes from the server.
        let mut body = Vec::new();
        let mut stream = resp;
        while let Some(chunk) = stream
            .chunk()
            .await
            .map_err(|e| HttpError::Transport(e.to_string()))?
        {
            if (body.len() as u64).saturating_add(chunk.len() as u64) > max_bytes {
                return Err(HttpError::BodyTooLarge(max_bytes));
            }
            body.extend_from_slice(&chunk);
        }

        Ok(HttpResponse { status, etag, body })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---------- t5-e2: PinnedTlsConnector wiring -----------------

    #[test]
    fn with_pin_empty_set_builds_strict_client() {
        let f = ReqwestFetcher::with_pin(&[], false, None);
        assert!(f.is_ok(), "with_pin empty failed: {:?}", f.err());
    }

    #[test]
    fn with_pin_allow_self_signed_without_pin_rejects() {
        let f = ReqwestFetcher::with_pin(&[], true, None);
        assert!(f.is_err(), "expected refusal: {:?}", f.ok().map(|_| ()));
    }

    #[test]
    fn with_pin_explicit_pin_and_depth_cap_builds() {
        let pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let f = ReqwestFetcher::with_pin(&[pin], false, Some(5));
        assert!(f.is_ok(), "with_pin pinned failed: {:?}", f.err());
    }
}
