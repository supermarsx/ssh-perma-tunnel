//! meek-http transport (HTTPS POST/POST fronting through a CDN).
//!
//! ## Wire summary
//!
//! Each direction of the SSH stream becomes a series of HTTPS POST
//! requests against the configured `real_url`. The CDN front terminates
//! TLS using the *URL host* (or explicit `sni` override) as SNI, while
//! the HTTP `Host:` header is set to the meek-server origin
//! (`front_host` override, or the URL host when no front is configured).
//!
//! Session continuity uses the standard `X-Session-Id` header
//! (random 64-bit, hex-encoded). The meek-server responds with the
//! upstream-to-downstream bytes in the response body of each POST. An
//! empty POST body is a keepalive that flushes any buffered downstream
//! bytes.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use rand::RngCore;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, HOST};
use reqwest::{Client, ClientBuilder};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use spt_core::Result;

use crate::audit::AuditHook;
use crate::config::ObfsConfig;
use crate::error::ObfsError;
use crate::transport::{AsyncReadWrite, ObfsTransport};

/// Maximum bytes accepted from a single meek HTTP response body.
///
/// A meek POST response carries one downstream burst of SSH bytes; without a
/// cap a malicious/compromised meek relay or MITM CDN could return a multi-GB
/// body and OOM the client (the sibling transports all cap their frames —
/// obfs4 `MAX_FRAME_PT`, shadowsocks `0x3fff`; meek was the only one missing a
/// bound). 4 MiB matches the remote-config download cap and is far above any
/// legitimate per-POST burst for an SSH tunnel.
pub const MAX_MEEK_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Bounded accumulator for an HTTP response body. Rejects up front if a
/// declared `Content-Length` exceeds the cap, and again while streaming if the
/// running total would exceed it — so the peer can never force an unbounded
/// allocation regardless of whether it sends a (possibly lying) length header.
#[derive(Debug)]
struct MeekBodyCap {
    cap: usize,
    buf: Vec<u8>,
}

impl MeekBodyCap {
    fn new(cap: usize, content_length: Option<u64>) -> std::io::Result<Self> {
        if let Some(len) = content_length {
            if len > cap as u64 {
                return Err(std::io::Error::other(format!(
                    "meek response body Content-Length {len} exceeds cap {cap}"
                )));
            }
        }
        Ok(Self {
            cap,
            buf: Vec::new(),
        })
    }

    fn push(&mut self, chunk: &[u8]) -> std::io::Result<()> {
        if self.buf.len().saturating_add(chunk.len()) > self.cap {
            return Err(std::io::Error::other(format!(
                "meek response body exceeds cap {}",
                self.cap
            )));
        }
        self.buf.extend_from_slice(chunk);
        Ok(())
    }

    fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

/// Read a reqwest response body, streaming it chunk-by-chunk through a
/// [`MeekBodyCap`] so an oversized body is rejected without buffering it whole.
async fn read_body_capped(mut resp: reqwest::Response, cap: usize) -> std::io::Result<Vec<u8>> {
    let mut acc = MeekBodyCap::new(cap, resp.content_length())?;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| std::io::Error::other(format!("meek body: {e}")))?
    {
        acc.push(&chunk)?;
    }
    Ok(acc.into_inner())
}

/// meek-http transport handle.
pub struct MeekHttpTransport {
    cfg: ObfsConfig,
    audit: Arc<dyn AuditHook>,
    /// Test-only simulated HTTP status — when set the transport short-
    /// circuits the live request and returns the canned status.
    pub(crate) simulated_status: u16,
    /// Test-only override of the real (post-DNS) URL.
    url_override: Option<String>,
}

impl MeekHttpTransport {
    /// Construct the transport, validating the config.
    pub fn new(cfg: ObfsConfig, audit: Arc<dyn AuditHook>) -> Result<Self> {
        let ObfsConfig::MeekHttp { .. } = cfg else {
            return Err(ObfsError::InvalidConfig(
                "MeekHttpTransport requires ObfsConfig::MeekHttp".into(),
            )
            .into());
        };
        cfg.validate().map_err(spt_core::Error::from)?;
        Ok(Self {
            cfg,
            audit,
            simulated_status: 200,
            url_override: None,
        })
    }

    /// Override the dial URL — used by integration tests that point at a
    /// loopback fixture.
    #[must_use]
    pub fn with_url_override(mut self, url: impl Into<String>) -> Self {
        self.url_override = Some(url.into());
        self
    }

    /// SNI host used for TLS — `sni` override > URL host.
    #[must_use]
    pub fn sni(&self) -> String {
        match &self.cfg {
            ObfsConfig::MeekHttp { url, sni, .. } => {
                if let Some(s) = sni {
                    return s.clone();
                }
                Self::host_from_url(url).unwrap_or_default()
            }
            _ => unreachable!("checked in new()"),
        }
    }

    /// HTTP Host: header — `front_host` override > URL host.
    #[must_use]
    pub fn host_header(&self) -> String {
        match &self.cfg {
            ObfsConfig::MeekHttp {
                url, front_host, ..
            } => {
                if let Some(h) = front_host {
                    return h.clone();
                }
                Self::host_from_url(url).unwrap_or_default()
            }
            _ => unreachable!("checked in new()"),
        }
    }

    /// True when SNI and Host: headers point at different names (the
    /// "domain fronting" mode meek is designed for).
    #[must_use]
    pub fn is_fronted(&self) -> bool {
        self.sni() != self.host_header()
    }

    /// Inject a simulated HTTP status for error-surface tests.
    pub fn set_simulated_status(&mut self, code: u16) {
        self.simulated_status = code;
    }

    /// Borrow the configured URL.
    #[must_use]
    pub fn url(&self) -> &str {
        match &self.cfg {
            ObfsConfig::MeekHttp { url, .. } => url.as_str(),
            _ => unreachable!("checked in new()"),
        }
    }

    fn host_from_url(url: &str) -> Option<String> {
        let parsed = url::Url::parse(url).ok()?;
        parsed.host_str().map(str::to_owned)
    }
}

#[async_trait]
impl ObfsTransport for MeekHttpTransport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);

        // Test-mode short-circuit: surface the simulated HTTP status as an
        // error so the contract test (#6) keeps passing without a live
        // peer.
        if !(200..300).contains(&self.simulated_status) {
            return Err(ObfsError::Handshake(format!(
                "meek-http front returned HTTP {}",
                self.simulated_status
            ))
            .into());
        }

        let host_hdr = self.host_header();
        let real_url = self
            .url_override
            .clone()
            .unwrap_or_else(|| self.url().to_owned());

        // Build the reqwest client. We rely on the workspace `reqwest`
        // dep (rustls-tls). For domain-fronting the front_host is set
        // via the `Host` header; the TLS SNI follows the URL host
        // because rustls reads it from the URL.
        let mut default_headers = HeaderMap::new();
        // Reqwest sets Host automatically from URL; we override only
        // when fronting is active.
        if host_hdr != Self::host_from_url(&real_url).unwrap_or_default() {
            default_headers.insert(
                HOST,
                HeaderValue::from_str(&host_hdr)
                    .map_err(|e| ObfsError::InvalidConfig(format!("bad host hdr: {e}")))?,
            );
        }
        // Standard meek headers.
        default_headers.insert(
            HeaderName::from_static("x-session-id"),
            HeaderValue::from_str(&random_session_id())
                .map_err(|e| ObfsError::Handshake(format!("sid: {e}")))?,
        );

        let client = ClientBuilder::new()
            .default_headers(default_headers.clone())
            // meek explicitly does NOT pool connections — each POST is
            // independent. But reqwest pools by default; that's still
            // wire-compatible with meek-server.
            .build()
            .map_err(|e| ObfsError::Handshake(format!("reqwest: {e}")))?;

        // Probe: emit an empty POST so configuration errors surface
        // before the SSH layer commits. A 2xx response is required.
        let probe = client
            .post(&real_url)
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(|e| ObfsError::Handshake(format!("meek probe: {e}")))?;
        let status = probe.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(
                ObfsError::Handshake(format!("meek-http front returned HTTP {status}")).into(),
            );
        }
        let initial_body = read_body_capped(probe, MAX_MEEK_BODY_BYTES)
            .await
            .map_err(|e| ObfsError::Handshake(format!("meek body: {e}")))?;

        let stream = MeekStream::new(client, real_url, default_headers, initial_body);
        Ok(Box::new(stream))
    }

    fn name(&self) -> &'static str {
        "meek-http"
    }
}

fn random_session_id() -> String {
    let mut buf = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Streaming bridge: `AsyncRead+Write` over a chain of HTTPS POSTs.
///
/// On `poll_write`: spawn a POST whose body is the data. The response
/// body becomes inbound bytes.
/// On `poll_read`: if buffered bytes are available drain them; else
/// emit an empty-body POST (keepalive) and read its response.
pub struct MeekStream {
    client: Client,
    url: String,
    headers: HeaderMap,
    rx_buf: Vec<u8>,
    in_flight: Option<PostFuture>,
    closed: bool,
}

/// Boxed future yielded by an in-flight POST.
pub type PostFuture = Pin<Box<dyn std::future::Future<Output = std::io::Result<Vec<u8>>> + Send>>;

impl MeekStream {
    /// Construct a stream pre-loaded with the initial probe response body.
    pub fn new(client: Client, url: String, headers: HeaderMap, initial: Vec<u8>) -> Self {
        Self {
            client,
            url,
            headers,
            rx_buf: initial,
            in_flight: None,
            closed: false,
        }
    }

    fn issue_post(&self, body: Vec<u8>) -> PostFuture {
        let c = self.client.clone();
        let u = self.url.clone();
        let h = self.headers.clone();
        Box::pin(async move {
            let r = c
                .post(&u)
                .headers(h)
                .body(body)
                .send()
                .await
                .map_err(|e| std::io::Error::other(format!("{e}")))?; // 1.88 lint: io_other_error
            let status = r.status().as_u16();
            if !(200..300).contains(&status) {
                // 1.88 lint: io_other_error
                return Err(std::io::Error::other(format!("meek HTTP {status}")));
            }
            read_body_capped(r, MAX_MEEK_BODY_BYTES).await
        })
    }
}

impl AsyncRead for MeekStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        loop {
            if !self.rx_buf.is_empty() {
                let n = buf.remaining().min(self.rx_buf.len());
                let drained: Vec<u8> = self.rx_buf.drain(..n).collect();
                buf.put_slice(&drained);
                return Poll::Ready(Ok(()));
            }
            if self.closed {
                return Poll::Ready(Ok(())); // EOF
            }
            if self.in_flight.is_none() {
                // Issue an empty-body keepalive POST to fetch downstream
                // bytes from the meek server.
                let f = self.issue_post(Vec::new());
                self.in_flight = Some(f);
            }
            // Poll the in-flight future.
            let fut = self.in_flight.as_mut().unwrap();
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(bytes)) => {
                    self.in_flight = None;
                    if bytes.is_empty() {
                        // No data — treat as a brief pending. Returning
                        // Pending without registering a fresh waker would
                        // stall; instead surface "would block" so caller
                        // applies backoff.
                        return Poll::Ready(Ok(()));
                    }
                    self.rx_buf = bytes;
                }
                Poll::Ready(Err(e)) => {
                    self.in_flight = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MeekStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Single-flight write: spawn POST, drain response into rx_buf,
        // report `data.len()` consumed.
        if self.in_flight.is_none() {
            let f = self.issue_post(data.to_vec());
            self.in_flight = Some(f);
        }
        let fut = self.in_flight.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(bytes)) => {
                self.in_flight = None;
                self.rx_buf.extend_from_slice(&bytes);
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(e)) => {
                self.in_flight = None;
                Poll::Ready(Err(e))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopAuditHook;

    fn fronted_cfg() -> ObfsConfig {
        ObfsConfig::MeekHttp {
            url: "https://front.cdn.example/path".into(),
            front_host: Some("hidden.example".into()),
            sni: None,
        }
    }

    #[test]
    fn sni_and_host_differ_under_fronting() {
        let t = MeekHttpTransport::new(fronted_cfg(), Arc::new(NoopAuditHook)).unwrap();
        assert_eq!(t.sni(), "front.cdn.example");
        assert_eq!(t.host_header(), "hidden.example");
        assert!(t.is_fronted());
    }

    #[test]
    fn body_cap_const_is_sane() {
        // A regression guard pinning the cap: generous enough for a legitimate
        // SSH burst, but bounded (4 MiB, matching the remote-config cap).
        assert_eq!(MAX_MEEK_BODY_BYTES, 4 * 1024 * 1024);
    }

    #[test]
    fn body_cap_rejects_oversized_content_length_up_front() {
        // A declared Content-Length over the cap is rejected before a single
        // byte is buffered (no unbounded allocation).
        let cap = 1024;
        let err = MeekBodyCap::new(cap, Some(cap as u64 + 1)).unwrap_err();
        assert!(format!("{err}").contains("Content-Length"), "got {err:?}");
    }

    #[test]
    fn body_cap_accepts_small_body() {
        // A valid small body within the cap accumulates correctly.
        let mut acc = MeekBodyCap::new(1024, Some(8)).unwrap();
        acc.push(b"hello").unwrap();
        acc.push(b"!!!").unwrap();
        assert_eq!(acc.into_inner(), b"hello!!!");
    }

    #[test]
    fn body_cap_accepts_body_exactly_at_cap() {
        let cap = 16;
        let mut acc = MeekBodyCap::new(cap, None).unwrap();
        acc.push(&vec![0xAB; cap]).unwrap();
        assert_eq!(acc.into_inner().len(), cap);
    }

    #[test]
    fn body_cap_rejects_streaming_overflow_without_content_length() {
        // Even when the peer sends NO Content-Length, the running total is
        // bounded: once the accumulated body would exceed the cap, push errors.
        let cap = 10;
        let mut acc = MeekBodyCap::new(cap, None).unwrap();
        acc.push(&[0u8; 6]).unwrap();
        let err = acc.push(&[0u8; 6]).unwrap_err();
        assert!(format!("{err}").contains("exceeds cap"), "got {err:?}");
        // The accumulator did not grow past what was accepted before the error.
        assert_eq!(acc.into_inner().len(), 6);
    }

    #[test]
    fn unfronted_cfg_sni_eq_host() {
        let cfg = ObfsConfig::MeekHttp {
            url: "https://plain.example/p".into(),
            front_host: None,
            sni: None,
        };
        let t = MeekHttpTransport::new(cfg, Arc::new(NoopAuditHook)).unwrap();
        assert_eq!(t.sni(), t.host_header());
        assert!(!t.is_fronted());
    }
}
