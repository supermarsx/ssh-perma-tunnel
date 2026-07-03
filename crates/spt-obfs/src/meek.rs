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

use std::future::Future;
use std::net::SocketAddr;
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

/// TCP/TLS connect deadline for the meek front (M10: a stalled front must not
/// pin the dial).
const MEEK_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Per-request round-trip deadline (covers the probe POST and each later POST).
const MEEK_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Idle poll interval: when a keepalive POST returns an EMPTY body (the server
/// simply had no downstream bytes ready), the read side waits this long before
/// issuing the next keepalive POST. An empty body is NOT end-of-stream — the
/// meek session stays open — so we back off and retry rather than surfacing a
/// premature EOF that would half-close the tunnel (HIGH-2a).
const MEEK_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

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

    /// The explicit `meek.sni` override, if configured (`None` falls back to
    /// the dialed URL host for the TLS SNI). Distinct from [`sni`](Self::sni),
    /// which resolves the fallback against the *configured* URL — `connect`
    /// needs the override relative to the *actually dialed* URL (which may be a
    /// test `url_override`).
    fn sni_override(&self) -> Option<&str> {
        match &self.cfg {
            ObfsConfig::MeekHttp { sni, .. } => sni.as_deref(),
            _ => None,
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

/// Plan for presenting a distinct TLS SNI through `reqwest`.
///
/// `reqwest` derives the TLS `ClientHello` SNI from the request URL host and
/// exposes no separate SNI knob. To honour a `meek.sni` override we POST to a
/// URL whose host *is* the desired SNI and pin that name back to the real
/// host's address with a DNS `resolve()` override, so the socket still connects
/// to the real front while the `ClientHello` advertises the configured SNI.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SniPlan {
    /// URL `reqwest` should POST to; its host drives the TLS SNI.
    dial_url: String,
    /// `Some((sni_host, real_host, port))` when the SNI differs from the real
    /// host and a `resolve()` override is required; `None` when the SNI already
    /// equals the URL host (no rewrite — prior behaviour preserved).
    resolve: Option<(String, String, u16)>,
}

/// Compute the [`SniPlan`] for dialing `real_url` while presenting `sni` as the
/// TLS SNI.
///
/// When `sni` is empty or already equal to the URL host the URL is dialed
/// unchanged (behaviour-preserving); otherwise the URL host is rewritten to
/// `sni` and the original host/port is returned so `connect` can pin it via
/// `resolve_to_addrs`.
fn plan_sni(real_url: &str, sni: &str) -> std::result::Result<SniPlan, ObfsError> {
    let mut parsed = url::Url::parse(real_url)
        .map_err(|e| ObfsError::InvalidConfig(format!("meek url: {e}")))?;
    let real_host = parsed.host_str().unwrap_or_default().to_owned();
    if sni.is_empty() || sni == real_host {
        return Ok(SniPlan {
            dial_url: real_url.to_owned(),
            resolve: None,
        });
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    parsed
        .set_host(Some(sni))
        .map_err(|e| ObfsError::InvalidConfig(format!("meek sni host {sni:?}: {e}")))?;
    Ok(SniPlan {
        dial_url: parsed.to_string(),
        resolve: Some((sni.to_owned(), real_host, port)),
    })
}

#[async_trait]
impl ObfsTransport for MeekHttpTransport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);

        // Test-mode short-circuit: surface the simulated HTTP status as an
        // error so the contract test (#6) keeps passing without a live
        // peer.
        if !(200..300).contains(&self.simulated_status) {
            tracing::warn!(
                transport = "meek-http",
                http_status = self.simulated_status,
                reason = "front-non-2xx",
                "meek-http handshake rejected: front returned non-2xx status"
            );
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

        // Resolve the TLS SNI: the `meek.sni` override when set, else the URL
        // host. `reqwest` has no separate SNI knob, so an override rewrites the
        // dial URL host to the SNI and pins that name back to the real host's
        // address (see `plan_sni`) — the socket still reaches the front while
        // the `ClientHello` advertises the configured SNI.
        let sni_override = self.sni_override().unwrap_or_default();
        let plan = plan_sni(&real_url, sni_override).map_err(spt_core::Error::from)?;

        // Build the reqwest client. We rely on the workspace `reqwest`
        // dep (rustls-tls). For domain-fronting the front_host is set
        // via the `Host` header; the TLS SNI follows the DIAL URL host
        // (the `sni` override when configured, else the URL host).
        let mut default_headers = HeaderMap::new();
        // Reqwest sets Host automatically from the dial URL host; override it
        // whenever the intended origin differs (fronting, or an SNI rewrite).
        if host_hdr != Self::host_from_url(&plan.dial_url).unwrap_or_default() {
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

        let mut builder = ClientBuilder::new()
            .default_headers(default_headers.clone())
            // M10: bound the TCP/TLS connect and the per-request round-trip so a
            // stalled / half-open front cannot pin the probe (and later POSTs)
            // indefinitely.
            .connect_timeout(MEEK_CONNECT_TIMEOUT)
            .timeout(MEEK_REQUEST_TIMEOUT);
        // When an explicit `sni` override rewrote the dial host, pin that name
        // to the real host's resolved address so DNS still targets the front.
        if let Some((sni_host, real_host, port)) = &plan.resolve {
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((real_host.as_str(), *port))
                .await
                .map_err(|e| ObfsError::Handshake(format!("meek resolve {real_host}:{port}: {e}")))?
                .collect();
            if addrs.is_empty() {
                return Err(ObfsError::Handshake(format!(
                    "meek resolve {real_host}:{port}: no addresses"
                ))
                .into());
            }
            builder = builder.resolve_to_addrs(sni_host, &addrs);
        }
        let client = builder
            // meek explicitly does NOT pool connections — each POST is
            // independent. But reqwest pools by default; that's still
            // wire-compatible with meek-server.
            .build()
            .map_err(|e| ObfsError::Handshake(format!("reqwest: {e}")))?;

        // Probe: emit an empty POST so configuration errors surface
        // before the SSH layer commits. A 2xx response is required.
        let probe = client
            .post(&plan.dial_url)
            .body(Vec::<u8>::new())
            .send()
            .await
            .map_err(|e| ObfsError::Handshake(format!("meek probe: {e}")))?;
        let status = probe.status().as_u16();
        if !(200..300).contains(&status) {
            tracing::warn!(
                transport = "meek-http",
                http_status = status,
                reason = "front-non-2xx",
                "meek-http handshake rejected: front returned non-2xx status"
            );
            return Err(
                ObfsError::Handshake(format!("meek-http front returned HTTP {status}")).into(),
            );
        }
        let initial_body = read_body_capped(probe, MAX_MEEK_BODY_BYTES)
            .await
            .map_err(|e| ObfsError::Handshake(format!("meek body: {e}")))?;

        let stream = MeekStream::new(client, plan.dial_url, default_headers, initial_body);
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
    /// In-flight keepalive/read POST. Kept SEPARATE from `write_in_flight`
    /// (HIGH-2b): sharing one slot meant a `poll_write` issued while a read POST
    /// was pending would poll the read future and report the write as sent
    /// WITHOUT ever transmitting the payload — silent outbound data loss.
    read_in_flight: Option<PostFuture>,
    /// In-flight write POST carrying outbound bytes (independent of reads).
    write_in_flight: Option<PostFuture>,
    /// Backoff timer armed after an empty poll response so the next keepalive
    /// POST is spaced out by `MEEK_POLL_INTERVAL` instead of busy-looping.
    read_backoff: Option<Pin<Box<tokio::time::Sleep>>>,
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
            read_in_flight: None,
            write_in_flight: None,
            read_backoff: None,
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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.rx_buf.is_empty() {
                let n = buf.remaining().min(this.rx_buf.len());
                let drained: Vec<u8> = this.rx_buf.drain(..n).collect();
                buf.put_slice(&drained);
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(())); // EOF
            }
            // If we're backing off after an empty poll response, wait out the
            // interval before issuing the next keepalive POST.
            if let Some(backoff) = this.read_backoff.as_mut() {
                match backoff.as_mut().poll(cx) {
                    Poll::Ready(()) => {
                        this.read_backoff = None;
                    }
                    Poll::Pending => return Poll::Pending,
                }
            }
            if this.read_in_flight.is_none() {
                // Issue an empty-body keepalive POST to fetch downstream
                // bytes from the meek server.
                let f = this.issue_post(Vec::new());
                this.read_in_flight = Some(f);
            }
            // Poll the in-flight read future.
            let fut = this.read_in_flight.as_mut().unwrap();
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(bytes)) => {
                    this.read_in_flight = None;
                    if bytes.is_empty() {
                        // HIGH-2a: an empty response is NOT EOF — the meek
                        // session is idle-but-open. Arm a short backoff and
                        // retry on the next loop turn rather than filling zero
                        // bytes (which `copy_one`/`tokio::io::copy` would read
                        // as EOF and half-close the tunnel).
                        this.read_backoff = Some(Box::pin(tokio::time::sleep(MEEK_POLL_INTERVAL)));
                        continue;
                    }
                    this.rx_buf = bytes;
                }
                Poll::Ready(Err(e)) => {
                    this.read_in_flight = None;
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for MeekStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        // Single-flight write on a DEDICATED slot (HIGH-2b): a concurrently
        // pending read POST must not swallow this write. The write issues its
        // own POST carrying `data`; on re-poll (after `Pending`) the same
        // in-flight future is polled, so `data` is transmitted exactly once.
        if this.write_in_flight.is_none() {
            let f = this.issue_post(data.to_vec());
            this.write_in_flight = Some(f);
        }
        let fut = this.write_in_flight.as_mut().unwrap();
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(bytes)) => {
                this.write_in_flight = None;
                this.rx_buf.extend_from_slice(&bytes);
                Poll::Ready(Ok(data.len()))
            }
            Poll::Ready(Err(e)) => {
                this.write_in_flight = None;
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
    fn plan_sni_no_override_dials_url_unchanged() {
        // No override (SNI == URL host): the dial URL is untouched and no
        // resolve() pin is needed — behaviour is byte-for-byte preserved.
        let plan = plan_sni("https://front.cdn.example/path", "front.cdn.example").unwrap();
        assert_eq!(plan.dial_url, "https://front.cdn.example/path");
        assert!(plan.resolve.is_none());
    }

    #[test]
    fn plan_sni_override_rewrites_dial_host_and_pins_real_host() {
        // A configured `meek.sni` distinct from the URL host becomes the dial
        // URL host (which drives the TLS `ClientHello` SNI), while the original
        // host/port is preserved for a resolve() pin so the socket still
        // reaches the real front.
        let plan = plan_sni("https://front.cdn.example/path", "third.example").unwrap();
        assert_eq!(
            url::Url::parse(&plan.dial_url).unwrap().host_str(),
            Some("third.example"),
            "dial URL host (TLS SNI) must be the configured meek.sni"
        );
        assert_eq!(
            plan.resolve,
            Some((
                "third.example".to_owned(),
                "front.cdn.example".to_owned(),
                443
            ))
        );
    }

    #[test]
    fn configured_sni_becomes_dial_sni() {
        // End-to-end wiring: the transport's `sni()` override flows into the
        // plan `connect()` uses, so the SNI advertised on the wire is the
        // configured `meek.sni` — not the URL host (finding 7). The Host header
        // still targets the hidden origin.
        let cfg = ObfsConfig::MeekHttp {
            url: "https://front.cdn.example/p".into(),
            front_host: Some("hidden.example".into()),
            sni: Some("sni.example".into()),
        };
        let t = MeekHttpTransport::new(cfg, Arc::new(NoopAuditHook)).unwrap();
        assert_eq!(t.sni(), "sni.example");
        let plan = plan_sni(t.url(), &t.sni()).unwrap();
        assert_eq!(
            url::Url::parse(&plan.dial_url).unwrap().host_str(),
            Some("sni.example"),
            "meek.sni override must drive the TLS SNI"
        );
        assert_eq!(t.host_header(), "hidden.example");
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
