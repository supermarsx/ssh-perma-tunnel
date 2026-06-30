//! Generic HTTPS sink (POST / REST). Used directly for `http`/`webhook_post`
//! sinks and as the transport-trait for `sms` / `push` adapters.

use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::event::Event;
use crate::sinks::{Sink, SinkError};
use crate::template;

/// Authentication mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum HttpAuth {
    /// No auth header.
    #[default]
    None,
    /// `Authorization: Bearer <token>`.
    Bearer(String),
    /// `Authorization: Basic <base64(user:pass)>` (caller pre-encodes).
    Basic(String),
}

/// Outbound HTTPS request prepared by [`HttpSink`].
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub content_type: String,
    pub body: Vec<u8>,
    pub auth: HttpAuth,
    /// Extra request headers (in addition to `Content-Type` / `Authorization`
    /// already derived from the fields above). Used by the WebPush sink to
    /// attach `TTL`, `Urgency`, `Content-Encoding: aes128gcm`, and the VAPID
    /// `Authorization: vapid t=…, k=…` value.
    #[doc(hidden)]
    pub extra_headers: Vec<(String, String)>,
}

/// Pick the template-escape context for a body from its `Content-Type`.
///
/// JSON bodies escape substituted values as JSON string content;
/// `x-www-form-urlencoded` bodies form-encode them; anything else (e.g.
/// `text/plain`) substitutes verbatim. The match is on the media-type token
/// only (parameters such as `; charset=utf-8` are ignored) and is
/// case-insensitive.
#[must_use]
fn body_escape_for(content_type: &str) -> template::EscapeMode {
    let media = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    if media.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        template::EscapeMode::Form
    } else if media.eq_ignore_ascii_case("application/json")
        || media.to_ascii_lowercase().ends_with("+json")
        || media.eq_ignore_ascii_case("text/json")
    {
        template::EscapeMode::JsonString
    } else {
        template::EscapeMode::None
    }
}

/// HTTP transport trait — implemented by reqwest for production, mocked in
/// tests.
#[async_trait]
pub trait HttpTransport: Send + Sync {
    async fn send(&self, req: HttpRequest) -> Result<(), SinkError>;
}

/// HTTPS sink (POST/PUT/etc) with optional bearer/basic auth and a
/// templated JSON body.
pub struct HttpSink {
    name: String,
    method: String,
    url_template: String,
    body_template: String,
    content_type: String,
    auth: HttpAuth,
    transport: Arc<dyn HttpTransport>,
}

impl HttpSink {
    /// Create a new HTTPS sink. `body_template` is rendered through
    /// [`template::render_template`] before each delivery.
    pub fn new(
        name: impl Into<String>,
        method: impl Into<String>,
        url_template: impl Into<String>,
        body_template: impl Into<String>,
        content_type: impl Into<String>,
        auth: HttpAuth,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            name: name.into(),
            method: method.into(),
            url_template: url_template.into(),
            body_template: body_template.into(),
            content_type: content_type.into(),
            auth,
            transport,
        }
    }
}

#[async_trait]
impl Sink for HttpSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "http"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        // URL-destined field values are percent-encoded so they cannot inject
        // query/path structure (host/scheme come from operator literal text).
        let (url, _) = template::render_template_escaped(
            &self.url_template,
            &event,
            template::EscapeMode::Url,
        );
        // Body values are escaped for the declared content type: JSON string
        // escaping for JSON bodies, form-encoding for x-www-form-urlencoded,
        // verbatim otherwise (e.g. text/plain).
        let (body, _) = template::render_template_escaped(
            &self.body_template,
            &event,
            body_escape_for(&self.content_type),
        );
        let req = HttpRequest {
            method: self.method.clone(),
            url,
            content_type: self.content_type.clone(),
            body: body.into_bytes(),
            auth: self.auth.clone(),
            extra_headers: Vec::new(),
        };
        self.transport.send(req).await
    }
}

/// Real HTTPS transport via `reqwest`. Available when `transports` feature
/// is on (default).
#[cfg(feature = "transports")]
pub mod reqwest_transport {
    use super::{HttpAuth, HttpRequest, HttpTransport, SinkError};
    use async_trait::async_trait;
    use reqwest::header::{HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
    use reqwest::redirect::Policy;
    use reqwest::{Client, Method};
    use std::net::IpAddr;
    use std::time::Duration;

    /// Maximum number of redirect hops to follow before giving up.
    const MAX_REDIRECTS: usize = 10;

    /// Decision for one redirect hop, kept separate from the reqwest
    /// `redirect::Action` so it can be unit-tested without a live server.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) enum RedirectDecision {
        /// Safe to follow this hop.
        Follow,
        /// Too many hops — stop following (let reqwest surface the last
        /// response).
        Stop,
        /// Reject: the target downgrades to a non-`https` scheme.
        BlockScheme,
        /// Reject: the target host is a private / loopback / link-local /
        /// cloud-metadata IP literal (SSRF guard).
        BlockPrivateIp,
    }

    /// Classify whether a redirect target may be followed.
    ///
    /// SSRF guard for compromised/malicious webhook or push endpoints: a
    /// `302` to `http://169.254.169.254/…` (or any private/loopback/link-local
    /// IP) would bypass the pinned-TLS connector and reach the cloud-metadata
    /// service or an internal host. We therefore:
    ///
    /// * reject any redirect that is not `https` (no http downgrade), and
    /// * reject any redirect whose host is an IP literal in a
    ///   private/loopback/link-local/unspecified range (which includes the
    ///   `169.254.169.254` and `fd00:ec2::254` metadata addresses).
    ///
    /// Hostname targets are not resolved here (no synchronous DNS in the
    /// redirect callback); the IP-literal block is what stops the documented
    /// metadata-IP pivot. The *initial* request host is intentionally NOT
    /// subject to the private-IP block — the operator chose that URL, so a
    /// legitimate internal webhook keeps working; only redirect *targets* are
    /// validated.
    pub(crate) fn classify_redirect(url: &reqwest::Url, previous_hops: usize) -> RedirectDecision {
        if previous_hops >= MAX_REDIRECTS {
            return RedirectDecision::Stop;
        }
        if !url.scheme().eq_ignore_ascii_case("https") {
            return RedirectDecision::BlockScheme;
        }
        match url.host() {
            Some(url::Host::Ipv4(ip)) => {
                if ip_is_blocked(IpAddr::V4(ip)) {
                    return RedirectDecision::BlockPrivateIp;
                }
            }
            Some(url::Host::Ipv6(ip)) => {
                if ip_is_blocked(IpAddr::V6(ip)) {
                    return RedirectDecision::BlockPrivateIp;
                }
            }
            // Domain (resolved later by the connector) or no host: allowed
            // through the https gate above.
            _ => {}
        }
        RedirectDecision::Follow
    }

    /// Whether an IP literal is in a range we refuse to be redirected to.
    /// Canonicalizes IPv4-mapped IPv6 (`::ffff:a.b.c.d`) first so the mapped
    /// metadata address cannot slip past the v4 checks.
    fn ip_is_blocked(ip: IpAddr) -> bool {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local() // 169.254.0.0/16 incl. metadata IP
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    // RFC 6598 shared / CGNAT space 100.64.0.0/10.
                    || {
                        let o = v4.octets();
                        o[0] == 100 && (o[1] & 0xc0) == 64
                    }
            }
            IpAddr::V6(v6) => {
                let seg = v6.segments();
                v6.is_loopback()
                    || v6.is_unspecified()
                    || (seg[0] & 0xfe00) == 0xfc00 // unique-local fc00::/7
                    || (seg[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
            }
        }
    }

    /// Build the SSRF-aware redirect policy applied to every constructed
    /// client: https-only hops, bounded count, no private/metadata IP target.
    fn ssrf_redirect_policy() -> Policy {
        Policy::custom(
            |attempt| match classify_redirect(attempt.url(), attempt.previous().len()) {
                RedirectDecision::Follow => attempt.follow(),
                RedirectDecision::Stop => attempt.stop(),
                RedirectDecision::BlockScheme => {
                    attempt.error("blocked redirect: non-https scheme (http downgrade)".to_string())
                }
                RedirectDecision::BlockPrivateIp => attempt.error(
                    "blocked redirect: target is a private/loopback/link-local/metadata IP"
                        .to_string(),
                ),
            },
        )
    }

    /// reqwest-backed transport. Construct once and reuse for many sinks.
    pub struct ReqwestTransport {
        client: Client,
    }

    impl ReqwestTransport {
        /// Build with a per-request timeout.
        pub fn new(timeout: Duration) -> Result<Self, SinkError> {
            Self::with_pin(timeout, &[], false, None)
        }

        /// Build with pinned-TLS parameters (t5-e2). The pin set, the
        /// `allow_self_signed` flag, and the chain-depth cap come straight
        /// from the per-sink config. Non-empty `pin_strings` enforces
        /// SPKI-SHA256 pinning against the leaf; `allow_self_signed=true`
        /// requires a non-empty pin set (the underlying builder refuses
        /// to disable verification entirely).
        pub fn with_pin(
            timeout: Duration,
            pin_strings: &[String],
            allow_self_signed: bool,
            max_cert_chain_depth: Option<u32>,
        ) -> Result<Self, SinkError> {
            let rustls_cfg = spt_trust::PinnedTlsConnector::from_config_parts(
                pin_strings,
                allow_self_signed,
                max_cert_chain_depth,
            )
            .map_err(|e| SinkError::Config(format!("pinned tls: {e}")))?;
            let cfg_inner = (*rustls_cfg).clone();
            let client = Client::builder()
                .use_preconfigured_tls(cfg_inner)
                .timeout(timeout)
                // SSRF guard: bound + re-validate every redirect hop (https
                // only, no private/loopback/link-local/metadata IP target).
                .redirect(ssrf_redirect_policy())
                .build()
                .map_err(|e| SinkError::Config(format!("reqwest: {e}")))?;
            Ok(Self { client })
        }

        /// Use a pre-built `reqwest::Client`.
        #[must_use]
        pub fn from_client(client: Client) -> Self {
            Self { client }
        }
    }

    #[async_trait]
    impl HttpTransport for ReqwestTransport {
        async fn send(&self, req: HttpRequest) -> Result<(), SinkError> {
            let method = Method::from_bytes(req.method.as_bytes())
                .map_err(|e| SinkError::Config(format!("method: {e}")))?;
            let mut rb = self.client.request(method, &req.url).body(req.body);
            if let Ok(ct) = HeaderValue::from_str(&req.content_type) {
                rb = rb.header(CONTENT_TYPE, ct);
            }
            match req.auth {
                HttpAuth::None => {}
                HttpAuth::Bearer(t) => {
                    if let Ok(v) = HeaderValue::from_str(&format!("Bearer {t}")) {
                        rb = rb.header(AUTHORIZATION, v);
                    }
                }
                HttpAuth::Basic(t) => {
                    if let Ok(v) = HeaderValue::from_str(&format!("Basic {t}")) {
                        rb = rb.header(AUTHORIZATION, v);
                    }
                }
            }
            for (name, value) in &req.extra_headers {
                if let (Ok(n), Ok(v)) = (
                    HeaderName::from_bytes(name.as_bytes()),
                    HeaderValue::from_str(value),
                ) {
                    rb = rb.header(n, v);
                }
            }
            let resp = rb
                .send()
                .await
                .map_err(|e| SinkError::Transient(format!("reqwest: {e}")))?;
            if resp.status().is_success() {
                Ok(())
            } else if resp.status().is_server_error() {
                Err(SinkError::Transient(format!(
                    "http {}: server error",
                    resp.status()
                )))
            } else {
                Err(SinkError::Permanent(format!(
                    "http {}: client error",
                    resp.status()
                )))
            }
        }
    }
}

/// Stub transport that never makes network IO — records every request to a
/// `parking_lot::Mutex<Vec<HttpRequest>>`. Used by tests in this crate plus
/// downstream crates that want to assert on what would be sent.
#[derive(Default)]
pub struct RecordingTransport {
    pub recorded: parking_lot::Mutex<Vec<HttpRequest>>,
    pub fail_with: parking_lot::Mutex<Option<SinkError>>,
}

impl RecordingTransport {
    /// New empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Tell the next call to fail with this error (consumed once).
    pub fn fail_once(&self, err: SinkError) {
        *self.fail_with.lock() = Some(err);
    }

    /// Snapshot of recorded requests.
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.recorded.lock().clone()
    }
}

#[async_trait]
impl HttpTransport for RecordingTransport {
    async fn send(&self, req: HttpRequest) -> Result<(), SinkError> {
        if let Some(err) = self.fail_with.lock().take() {
            return Err(err);
        }
        self.recorded.lock().push(req);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_renders_template_and_calls_transport() {
        let t = Arc::new(RecordingTransport::new());
        let sink = HttpSink::new(
            "alerts",
            "POST",
            "https://example.com/alerts/{{kind}}",
            r#"{"profile":"{{profile_id}}","msg":"{{message}}"}"#,
            "application/json",
            HttpAuth::Bearer("xyz".into()),
            t.clone(),
        );

        let ev = Event::builder("profile.failed", Severity::Error)
            .profile(spt_core::ProfileId::new("p1").unwrap())
            .message("boom")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();

        let r = t.requests();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].url, "https://example.com/alerts/profile.failed");
        let body = std::str::from_utf8(&r[0].body).unwrap();
        assert!(body.contains("p1"));
        assert!(body.contains("boom"));
        assert_eq!(r[0].auth, HttpAuth::Bearer("xyz".into()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transient_error_is_retryable() {
        let t = Arc::new(RecordingTransport::new());
        t.fail_once(SinkError::Transient("network".into()));
        let sink = HttpSink::new(
            "x",
            "POST",
            "https://x/",
            "{}",
            "application/json",
            HttpAuth::None,
            t.clone(),
        );
        let ev = Event::builder("k", Severity::Info).build();
        let err = sink.deliver(Arc::new(ev)).await.unwrap_err();
        assert!(err.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn permanent_error_is_not_retryable() {
        let t = Arc::new(RecordingTransport::new());
        t.fail_once(SinkError::Permanent("bad-request".into()));
        let sink = HttpSink::new(
            "x",
            "POST",
            "https://x/",
            "{}",
            "application/json",
            HttpAuth::None,
            t.clone(),
        );
        let err = sink
            .deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap_err();
        assert!(!err.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn name_kind_are_stable() {
        let sink = HttpSink::new(
            "alerts",
            "POST",
            "https://x/",
            "{}",
            "application/json",
            HttpAuth::None,
            Arc::new(RecordingTransport::new()),
        );
        assert_eq!(sink.name(), "alerts");
        assert_eq!(sink.kind(), "http");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_auth_default_is_none() {
        assert!(matches!(HttpAuth::default(), HttpAuth::None));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_auth_basic_round_trips() {
        let a = HttpAuth::Basic("dXNlcjpwYXNz".into());
        let b = HttpAuth::Basic("dXNlcjpwYXNz".into());
        assert_eq!(a, b);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_auth_round_trips_through_serde_json() {
        for auth in [
            HttpAuth::None,
            HttpAuth::Bearer("xyz".into()),
            HttpAuth::Basic("ZA==".into()),
        ] {
            let s = serde_json::to_string(&auth).unwrap();
            let back: HttpAuth = serde_json::from_str(&s).unwrap();
            assert_eq!(auth, back);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn basic_auth_propagates_to_request() {
        let t = Arc::new(RecordingTransport::new());
        let sink = HttpSink::new(
            "x",
            "POST",
            "https://x/",
            "{}",
            "application/json",
            HttpAuth::Basic("ZA==".into()),
            t.clone(),
        );
        sink.deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap();
        let req = &t.requests()[0];
        assert_eq!(req.auth, HttpAuth::Basic("ZA==".into()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn content_type_is_propagated() {
        let t = Arc::new(RecordingTransport::new());
        let sink = HttpSink::new(
            "x",
            "PUT",
            "https://x/",
            "x=1",
            "application/x-www-form-urlencoded",
            HttpAuth::None,
            t.clone(),
        );
        sink.deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap();
        let req = &t.requests()[0];
        assert_eq!(req.method, "PUT");
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
        assert_eq!(req.body, b"x=1");
        assert!(req.extra_headers.is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recording_transport_default_constructs() {
        let t: RecordingTransport = RecordingTransport::default();
        assert!(t.requests().is_empty());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn http_request_is_cloneable() {
        let r = HttpRequest {
            method: "POST".into(),
            url: "https://x/".into(),
            content_type: "application/json".into(),
            body: b"{}".to_vec(),
            auth: HttpAuth::Bearer("t".into()),
            extra_headers: vec![("X-Trace".into(), "1".into())],
        };
        let r2 = r.clone();
        assert_eq!(r2.url, r.url);
        assert_eq!(r2.body, r.body);
        assert_eq!(r2.extra_headers, r.extra_headers);
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn reqwest_transport_new_succeeds() {
        let t = reqwest_transport::ReqwestTransport::new(std::time::Duration::from_secs(1));
        assert!(t.is_ok());
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn reqwest_transport_from_client_constructs() {
        let client = reqwest::Client::new();
        let _ = reqwest_transport::ReqwestTransport::from_client(client);
    }

    // ---------- t5-e2: PinnedTlsConnector wiring -----------------

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn reqwest_transport_with_pin_empty_set_succeeds() {
        // Empty pin set + default flag + None cap = strict system roots
        // routed through the pinned connector. Builds cleanly.
        let t = reqwest_transport::ReqwestTransport::with_pin(
            std::time::Duration::from_secs(1),
            &[],
            false,
            None,
        );
        assert!(t.is_ok(), "with_pin empty failed: {:?}", t.err());
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn reqwest_transport_with_pin_self_signed_without_pin_rejects() {
        // allow_self_signed=true with empty pin set must be rejected by
        // the PinnedTlsConnector builder.
        let t = reqwest_transport::ReqwestTransport::with_pin(
            std::time::Duration::from_secs(1),
            &[],
            true,
            None,
        );
        assert!(t.is_err(), "expected pin-set requirement to reject");
    }

    // ---------- body content-type escape selection -----------------

    #[tokio::test(flavor = "current_thread")]
    async fn body_escape_for_selects_by_content_type() {
        use super::body_escape_for;
        use crate::template::EscapeMode;
        assert_eq!(body_escape_for("application/json"), EscapeMode::JsonString);
        assert_eq!(
            body_escape_for("application/json; charset=utf-8"),
            EscapeMode::JsonString
        );
        assert_eq!(
            body_escape_for("application/vnd.api+json"),
            EscapeMode::JsonString
        );
        assert_eq!(
            body_escape_for("application/x-www-form-urlencoded"),
            EscapeMode::Form
        );
        assert_eq!(body_escape_for("text/plain"), EscapeMode::None);
    }

    /// End-to-end through the sink: an attacker-influenced `message` field with
    /// embedded quotes and an `"admin":true` payload must NOT inject keys —
    /// the delivered JSON body parses with `msg` as a plain string.
    #[tokio::test(flavor = "current_thread")]
    async fn http_json_body_injection_is_neutralised() {
        let t = Arc::new(RecordingTransport::new());
        let sink = HttpSink::new(
            "alerts",
            "POST",
            "https://example.com/hook",
            r#"{"msg":"{{message}}"}"#,
            "application/json",
            HttpAuth::None,
            t.clone(),
        );
        let ev = Event::builder("k", Severity::Error)
            .message(r#"pwn","admin":true,"x":""#)
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let body = t.requests()[0].body.clone();
        let v: serde_json::Value = serde_json::from_slice(&body).expect("body must parse as JSON");
        assert!(v.get("admin").is_none(), "key injected: {v}");
        assert!(v["msg"].is_string());
        assert_eq!(v.as_object().unwrap().len(), 1);
    }

    /// A URL-context field value cannot inject query parameters.
    #[tokio::test(flavor = "current_thread")]
    async fn http_url_value_is_percent_encoded() {
        let t = Arc::new(RecordingTransport::new());
        let sink = HttpSink::new(
            "alerts",
            "GET",
            "https://example.com/p/{{message}}",
            "{}",
            "application/json",
            HttpAuth::None,
            t.clone(),
        );
        let ev = Event::builder("k", Severity::Info)
            .message("a&evil=1")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        assert_eq!(t.requests()[0].url, "https://example.com/p/a%26evil%3D1");
    }

    // ---------- SSRF redirect guard (classify_redirect) -------------

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn classify_redirect_blocks_metadata_ip() {
        use super::reqwest_transport::{classify_redirect, RedirectDecision};
        let u = reqwest::Url::parse("https://169.254.169.254/latest/meta-data/").unwrap();
        assert_eq!(classify_redirect(&u, 0), RedirectDecision::BlockPrivateIp);
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn classify_redirect_blocks_http_downgrade() {
        use super::reqwest_transport::{classify_redirect, RedirectDecision};
        let u = reqwest::Url::parse("http://example.com/ok").unwrap();
        assert_eq!(classify_redirect(&u, 0), RedirectDecision::BlockScheme);
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn classify_redirect_blocks_private_and_loopback() {
        use super::reqwest_transport::{classify_redirect, RedirectDecision};
        for host in [
            "https://10.0.0.5/x",
            "https://192.168.1.1/x",
            "https://172.16.0.1/x",
            "https://127.0.0.1/x",
            "https://[::1]/x",
            "https://[fd00::1]/x",  // unique-local
            "https://[fe80::1]/x",  // link-local
            "https://100.64.0.1/x", // CGNAT shared space
        ] {
            let u = reqwest::Url::parse(host).unwrap();
            assert_eq!(
                classify_redirect(&u, 0),
                RedirectDecision::BlockPrivateIp,
                "host {host} should be blocked"
            );
        }
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn classify_redirect_blocks_ipv4_mapped_metadata() {
        use super::reqwest_transport::{classify_redirect, RedirectDecision};
        // IPv4-mapped IPv6 form of the metadata IP must canonicalize + block.
        let u = reqwest::Url::parse("https://[::ffff:169.254.169.254]/x").unwrap();
        assert_eq!(classify_redirect(&u, 0), RedirectDecision::BlockPrivateIp);
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn classify_redirect_allows_public_https_and_domains() {
        use super::reqwest_transport::{classify_redirect, RedirectDecision};
        for host in [
            "https://example.com/ok",
            "https://8.8.8.8/ok",
            "https://hooks.slack.com/services/x",
        ] {
            let u = reqwest::Url::parse(host).unwrap();
            assert_eq!(
                classify_redirect(&u, 0),
                RedirectDecision::Follow,
                "host {host} should be allowed"
            );
        }
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn classify_redirect_stops_after_max_hops() {
        use super::reqwest_transport::{classify_redirect, RedirectDecision};
        let u = reqwest::Url::parse("https://example.com/ok").unwrap();
        assert_eq!(classify_redirect(&u, 10), RedirectDecision::Stop);
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn reqwest_transport_with_pin_explicit_pin_builds() {
        // A well-formed SHA256:b64 pin together with allow_self_signed
        // builds successfully (the pin set is non-empty).
        let pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let t = reqwest_transport::ReqwestTransport::with_pin(
            std::time::Duration::from_secs(1),
            &[pin],
            true,
            Some(5),
        );
        assert!(t.is_ok(), "with_pin pinned mode failed: {:?}", t.err());
    }
}
