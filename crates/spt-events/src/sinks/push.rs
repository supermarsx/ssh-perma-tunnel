//! Push-notification sinks.
//!
//! Two flavours:
//!
//! * [`PushSink`] — generic webhook: POSTs a templated JSON body to the
//!   configured URL. Use when the receiver is a custom backend that does
//!   its own fan-out / encryption (e.g. an internal mobile push gateway).
//!
//! * [`WebPushSink`] — RFC 8030 / RFC 8291 / RFC 8292 Web Push. Encrypts a
//!   templated payload with `aes128gcm` content-encoding using ECDH P-256
//!   key agreement against each subscription's `p256dh` key + `auth`
//!   secret, and signs a VAPID ES256 JWT for the `Authorization` header.
//!   Posts to each subscription endpoint independently — failure of one
//!   subscription does not block the others.
//!
//! Both sinks share the same [`HttpTransport`] so unit tests can substitute
//! a `RecordingTransport`. Real network IO goes through
//! [`super::http::reqwest_transport::ReqwestTransport`] when the
//! `transports` feature is on (default).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64ct::{Base64UrlUnpadded, Encoding};
use web_push_native::jwt_simple::algorithms::ES256KeyPair;
use web_push_native::p256::PublicKey;
use web_push_native::{Auth, WebPushBuilder};

use crate::event::Event;
use crate::sinks::http::{HttpAuth, HttpRequest, HttpTransport};
use crate::sinks::{Sink, SinkError};
use crate::template;

// --------------------------------------------------------------------- Push

/// Generic push-notification sink (templated JSON POST). For full Web Push
/// see [`WebPushSink`].
pub struct PushSink {
    name: String,
    url: String,
    body_template: String,
    auth: HttpAuth,
    transport: Arc<dyn HttpTransport>,
}

impl PushSink {
    /// Construct.
    pub fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        body_template: impl Into<String>,
        auth: HttpAuth,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            name: name.into(),
            url: url.into(),
            body_template: body_template.into(),
            auth,
            transport,
        }
    }
}

#[async_trait]
impl Sink for PushSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "push"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        let (body, _) = template::render_template(&self.body_template, &event);
        self.transport
            .send(HttpRequest {
                method: "POST".into(),
                url: self.url.clone(),
                content_type: "application/json".into(),
                body: body.into_bytes(),
                auth: HttpAuth::None,
                extra_headers: match &self.auth {
                    HttpAuth::None => Vec::new(),
                    HttpAuth::Bearer(t) => {
                        vec![("Authorization".into(), format!("Bearer {t}"))]
                    }
                    HttpAuth::Basic(t) => {
                        vec![("Authorization".into(), format!("Basic {t}"))]
                    }
                },
            })
            .await
    }
}

// ------------------------------------------------------------------ WebPush

/// Push-message urgency per RFC 8030 §5.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    VeryLow,
    Low,
    Normal,
    High,
}

impl Urgency {
    fn as_str(self) -> &'static str {
        match self {
            Self::VeryLow => "very-low",
            Self::Low => "low",
            Self::Normal => "normal",
            Self::High => "high",
        }
    }
}

/// A single Web Push subscription as obtained from a browser's
/// `pushManager.subscribe`. All fields use base64url (no padding) wire
/// encoding except `endpoint`.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Subscription endpoint URL provided by the push service.
    pub endpoint: String,
    /// User-agent ECDH P-256 public key, base64url-no-padding.
    pub p256dh_key: String,
    /// User-agent auth secret (16 bytes), base64url-no-padding.
    pub auth_secret: String,
}

/// Errors specific to constructing a [`WebPushSink`] or its subscriptions.
#[derive(Debug, thiserror::Error)]
pub enum WebPushConfigError {
    /// Failed to parse the subscription endpoint URL.
    #[error("invalid endpoint URL: {0}")]
    Endpoint(String),
    /// Failed to parse the subscription's P-256 public key.
    #[error("invalid p256dh key: {0}")]
    P256dh(String),
    /// Failed to parse the subscription's auth secret.
    #[error("invalid auth secret: {0}")]
    Auth(String),
    /// Failed to load / parse the VAPID ES256 keypair.
    #[error("invalid vapid private key: {0}")]
    VapidKey(String),
}

impl From<WebPushConfigError> for SinkError {
    fn from(err: WebPushConfigError) -> Self {
        SinkError::Config(err.to_string())
    }
}

/// VAPID identity used to sign requests sent to subscription endpoints.
///
/// `subject` SHOULD be a `mailto:` URL or the origin URL of the push
/// application server, per RFC 8292 §2.1.
#[derive(Clone)]
pub struct VapidIdentity {
    /// Raw 32-byte ES256 private key (base64url-no-padding when persisted).
    /// Wrapped in `Arc` so cloning the identity does not duplicate the
    /// keypair material.
    keypair: Arc<ES256KeyPair>,
    subject: String,
}

impl std::fmt::Debug for VapidIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VapidIdentity")
            .field("subject", &self.subject)
            .field("keypair", &"<redacted>")
            .finish()
    }
}

impl VapidIdentity {
    /// Build from a base64url-no-padding-encoded 32-byte private scalar
    /// and a contact `mailto:` / origin URL.
    pub fn from_base64url(
        private_key_b64url: &str,
        subject: impl Into<String>,
    ) -> Result<Self, WebPushConfigError> {
        let raw = Base64UrlUnpadded::decode_vec(private_key_b64url)
            .map_err(|e| WebPushConfigError::VapidKey(e.to_string()))?;
        let kp = ES256KeyPair::from_bytes(&raw)
            .map_err(|e| WebPushConfigError::VapidKey(e.to_string()))?;
        Ok(Self {
            keypair: Arc::new(kp),
            subject: subject.into(),
        })
    }

    /// Subject (contact) used in the VAPID JWT `sub` claim.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// Web Push notification sink.
///
/// Holds a set of [`Subscription`]s and a [`VapidIdentity`]. On each event,
/// renders the body template, encrypts the rendered bytes once per
/// subscription (each subscription has its own `p256dh`/`auth`), and POSTs
/// the resulting `aes128gcm` payload via the [`HttpTransport`].
///
/// Per-subscription failures are aggregated: the sink succeeds if at least
/// one subscription accepted the message. If every subscription fails,
/// the most-retryable error class (Transient > Permanent > Config) is
/// returned so the dispatcher can decide whether to spool.
pub struct WebPushSink {
    name: String,
    body_template: String,
    subscriptions: Vec<Subscription>,
    vapid: VapidIdentity,
    ttl: Duration,
    urgency: Urgency,
    topic: Option<String>,
    transport: Arc<dyn HttpTransport>,
}

impl WebPushSink {
    /// Construct.
    pub fn new(
        name: impl Into<String>,
        body_template: impl Into<String>,
        subscriptions: Vec<Subscription>,
        vapid: VapidIdentity,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            name: name.into(),
            body_template: body_template.into(),
            subscriptions,
            vapid,
            ttl: Duration::from_secs(12 * 60 * 60),
            urgency: Urgency::Normal,
            topic: None,
            transport,
        }
    }

    /// Override the default 12-hour TTL.
    #[must_use]
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Override the default `normal` urgency.
    #[must_use]
    pub fn with_urgency(mut self, urgency: Urgency) -> Self {
        self.urgency = urgency;
        self
    }

    /// Set a `Topic` header (RFC 8030 §5.4) to coalesce updates.
    #[must_use]
    pub fn with_topic(mut self, topic: impl Into<String>) -> Self {
        self.topic = Some(topic.into());
        self
    }

    /// Build the encrypted HTTP request for a single subscription, ready to
    /// hand to the transport.
    fn build_request(
        &self,
        sub: &Subscription,
        plaintext: &[u8],
    ) -> Result<HttpRequest, SinkError> {
        let endpoint_uri: http::Uri = sub
            .endpoint
            .parse()
            .map_err(|e: http::uri::InvalidUri| {
                SinkError::Config(WebPushConfigError::Endpoint(e.to_string()).to_string())
            })?;

        let p256dh_bytes = Base64UrlUnpadded::decode_vec(&sub.p256dh_key)
            .map_err(|e| SinkError::Config(WebPushConfigError::P256dh(e.to_string()).to_string()))?;
        let ua_public = PublicKey::from_sec1_bytes(&p256dh_bytes)
            .map_err(|e| SinkError::Config(WebPushConfigError::P256dh(e.to_string()).to_string()))?;

        let auth_bytes = Base64UrlUnpadded::decode_vec(&sub.auth_secret)
            .map_err(|e| SinkError::Config(WebPushConfigError::Auth(e.to_string()).to_string()))?;
        if auth_bytes.len() != 16 {
            return Err(SinkError::Config(
                WebPushConfigError::Auth(format!(
                    "expected 16 bytes, got {}",
                    auth_bytes.len()
                ))
                .to_string(),
            ));
        }
        let ua_auth = Auth::clone_from_slice(&auth_bytes);

        let request = WebPushBuilder::new(endpoint_uri, ua_public, ua_auth)
            .with_valid_duration(self.ttl)
            .with_vapid(&self.vapid.keypair, &self.vapid.subject)
            .build(plaintext.to_vec())
            .map_err(|e| SinkError::Permanent(format!("webpush build: {e}")))?;

        let (parts, body) = request.into_parts();

        let mut extra: Vec<(String, String)> = Vec::with_capacity(parts.headers.len() + 2);
        let mut content_type = "application/octet-stream".to_string();
        for (name, value) in &parts.headers {
            let n = name.as_str();
            // Skip headers we represent through dedicated HttpRequest fields
            // (or the transport adds for us).
            if n.eq_ignore_ascii_case("content-type") {
                if let Ok(v) = value.to_str() {
                    content_type = v.to_string();
                }
                continue;
            }
            if n.eq_ignore_ascii_case("content-length") {
                continue;
            }
            if let Ok(v) = value.to_str() {
                extra.push((n.to_string(), v.to_string()));
            }
        }
        extra.push(("Urgency".into(), self.urgency.as_str().into()));
        if let Some(t) = &self.topic {
            extra.push(("Topic".into(), t.clone()));
        }

        Ok(HttpRequest {
            method: "POST".into(),
            url: parts.uri.to_string(),
            content_type,
            body,
            auth: HttpAuth::None,
            extra_headers: extra,
        })
    }
}

#[async_trait]
impl Sink for WebPushSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "webpush"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        if self.subscriptions.is_empty() {
            return Err(SinkError::Config(
                "webpush: no subscriptions configured".into(),
            ));
        }

        let (body, _) = template::render_template(&self.body_template, &event);
        let plaintext = body.into_bytes();

        let mut last_transient: Option<SinkError> = None;
        let mut last_permanent: Option<SinkError> = None;
        let mut last_config: Option<SinkError> = None;
        let mut any_ok = false;

        for sub in &self.subscriptions {
            let req = match self.build_request(sub, &plaintext) {
                Ok(r) => r,
                Err(e @ SinkError::Config(_)) => {
                    last_config = Some(e);
                    continue;
                }
                Err(e) => {
                    last_permanent = Some(e);
                    continue;
                }
            };
            match self.transport.send(req).await {
                Ok(()) => any_ok = true,
                Err(e @ SinkError::Transient(_)) => last_transient = Some(e),
                Err(e @ SinkError::Permanent(_)) => last_permanent = Some(e),
                Err(e @ SinkError::Config(_)) => last_config = Some(e),
            }
        }

        if any_ok {
            Ok(())
        } else if let Some(e) = last_transient {
            Err(e)
        } else if let Some(e) = last_permanent {
            Err(e)
        } else if let Some(e) = last_config {
            Err(e)
        } else {
            // Unreachable: subscriptions non-empty and every iteration sets
            // exactly one branch, but keep a fallback for defensive coding.
            Err(SinkError::Permanent("webpush: unknown failure".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;
    use crate::sinks::http::RecordingTransport;
    use web_push_native::jwt_simple::algorithms::ES256KeyPair;
    use web_push_native::p256::SecretKey as P256Secret;

    /// Generate a Subscription whose private side we keep so the test can
    /// decrypt the ciphertext that the sink produces.
    fn fresh_subscription() -> (Subscription, P256Secret, [u8; 16]) {
        use web_push_native::p256::elliptic_curve::sec1::ToEncodedPoint;
        let mut auth = [0u8; 16];
        getrandom_fill(&mut auth);
        let sk = P256Secret::random(&mut rand_compat::RngAdapter);
        let pk = sk.public_key();
        let p256dh =
            Base64UrlUnpadded::encode_string(pk.as_affine().to_encoded_point(false).as_bytes());
        let auth_b64 = Base64UrlUnpadded::encode_string(&auth);
        (
            Subscription {
                endpoint: "https://push.example.com/abc".into(),
                p256dh_key: p256dh,
                auth_secret: auth_b64,
            },
            sk,
            auth,
        )
    }

    /// Use the OS RNG via the same `rand_core::OsRng` that `web-push-native`
    /// itself depends on, so we don't introduce a new dev-dep.
    fn getrandom_fill(buf: &mut [u8]) {
        use web_push_native::p256::elliptic_curve::rand_core::RngCore;
        let mut rng = web_push_native::p256::elliptic_curve::rand_core::OsRng;
        rng.fill_bytes(buf);
    }

    /// Adapter so `P256Secret::random` accepts the `OsRng` from the
    /// upstream crate without us pulling in a `rand`-version that would
    /// disagree with `p256`'s own.
    mod rand_compat {
        use web_push_native::p256::elliptic_curve::rand_core::{
            CryptoRng, OsRng, RngCore,
        };
        pub struct RngAdapter;
        impl CryptoRng for RngAdapter {}
        impl RngCore for RngAdapter {
            fn next_u32(&mut self) -> u32 {
                OsRng.next_u32()
            }
            fn next_u64(&mut self) -> u64 {
                OsRng.next_u64()
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                OsRng.fill_bytes(dest);
            }
            fn try_fill_bytes(
                &mut self,
                dest: &mut [u8],
            ) -> Result<(), web_push_native::p256::elliptic_curve::rand_core::Error> {
                OsRng.try_fill_bytes(dest)
            }
        }
    }

    fn fresh_vapid() -> VapidIdentity {
        let kp = ES256KeyPair::generate();
        let raw = kp.to_bytes();
        let b64 = Base64UrlUnpadded::encode_string(&raw);
        VapidIdentity::from_base64url(&b64, "mailto:ops@example.com").unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn push_sink_posts_templated_json() {
        let t = Arc::new(RecordingTransport::new());
        let sink = PushSink::new(
            "mobile",
            "https://push.example.com/send",
            r#"{"title":"{{kind}}","body":"{{message}}"}"#,
            HttpAuth::Bearer("xyz".into()),
            t.clone(),
        );
        let ev = Event::builder("profile.connected", Severity::Info)
            .message("up")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let r = t.requests();
        assert_eq!(r.len(), 1);
        let body = std::str::from_utf8(&r[0].body).unwrap();
        assert!(body.contains("profile.connected"));
        assert!(body.contains("\"body\":\"up\""));
        // Bearer auth should ride as Authorization header.
        assert!(r[0]
            .extra_headers
            .iter()
            .any(|(n, v)| n.eq_ignore_ascii_case("authorization") && v == "Bearer xyz"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn vapid_identity_round_trips_through_base64url() {
        let kp = ES256KeyPair::generate();
        let raw = kp.to_bytes();
        let b64 = Base64UrlUnpadded::encode_string(&raw);
        let id = VapidIdentity::from_base64url(&b64, "mailto:a@b.example").unwrap();
        assert_eq!(id.subject(), "mailto:a@b.example");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn webpush_invalid_vapid_key_is_config_error() {
        let err = VapidIdentity::from_base64url("!!!not-base64!!!", "mailto:x@y.example")
            .unwrap_err();
        assert!(matches!(err, WebPushConfigError::VapidKey(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn webpush_no_subscriptions_is_config_error() {
        let t = Arc::new(RecordingTransport::new());
        let sink = WebPushSink::new(
            "mobile",
            r#"{"k":"{{kind}}"}"#,
            Vec::new(),
            fresh_vapid(),
            t,
        );
        let ev = Event::builder("k", Severity::Info).build();
        let err = sink.deliver(Arc::new(ev)).await.unwrap_err();
        assert!(matches!(err, SinkError::Config(_)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn webpush_emits_aes128gcm_post_with_vapid_and_decryptable_body() {
        let t = Arc::new(RecordingTransport::new());
        let (sub, ua_secret, ua_auth) = fresh_subscription();
        let ua_auth_ga = Auth::clone_from_slice(&ua_auth);

        let sink = WebPushSink::new(
            "mobile",
            r#"{"title":"{{kind}}","body":"{{message}}"}"#,
            vec![sub.clone()],
            fresh_vapid(),
            t.clone(),
        )
        .with_urgency(Urgency::High)
        .with_topic("alerts");
        let ev = Event::builder("profile.failed", Severity::Error)
            .message("boom")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();

        let r = t.requests();
        assert_eq!(r.len(), 1);
        let req = &r[0];
        assert_eq!(req.method, "POST");
        assert_eq!(req.url, "https://push.example.com/abc");
        assert_eq!(req.content_type, "application/octet-stream");

        let header = |name: &str| {
            req.extra_headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(header("content-encoding"), Some("aes128gcm"));
        assert_eq!(header("urgency"), Some("high"));
        assert_eq!(header("topic"), Some("alerts"));
        assert!(header("ttl").is_some());
        let auth = header("authorization").expect("vapid Authorization header");
        assert!(auth.starts_with("vapid t="), "auth = {auth}");
        assert!(auth.contains(", k="), "auth = {auth}");

        // Decrypt with the UA private key + auth secret to confirm the
        // payload is well-formed RFC 8291 ciphertext.
        let plain = web_push_native::decrypt(req.body.clone(), &ua_secret, &ua_auth_ga)
            .expect("decrypt round-trip");
        let s = std::str::from_utf8(&plain).unwrap();
        assert!(s.contains("profile.failed"), "body = {s}");
        assert!(s.contains("boom"), "body = {s}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn webpush_one_bad_subscription_does_not_block_others() {
        let t = Arc::new(RecordingTransport::new());
        let bad = Subscription {
            endpoint: "https://push.example.com/bad".into(),
            // Wrong length — will fail to parse as a P-256 SEC1 point.
            p256dh_key: Base64UrlUnpadded::encode_string(&[0u8; 8]),
            auth_secret: Base64UrlUnpadded::encode_string(&[0u8; 16]),
        };
        let (good, _sk, _auth) = fresh_subscription();
        let sink = WebPushSink::new(
            "mobile",
            r#"{"k":"{{kind}}"}"#,
            vec![bad, good.clone()],
            fresh_vapid(),
            t.clone(),
        );
        let ev = Event::builder("k", Severity::Info).build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let r = t.requests();
        // The bad subscription was rejected before transport; only the good
        // one should have produced a request.
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].url, good.endpoint);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn webpush_transient_transport_failure_propagates_as_retryable() {
        let t = Arc::new(RecordingTransport::new());
        t.fail_once(SinkError::Transient("net".into()));
        let (sub, _sk, _auth) = fresh_subscription();
        let sink = WebPushSink::new(
            "mobile",
            r#"{"k":"{{kind}}"}"#,
            vec![sub],
            fresh_vapid(),
            t,
        );
        let ev = Event::builder("k", Severity::Info).build();
        let err = sink.deliver(Arc::new(ev)).await.unwrap_err();
        assert!(err.is_retryable(), "got {err:?}");
    }
}
