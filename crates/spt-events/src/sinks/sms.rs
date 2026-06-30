//! SMS sink — generic webhook adapter (Twilio/Vonage style POST).
//!
//! No SMS-specific transport here; we just delegate to an `HttpTransport`.
//! Config maps the provider URL + auth into the [`SmsSink`] constructor.

use std::sync::Arc;

use async_trait::async_trait;

use crate::event::Event;
use crate::sinks::http::{HttpAuth, HttpRequest, HttpTransport};
use crate::sinks::{Sink, SinkError};
use crate::template;

/// SMS sink.
pub struct SmsSink {
    name: String,
    provider: String,
    url: String,
    body_template: String,
    auth: HttpAuth,
    transport: Arc<dyn HttpTransport>,
}

impl SmsSink {
    /// Construct.
    pub fn new(
        name: impl Into<String>,
        provider: impl Into<String>,
        url: impl Into<String>,
        body_template: impl Into<String>,
        auth: HttpAuth,
        transport: Arc<dyn HttpTransport>,
    ) -> Self {
        Self {
            name: name.into(),
            provider: provider.into(),
            url: url.into(),
            body_template: body_template.into(),
            auth,
            transport,
        }
    }

    /// Provider hint (e.g. `"twilio"`, `"vonage"`). Useful for telemetry.
    #[must_use]
    pub fn provider(&self) -> &str {
        &self.provider
    }
}

#[async_trait]
impl Sink for SmsSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "sms"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        // The provider body is `application/x-www-form-urlencoded`; form-encode
        // substituted values so a field containing `&`/`=` cannot inject or
        // override sibling provider parameters (e.g. append `&To=...`).
        let (body, _) = template::render_template_escaped(
            &self.body_template,
            &event,
            template::EscapeMode::Form,
        );
        let req = HttpRequest {
            method: "POST".into(),
            url: self.url.clone(),
            content_type: "application/x-www-form-urlencoded".into(),
            body: body.into_bytes(),
            auth: self.auth.clone(),
            extra_headers: Vec::new(),
        };
        self.transport.send(req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;
    use crate::sinks::http::RecordingTransport;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_emits_post() {
        let t = Arc::new(RecordingTransport::new());
        let sink = SmsSink::new(
            "oncall",
            "twilio",
            "https://api.twilio.com/x/Messages",
            "Body=ALERT+{{kind}}",
            HttpAuth::Basic("dXNlcjpwYXNz".into()),
            t.clone(),
        );
        let ev = Event::builder("profile.failed", Severity::Error).build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let r = t.requests();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].method, "POST");
        assert!(std::str::from_utf8(&r[0].body)
            .unwrap()
            .contains("profile.failed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn provider_hint_is_exposed() {
        let t = Arc::new(RecordingTransport::new());
        let sink = SmsSink::new(
            "oncall",
            "vonage",
            "https://x/y",
            "Body={{kind}}",
            HttpAuth::None,
            t,
        );
        assert_eq!(sink.provider(), "vonage");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn name_kind_are_stable() {
        let t = Arc::new(RecordingTransport::new());
        let sink = SmsSink::new("oncall", "twilio", "https://x", "b", HttpAuth::None, t);
        assert_eq!(sink.name(), "oncall");
        assert_eq!(sink.kind(), "sms");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn content_type_is_form_urlencoded() {
        let t = Arc::new(RecordingTransport::new());
        let sink = SmsSink::new(
            "a",
            "p",
            "https://x",
            "k={{kind}}",
            HttpAuth::None,
            t.clone(),
        );
        sink.deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap();
        let req = &t.requests()[0];
        assert_eq!(req.content_type, "application/x-www-form-urlencoded");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn form_param_injection_is_neutralised() {
        // A field value trying to append `&To=+1900...` must be form-encoded so
        // it stays inside the `Body` parameter and cannot add/override params.
        let t = Arc::new(RecordingTransport::new());
        let sink = SmsSink::new(
            "oncall",
            "twilio",
            "https://api.twilio.com/x/Messages",
            "Body={{message}}",
            HttpAuth::None,
            t.clone(),
        );
        let ev = Event::builder("k", Severity::Error)
            .message("hi&To=+1900555&x=1")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let body = std::str::from_utf8(&t.requests()[0].body)
            .unwrap()
            .to_string();
        // Exactly one `&`/`=`-delimited parameter survives (the literal Body=).
        let params: Vec<&str> = body.split('&').collect();
        assert_eq!(params.len(), 1, "extra params injected: {body}");
        assert!(params[0].starts_with("Body="));
        // The injected `To` must not appear as a bare parameter.
        assert!(!body.contains("&To="), "To param injected: {body}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transient_transport_failure_propagates() {
        let t = Arc::new(RecordingTransport::new());
        t.fail_once(SinkError::Transient("rate-limited".into()));
        let sink = SmsSink::new("a", "p", "https://x", "b", HttpAuth::None, t);
        let err = sink
            .deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap_err();
        assert!(err.is_retryable());
    }
}
