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
        let (body, _) = template::render_template(&self.body_template, &event);
        let req = HttpRequest {
            method: "POST".into(),
            url: self.url.clone(),
            content_type: "application/x-www-form-urlencoded".into(),
            body: body.into_bytes(),
            auth: self.auth.clone(),
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
}
