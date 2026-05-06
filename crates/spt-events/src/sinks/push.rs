//! Push-notification sink.
//!
//! Two backends are supported via the same `HttpTransport`:
//!
//! * Generic webhook — POST templated JSON to the configured URL.
//! * Web-push — same but with a wrapped envelope per RFC 8030. The wire
//!   crypto / VAPID lives in spt-bin (e18); this sink only constructs the
//!   request body.

use std::sync::Arc;

use async_trait::async_trait;

use crate::event::Event;
use crate::sinks::http::{HttpAuth, HttpRequest, HttpTransport};
use crate::sinks::{Sink, SinkError};
use crate::template;

/// Push sink.
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
                auth: self.auth.clone(),
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;
    use crate::sinks::http::RecordingTransport;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_posts_json() {
        let t = Arc::new(RecordingTransport::new());
        let sink = PushSink::new(
            "mobile",
            "https://push.example.com/send",
            r#"{"title":"{{kind}}","body":"{{message}}"}"#,
            HttpAuth::None,
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
    }
}
