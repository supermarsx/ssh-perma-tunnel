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
        let (url, _) = template::render_template(&self.url_template, &event);
        let (body, _) = template::render_template(&self.body_template, &event);
        let req = HttpRequest {
            method: self.method.clone(),
            url,
            content_type: self.content_type.clone(),
            body: body.into_bytes(),
            auth: self.auth.clone(),
        };
        self.transport.send(req).await
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
}
