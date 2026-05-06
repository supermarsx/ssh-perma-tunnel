//! Email sink (SMTP+TLS via injected transport).
//!
//! The actual SMTP wire — `lettre` or another crate — lives in `spt-bin`
//! (e18) where it's wired with config-loaded TLS certs and credentials.
//! Here we only model the message that would be sent and accept any
//! transport implementing [`EmailTransport`].

use std::sync::Arc;

use async_trait::async_trait;

use crate::event::Event;
use crate::sinks::{Sink, SinkError};
use crate::template;

/// One outbound email message.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

/// Transport trait — production wires this to lettre.
#[async_trait]
pub trait EmailTransport: Send + Sync {
    async fn send(&self, msg: EmailMessage) -> Result<(), SinkError>;
}

/// Email sink.
pub struct EmailSink {
    name: String,
    from: String,
    to: Vec<String>,
    subject_template: String,
    body_template: String,
    transport: Arc<dyn EmailTransport>,
}

impl EmailSink {
    /// Construct.
    pub fn new(
        name: impl Into<String>,
        from: impl Into<String>,
        to: Vec<String>,
        subject_template: impl Into<String>,
        body_template: impl Into<String>,
        transport: Arc<dyn EmailTransport>,
    ) -> Self {
        Self {
            name: name.into(),
            from: from.into(),
            to,
            subject_template: subject_template.into(),
            body_template: body_template.into(),
            transport,
        }
    }
}

#[async_trait]
impl Sink for EmailSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "email"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        let (subject, _) = template::render_template(&self.subject_template, &event);
        let (body, _) = template::render_template(&self.body_template, &event);
        let msg = EmailMessage {
            from: self.from.clone(),
            to: self.to.clone(),
            subject,
            body,
        };
        self.transport.send(msg).await
    }
}

/// Test transport.
#[derive(Default)]
pub struct RecordingEmailTransport {
    pub sent: parking_lot::Mutex<Vec<EmailMessage>>,
}

impl RecordingEmailTransport {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn messages(&self) -> Vec<EmailMessage> {
        self.sent.lock().clone()
    }
}

#[async_trait]
impl EmailTransport for RecordingEmailTransport {
    async fn send(&self, msg: EmailMessage) -> Result<(), SinkError> {
        self.sent.lock().push(msg);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_renders_subject_and_body() {
        let t = Arc::new(RecordingEmailTransport::new());
        let sink = EmailSink::new(
            "ops",
            "spt@example.com",
            vec!["sre@example.com".into()],
            "[{{severity}}] {{kind}}",
            "msg={{message}}",
            t.clone(),
        );
        let ev = Event::builder("profile.failed", Severity::Error)
            .message("connection refused")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let m = t.messages();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].subject, "[error] profile.failed");
        assert!(m[0].body.contains("connection refused"));
        assert_eq!(m[0].from, "spt@example.com");
        assert_eq!(m[0].to, vec!["sre@example.com".to_string()]);
    }
}
