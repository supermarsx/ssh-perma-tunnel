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

/// Default subject-line template used when a config `email` sink omits
/// `subject_template`. Mirrors the body-template default pattern: a
/// config-build site uses
/// [`resolve_subject_template`] over `sc.subject_template`.
pub const DEFAULT_EMAIL_SUBJECT_TEMPLATE: &str = "[{{severity}}] {{kind}}";

/// Resolve a config `subject_template` (`Option<String>`) to the effective
/// subject template, falling back to [`DEFAULT_EMAIL_SUBJECT_TEMPLATE`] when
/// unset. Mirrors the body-template default pattern for config-build sites.
pub fn resolve_subject_template(configured: Option<String>) -> String {
    configured.unwrap_or_else(|| DEFAULT_EMAIL_SUBJECT_TEMPLATE.into())
}

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

/// Real SMTP+STARTTLS transport via `lettre`. Built only when the
/// `transports` feature is on.
#[cfg(feature = "transports")]
pub mod smtp {
    use super::{EmailMessage, EmailTransport, SinkError};
    use async_trait::async_trait;
    use lettre::message::header::ContentType;
    use lettre::transport::smtp::authentication::Credentials;
    use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};

    /// Production SMTP transport.
    pub struct SmtpTransport {
        inner: AsyncSmtpTransport<Tokio1Executor>,
    }

    impl SmtpTransport {
        /// Build a STARTTLS-only transport for `host:port` with optional
        /// username/password.
        pub fn build(
            host: &str,
            port: u16,
            user_pass: Option<(String, String)>,
        ) -> Result<Self, SinkError> {
            let mut b = AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(host)
                .map_err(|e| SinkError::Config(format!("smtp tls config: {e}")))?
                .port(port);
            if let Some((u, p)) = user_pass {
                b = b.credentials(Credentials::new(u, p));
            }
            Ok(Self { inner: b.build() })
        }
    }

    #[async_trait]
    impl EmailTransport for SmtpTransport {
        async fn send(&self, msg: EmailMessage) -> Result<(), SinkError> {
            let mut b = Message::builder()
                .from(
                    msg.from
                        .parse()
                        .map_err(|e| SinkError::Permanent(format!("from: {e}")))?,
                )
                .subject(msg.subject)
                .header(ContentType::TEXT_PLAIN);
            for to in &msg.to {
                b = b.to(to
                    .parse()
                    .map_err(|e| SinkError::Permanent(format!("to {to}: {e}")))?);
            }
            let email = b
                .body(msg.body)
                .map_err(|e| SinkError::Permanent(format!("body: {e}")))?;
            self.inner.send(email).await.map(|_| ()).map_err(|e| {
                if e.is_permanent() {
                    SinkError::Permanent(format!("smtp: {e}"))
                } else {
                    SinkError::Transient(format!("smtp: {e}"))
                }
            })
        }
    }
}

/// Test transport.
#[derive(Default)]
pub struct RecordingEmailTransport {
    pub sent: parking_lot::Mutex<Vec<EmailMessage>>,
    pub fail_with: parking_lot::Mutex<Option<SinkError>>,
}

impl RecordingEmailTransport {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn messages(&self) -> Vec<EmailMessage> {
        self.sent.lock().clone()
    }
    /// Inject a one-shot failure for the next call.
    pub fn fail_once(&self, err: SinkError) {
        *self.fail_with.lock() = Some(err);
    }
}

#[async_trait]
impl EmailTransport for RecordingEmailTransport {
    async fn send(&self, msg: EmailMessage) -> Result<(), SinkError> {
        if let Some(err) = self.fail_with.lock().take() {
            return Err(err);
        }
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

    #[tokio::test(flavor = "current_thread")]
    async fn default_subject_template_renders_when_unset() {
        // A config build site that omits `subject_template` falls back to the
        // DEFAULT const; rendering it yields the same subject the explicit
        // `deliver_renders_subject_and_body` test asserts.
        let t = Arc::new(RecordingEmailTransport::new());
        // Simulate a config sink that omits `subject_template`.
        let subject_template = resolve_subject_template(None);
        assert_eq!(subject_template, DEFAULT_EMAIL_SUBJECT_TEMPLATE);
        let sink = EmailSink::new(
            "ops",
            "spt@example.com",
            vec!["sre@example.com".into()],
            subject_template,
            "msg={{message}}",
            t.clone(),
        );
        let ev = Event::builder("profile.failed", Severity::Error).build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let m = t.messages();
        assert_eq!(m[0].subject, "[error] profile.failed");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn name_and_kind_are_stable() {
        let t = Arc::new(RecordingEmailTransport::new());
        let sink = EmailSink::new("ops", "from@x", vec!["to@x".into()], "s", "b", t);
        assert_eq!(sink.name(), "ops");
        assert_eq!(sink.kind(), "email");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transport_failure_propagates_as_transient() {
        let t = Arc::new(RecordingEmailTransport::new());
        t.fail_once(SinkError::Transient("upstream MX 421".into()));
        let sink = EmailSink::new(
            "ops",
            "from@x",
            vec!["to@x".into()],
            "{{kind}}",
            "{{message}}",
            t,
        );
        let ev = Event::builder("k", Severity::Info).build();
        let err = sink.deliver(Arc::new(ev)).await.unwrap_err();
        assert!(err.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transport_failure_propagates_as_permanent() {
        let t = Arc::new(RecordingEmailTransport::new());
        t.fail_once(SinkError::Permanent("bad address".into()));
        let sink = EmailSink::new("ops", "from@x", vec!["to@x".into()], "s", "b", t);
        let err = sink
            .deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap_err();
        assert!(!err.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn multiple_recipients_are_preserved() {
        let t = Arc::new(RecordingEmailTransport::new());
        let sink = EmailSink::new(
            "ops",
            "from@x",
            vec!["a@x".into(), "b@x".into(), "c@x".into()],
            "S",
            "B",
            t.clone(),
        );
        sink.deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap();
        let m = t.messages();
        assert_eq!(m[0].to.len(), 3);
        assert_eq!(m[0].to[2], "c@x");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_template_fields_are_kept_as_placeholders() {
        let t = Arc::new(RecordingEmailTransport::new());
        let sink = EmailSink::new(
            "ops",
            "from@x",
            vec!["to@x".into()],
            "subj {{nope}}",
            "body {{also_missing}}",
            t.clone(),
        );
        sink.deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap();
        let m = t.messages();
        assert!(m[0].subject.contains("{{nope}}"));
        assert!(m[0].body.contains("{{also_missing}}"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn email_message_is_cloneable_for_telemetry() {
        let msg = EmailMessage {
            from: "a".into(),
            to: vec!["b".into()],
            subject: "s".into(),
            body: "b".into(),
        };
        let msg2 = msg.clone();
        assert_eq!(msg2.from, msg.from);
        assert_eq!(msg2.subject, msg.subject);
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn smtp_transport_build_returns_smtp_transport() {
        let r = smtp::SmtpTransport::build("smtp.example.com", 587, None);
        assert!(r.is_ok());
    }

    #[cfg(feature = "transports")]
    #[tokio::test(flavor = "current_thread")]
    async fn smtp_transport_build_with_credentials_succeeds() {
        let r = smtp::SmtpTransport::build(
            "smtp.example.com",
            587,
            Some(("user".into(), "pass".into())),
        );
        assert!(r.is_ok());
    }
}
