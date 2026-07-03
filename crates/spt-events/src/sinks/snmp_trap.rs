//! SNMP-trap event sink (W4 finding 1 / wire-observ finding 2).
//!
//! Emitting a real SNMPv2c/v3 trap requires the SNMP PDU encoder plus a UDP
//! transport, both of which live in `spt-snmp` and are only wired into the
//! shipped binary in **Wave 5** (SNMP serving). To keep `spt-events` free of a
//! `spt-events → spt-snmp` dependency (and the edition-2024 / MSRV cost that
//! chain would pull in) the trap transport is abstracted behind
//! [`SnmpTrapTransport`]: the binary injects a live implementation once Wave 5
//! lands.
//!
//! Until then the sink is **still constructed** (never silently dropped from
//! the pipeline) and logs a loud WARN at construction so an operator can see
//! that a configured `snmp_trap` sink is not yet deliverable. A matched event
//! then surfaces a `Permanent` failure (logged by the dispatcher) rather than
//! disappearing.
//!
//! Redaction: the prepared [`SnmpTrap`] carries only the rendered body
//! template (event fields) and the event kind — never a secret.

use std::sync::Arc;

use async_trait::async_trait;

use crate::event::Event;
use crate::sinks::{Sink, SinkError};
use crate::template;

/// A prepared SNMP trap ready to be encoded and sent by the transport.
#[derive(Debug, Clone)]
pub struct SnmpTrap {
    /// Trap target (`host:port`, taken from the sink `url`/`endpoint`).
    pub target: String,
    /// Rendered notification text (the sink body template). Carries event
    /// field values only — never a secret.
    pub message: String,
    /// Event kind, surfaced as the trap's notification tag.
    pub kind: String,
}

/// Transport that encodes and sends an SNMP trap. Implemented in the binary
/// (Wave 5, over `spt-snmp`); mocked in tests.
#[async_trait]
pub trait SnmpTrapTransport: Send + Sync {
    /// Send one prepared trap. `Transient` errors are spooled/retried by the
    /// dispatcher; `Permanent`/`Config` errors are not.
    async fn send_trap(&self, trap: SnmpTrap) -> Result<(), SinkError>;
}

/// SNMP-trap sink.
pub struct SnmpTrapSink {
    name: String,
    target: String,
    body_template: String,
    transport: Option<Arc<dyn SnmpTrapTransport>>,
}

impl SnmpTrapSink {
    /// Construct. `transport` is `None` until the Wave-5 SNMP integration
    /// supplies a live trap sender; a `None` transport logs a WARN here so a
    /// configured-but-undeliverable sink is visible rather than silent.
    pub fn new(
        name: impl Into<String>,
        target: impl Into<String>,
        body_template: impl Into<String>,
        transport: Option<Arc<dyn SnmpTrapTransport>>,
    ) -> Self {
        let name = name.into();
        if transport.is_none() {
            tracing::warn!(
                sink = %name,
                kind = "snmp_trap",
                "snmp_trap sink constructed without a trap transport (SNMP trap \
                 delivery is a Wave-5 integration); matched events will be reported \
                 as undeliverable, not silently dropped"
            );
        }
        Self {
            name,
            target: target.into(),
            body_template: body_template.into(),
            transport,
        }
    }
}

#[async_trait]
impl Sink for SnmpTrapSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "snmp_trap"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        let Some(transport) = self.transport.as_ref() else {
            return Err(SinkError::Permanent(format!(
                "snmp_trap sink `{}` has no trap transport (SNMP serving is wired in \
                 Wave 5); event not delivered",
                self.name
            )));
        };
        let (message, _) = template::render_template(&self.body_template, &event);
        let trap = SnmpTrap {
            target: self.target.clone(),
            message,
            kind: event.kind.as_str().to_string(),
        };
        transport.send_trap(trap).await
    }
}

/// Recording trap transport for tests + downstream assertions (mirrors
/// [`crate::sinks::http::RecordingTransport`]). Never performs network I/O.
#[derive(Default)]
pub struct RecordingSnmpTrapTransport {
    /// Traps handed to the transport, in order.
    pub traps: parking_lot::Mutex<Vec<SnmpTrap>>,
    /// If set, the next `send_trap` fails with this error (consumed once).
    pub fail_with: parking_lot::Mutex<Option<SinkError>>,
}

impl RecordingSnmpTrapTransport {
    /// New empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `send_trap` with `err` (consumed once).
    pub fn fail_once(&self, err: SinkError) {
        *self.fail_with.lock() = Some(err);
    }

    /// Snapshot of recorded traps.
    #[must_use]
    pub fn traps(&self) -> Vec<SnmpTrap> {
        self.traps.lock().clone()
    }
}

#[async_trait]
impl SnmpTrapTransport for RecordingSnmpTrapTransport {
    async fn send_trap(&self, trap: SnmpTrap) -> Result<(), SinkError> {
        if let Some(err) = self.fail_with.lock().take() {
            return Err(err);
        }
        self.traps.lock().push(trap);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_sends_trap_through_transport() {
        let t = Arc::new(RecordingSnmpTrapTransport::new());
        let sink = SnmpTrapSink::new(
            "traps",
            "10.0.0.1:162",
            "{{kind}}: {{message}}",
            Some(t.clone()),
        );
        assert_eq!(sink.name(), "traps");
        assert_eq!(sink.kind(), "snmp_trap");
        let ev = Event::builder("profile.failed", Severity::Error)
            .message("boom")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let traps = t.traps();
        assert_eq!(traps.len(), 1);
        assert_eq!(traps[0].target, "10.0.0.1:162");
        assert_eq!(traps[0].kind, "profile.failed");
        assert!(traps[0].message.contains("boom"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_without_transport_is_permanent_not_silent() {
        let sink = SnmpTrapSink::new("traps", "10.0.0.1:162", "{{kind}}", None);
        let err = sink
            .deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap_err();
        assert!(matches!(err, SinkError::Permanent(_)));
        assert!(!err.is_retryable());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transient_transport_failure_is_retryable() {
        let t = Arc::new(RecordingSnmpTrapTransport::new());
        t.fail_once(SinkError::Transient("udp send failed".into()));
        let sink = SnmpTrapSink::new("traps", "10.0.0.1:162", "{{kind}}", Some(t));
        let err = sink
            .deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap_err();
        assert!(err.is_retryable());
    }
}
