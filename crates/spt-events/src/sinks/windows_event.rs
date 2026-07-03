//! Windows Event Log event sink (W4 finding 1 / wire-observ finding 2).
//!
//! Writing to the Windows Event Log requires the Win32 `ReportEvent` /
//! `RegisterEventSource` API, which is not available in `std` and would pull a
//! new `windows`/`winapi` dependency into `spt-events`. To honour the
//! no-new-deps constraint the OS write is abstracted behind
//! [`WindowsEventTransport`]: the binary injects a live `cfg(windows)`
//! implementation (sharing the existing `spt observe windows-event` code
//! path); on non-Windows targets — or before that transport is wired — the
//! sink is **still constructed** (never silently dropped) and logs a WARN.
//!
//! A matched event with no transport surfaces a `Permanent` failure (logged by
//! the dispatcher) rather than disappearing.
//!
//! Redaction: the prepared [`WindowsEventRecord`] carries only the rendered
//! body template (event fields) and the mapped severity — never a secret.

use std::sync::Arc;

use async_trait::async_trait;

use crate::event::{Event, Severity};
use crate::sinks::{Sink, SinkError};
use crate::template;

/// A prepared Windows Event Log record ready to be reported by the transport.
#[derive(Debug, Clone)]
pub struct WindowsEventRecord {
    /// Event Log source name (from the sink `provider`, else the sink name).
    pub source: String,
    /// Rendered message text (the sink body template). Event field values
    /// only — never a secret.
    pub message: String,
    /// Event severity, mapped by the transport to an Event Log entry type
    /// (Information / Warning / Error).
    pub severity: Severity,
}

/// Transport that reports a record to the Windows Event Log. Implemented in
/// the binary (`cfg(windows)`); mocked in tests.
#[async_trait]
pub trait WindowsEventTransport: Send + Sync {
    /// Report one record to the Event Log.
    async fn report(&self, record: WindowsEventRecord) -> Result<(), SinkError>;
}

/// Windows Event Log sink.
pub struct WindowsEventSink {
    name: String,
    source: String,
    body_template: String,
    transport: Option<Arc<dyn WindowsEventTransport>>,
}

impl WindowsEventSink {
    /// Construct. `transport` is `None` on non-Windows targets or until the
    /// `cfg(windows)` Event Log writer is injected; a `None` transport logs a
    /// WARN here so a configured-but-undeliverable sink is visible.
    pub fn new(
        name: impl Into<String>,
        source: impl Into<String>,
        body_template: impl Into<String>,
        transport: Option<Arc<dyn WindowsEventTransport>>,
    ) -> Self {
        let name = name.into();
        if transport.is_none() {
            #[cfg(windows)]
            tracing::warn!(
                sink = %name,
                kind = "windows_event",
                "windows_event sink constructed without an Event Log transport; \
                 matched events will be reported as undeliverable, not silently dropped"
            );
            #[cfg(not(windows))]
            tracing::warn!(
                sink = %name,
                kind = "windows_event",
                "windows_event sink is a no-op on non-Windows platforms; matched \
                 events will be reported as undeliverable, not silently dropped"
            );
        }
        Self {
            name,
            source: source.into(),
            body_template: body_template.into(),
            transport,
        }
    }
}

#[async_trait]
impl Sink for WindowsEventSink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "windows_event"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        let Some(transport) = self.transport.as_ref() else {
            return Err(SinkError::Permanent(format!(
                "windows_event sink `{}` has no Event Log transport (unavailable on \
                 this platform / not yet wired); event not delivered",
                self.name
            )));
        };
        let (message, _) = template::render_template(&self.body_template, &event);
        let record = WindowsEventRecord {
            source: self.source.clone(),
            message,
            severity: event.severity,
        };
        transport.report(record).await
    }
}

/// Recording Event Log transport for tests + downstream assertions. Never
/// touches the real Event Log.
#[derive(Default)]
pub struct RecordingWindowsEventTransport {
    /// Records handed to the transport, in order.
    pub records: parking_lot::Mutex<Vec<WindowsEventRecord>>,
    /// If set, the next `report` fails with this error (consumed once).
    pub fail_with: parking_lot::Mutex<Option<SinkError>>,
}

impl RecordingWindowsEventTransport {
    /// New empty transport.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `report` with `err` (consumed once).
    pub fn fail_once(&self, err: SinkError) {
        *self.fail_with.lock() = Some(err);
    }

    /// Snapshot of recorded records.
    #[must_use]
    pub fn records(&self) -> Vec<WindowsEventRecord> {
        self.records.lock().clone()
    }
}

#[async_trait]
impl WindowsEventTransport for RecordingWindowsEventTransport {
    async fn report(&self, record: WindowsEventRecord) -> Result<(), SinkError> {
        if let Some(err) = self.fail_with.lock().take() {
            return Err(err);
        }
        self.records.lock().push(record);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_reports_record_through_transport() {
        let t = Arc::new(RecordingWindowsEventTransport::new());
        let sink =
            WindowsEventSink::new("eventlog", "spt", "{{kind}}: {{message}}", Some(t.clone()));
        assert_eq!(sink.name(), "eventlog");
        assert_eq!(sink.kind(), "windows_event");
        let ev = Event::builder("profile.failed", Severity::Error)
            .message("down")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let recs = t.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].source, "spt");
        assert_eq!(recs[0].severity, Severity::Error);
        assert!(recs[0].message.contains("down"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_without_transport_is_permanent_not_silent() {
        let sink = WindowsEventSink::new("eventlog", "spt", "{{kind}}", None);
        let err = sink
            .deliver(Arc::new(Event::builder("k", Severity::Info).build()))
            .await
            .unwrap_err();
        assert!(matches!(err, SinkError::Permanent(_)));
    }
}
