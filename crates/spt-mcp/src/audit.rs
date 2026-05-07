//! Audit-event sink trait used by the MCP server to record every tool call.
//!
//! `spt-events` provides the production [`McpAuditSink`] implementation that
//! routes events into the global event bus. This crate ships only the trait,
//! a no-op default for tests and embedding harnesses, and a small in-memory
//! mock used by the unit tests.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;

/// A single audit event emitted by the MCP server.
///
/// One event is produced per tool invocation, regardless of outcome:
/// - on success, [`AuditEvent::ok`] is `true` and `error` is `None`;
/// - on policy denial or handler failure, [`AuditEvent::ok`] is `false` and
///   `error` carries a redacted message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Tool name, e.g. `"forward_add"`.
    pub tool: String,
    /// Arguments after redaction (no plaintext secrets).
    pub arguments: Value,
    /// `true` if the handler returned a result.
    pub ok: bool,
    /// Optional client identity if the transport supplied one.
    pub client_id: Option<String>,
    /// Error message (already redacted) when `ok == false`.
    pub error: Option<String>,
    /// Unix-epoch milliseconds the event was created.
    pub timestamp_ms: i64,
}

/// Sink trait for MCP audit events.
///
/// Implementations must be cheap to clone (typically `Arc`-wrapped) and must
/// not block — the dispatch path awaits this in the request handler.
#[async_trait]
pub trait McpAuditSink: Send + Sync + 'static {
    /// Record one audit event. Errors are logged by the caller and otherwise
    /// suppressed — audit failure must not propagate to the MCP client.
    async fn record(&self, event: AuditEvent);
}

/// Default no-op sink used when the binary has not wired one up.
#[derive(Debug, Default, Clone)]
pub struct NoopAuditSink;

#[async_trait]
impl McpAuditSink for NoopAuditSink {
    async fn record(&self, _event: AuditEvent) {}
}

/// Convenience boxed alias used by the server.
pub type DynAuditSink = Arc<dyn McpAuditSink>;

#[cfg(any(test, feature = "testing"))]
pub mod test_support {
    use super::{AuditEvent, McpAuditSink};
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use std::sync::Arc;

    /// In-memory audit sink used by the unit tests.
    #[derive(Debug, Default, Clone)]
    pub struct MockAuditSink {
        events: Arc<Mutex<Vec<AuditEvent>>>,
    }

    impl MockAuditSink {
        /// Build an empty sink.
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Snapshot of recorded events in arrival order.
        #[must_use]
        pub fn snapshot(&self) -> Vec<AuditEvent> {
            self.events.lock().clone()
        }
    }

    #[async_trait]
    impl McpAuditSink for MockAuditSink {
        async fn record(&self, event: AuditEvent) {
            self.events.lock().push(event);
        }
    }
}
