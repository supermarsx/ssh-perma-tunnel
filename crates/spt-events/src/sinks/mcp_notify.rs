//! MCP-notify sink — delegates to the [`McpNotifier`] trait.

use std::sync::Arc;

use async_trait::async_trait;

use crate::event::Event;
use crate::mcp_notifier::{McpNotification, McpNotifier};
use crate::sinks::{Sink, SinkError};

/// MCP-notify sink.
pub struct McpNotifySink {
    name: String,
    notifier: Arc<dyn McpNotifier>,
}

impl McpNotifySink {
    /// Construct.
    pub fn new(name: impl Into<String>, notifier: Arc<dyn McpNotifier>) -> Self {
        Self {
            name: name.into(),
            notifier,
        }
    }
}

#[async_trait]
impl Sink for McpNotifySink {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> &'static str {
        "mcp_notify"
    }

    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
        let notif = McpNotification::from_event(&event);
        self.notifier
            .notify(notif)
            .await
            .map_err(SinkError::Transient)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;
    use crate::mcp_notifier::NoopMcpNotifier;

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_calls_notifier() {
        let sink = McpNotifySink::new("mcp", Arc::new(NoopMcpNotifier));
        let ev = Event::builder("k", Severity::Info).build();
        sink.deliver(Arc::new(ev)).await.unwrap();
    }

    /// Recording notifier — verifies Sink invokes `notify()`.
    struct Rec(parking_lot::Mutex<Vec<McpNotification>>);
    #[async_trait]
    impl McpNotifier for Rec {
        async fn notify(&self, n: McpNotification) -> Result<(), String> {
            self.0.lock().push(n);
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn deliver_passes_event_in_params() {
        let r = Arc::new(Rec(parking_lot::Mutex::new(Vec::new())));
        let sink = McpNotifySink::new("mcp", r.clone());
        let ev = Event::builder("k", Severity::Info)
            .message("hello")
            .build();
        sink.deliver(Arc::new(ev)).await.unwrap();
        let v = r.0.lock().clone();
        assert_eq!(v.len(), 1);
        assert!(v[0].params.to_string().contains("hello"));
    }
}
