//! Cross-crate `McpNotifier` trait.
//!
//! Defined here so spt-events doesn't depend on spt-mcp (avoids a dep cycle
//! since spt-mcp may want to subscribe to the event bus). spt-mcp implements
//! `McpNotifier` against its notification channel; spt-events takes a
//! `Box<dyn McpNotifier>` for its `mcp_notify` sink.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::event::Event;

/// One notification dispatched through MCP.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpNotification {
    /// Optional method name override. Defaults to `"spt/event"`.
    pub method: Option<String>,
    /// JSON params payload (the full event by default).
    pub params: serde_json::Value,
}

impl McpNotification {
    /// Build the default notification (method = `spt/event`, params = the
    /// full event).
    pub fn from_event(event: &Event) -> Self {
        Self {
            method: Some("spt/event".to_string()),
            params: serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
        }
    }
}

/// Trait that spt-mcp implements; spt-events consumes it via `Box<dyn ..>`.
#[async_trait]
pub trait McpNotifier: Send + Sync {
    /// Deliver a notification. Returning `Err` causes spool retry.
    async fn notify(&self, n: McpNotification) -> Result<(), String>;
}

/// No-op notifier — used when MCP is disabled or not yet wired.
pub struct NoopMcpNotifier;

#[async_trait]
impl McpNotifier for NoopMcpNotifier {
    async fn notify(&self, _: McpNotification) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    #[tokio::test(flavor = "current_thread")]
    async fn noop_always_ok() {
        let n = NoopMcpNotifier;
        let ev = Event::builder("k", Severity::Info).build();
        let r = n.notify(McpNotification::from_event(&ev)).await;
        assert!(r.is_ok());
    }

    #[test]
    fn from_event_uses_default_method() {
        let ev = Event::builder("k", Severity::Info).build();
        let n = McpNotification::from_event(&ev);
        assert_eq!(n.method.as_deref(), Some("spt/event"));
    }
}
