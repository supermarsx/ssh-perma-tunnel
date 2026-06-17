//! Real [`spt_events::McpNotifier`] implementation for the `tunnel run`
//! loopback path (GAP 1).
//!
//! The event pipeline's `mcp_notify` sink calls
//! [`spt_events::McpNotifier::notify`] for every event routed to it. Until this
//! wave, `cli_dispatch` passed [`spt_events::NoopMcpNotifier`], so the sink
//! constructed but delivered nothing.
//!
//! [`BroadcastMcpNotifier`] is the live notifier: each `notify()` serializes the
//! [`spt_events::McpNotification`] (method + params) into a JSON-RPC
//! notification frame and publishes it onto a process-local
//! [`tokio::sync::broadcast`] channel. The same channel is the seam the MCP
//! loopback server consumes when a client subscribes — the same broadcast
//! pattern the orchestrator's `StatsTick` stream (`stats_subscribe`) already
//! uses. When no subscriber is attached the frame is dropped (broadcast
//! semantics) and `notify()` still reports success, so a configured
//! `mcp_notify` sink never blocks the dispatcher or trips spool retry just
//! because nobody is listening yet.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{json, Value};
use tokio::sync::broadcast;

use spt_events::{McpNotification, McpNotifier};

/// Default broadcast buffer depth for queued event notifications.
const DEFAULT_CAPACITY: usize = 256;

/// Live MCP notifier backed by a broadcast channel.
///
/// Construct once in `tunnel run`, hand the `Arc` to the events `SinkDeps`
/// (`.with_mcp(..)`) and keep a [`subscribe`](Self::subscribe) handle for the
/// MCP loopback server to stream from.
#[derive(Clone)]
pub struct BroadcastMcpNotifier {
    tx: broadcast::Sender<Value>,
}

impl BroadcastMcpNotifier {
    /// Build a notifier with the default channel capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Build a notifier with an explicit channel capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(capacity.max(1));
        Self { tx }
    }

    /// Subscribe to the notification stream. Each item is a JSON-RPC
    /// notification frame (`{"jsonrpc":"2.0","method":..,"params":..}`).
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Value> {
        self.tx.subscribe()
    }

    /// Number of currently-attached subscribers (diagnostics/tests).
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Render a [`McpNotification`] into a JSON-RPC notification frame.
    fn frame(n: &McpNotification) -> Value {
        let method = n.method.clone().unwrap_or_else(|| "spt/event".to_string());
        json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": n.params,
        })
    }
}

impl Default for BroadcastMcpNotifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl McpNotifier for BroadcastMcpNotifier {
    async fn notify(&self, n: McpNotification) -> Result<(), String> {
        let frame = Self::frame(&n);
        // `send` errors only when there are zero receivers. That is not a
        // delivery failure for the dispatcher's purposes (a notification with
        // no listener is fine), so we swallow it rather than triggering spool
        // retry on every event when no MCP client is subscribed.
        let _ = self.tx.send(frame);
        Ok(())
    }
}

/// Convenience: build a live notifier as a trait object for `SinkDeps::with_mcp`.
#[must_use]
pub fn live_notifier() -> (Arc<BroadcastMcpNotifier>, Arc<dyn McpNotifier>) {
    let concrete = Arc::new(BroadcastMcpNotifier::new());
    let dynamic = concrete.clone() as Arc<dyn McpNotifier>;
    (concrete, dynamic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_events::{Event, Severity};

    #[tokio::test]
    async fn notify_publishes_frame_to_subscriber() {
        let notifier = BroadcastMcpNotifier::new();
        let mut rx = notifier.subscribe();

        let ev = Event::builder("profile.failed", Severity::Error).build();
        notifier
            .notify(McpNotification::from_event(&ev))
            .await
            .expect("notify ok");

        let frame = rx.try_recv().expect("frame delivered");
        assert_eq!(frame["jsonrpc"], "2.0");
        assert_eq!(frame["method"], "spt/event");
        assert!(frame["params"].is_object(), "params carry the event");
    }

    #[tokio::test]
    async fn notify_is_ok_without_subscribers() {
        // No subscriber attached → send returns Err internally, but notify()
        // must still report success so the dispatcher doesn't spool-retry.
        let notifier = BroadcastMcpNotifier::new();
        assert_eq!(notifier.receiver_count(), 0);
        let ev = Event::builder("session.up", Severity::Info).build();
        let r = notifier.notify(McpNotification::from_event(&ev)).await;
        assert!(r.is_ok());
    }

    #[tokio::test]
    async fn honors_method_override() {
        let notifier = BroadcastMcpNotifier::new();
        let mut rx = notifier.subscribe();
        notifier
            .notify(McpNotification {
                method: Some("spt/custom".into()),
                params: json!({"x": 1}),
            })
            .await
            .unwrap();
        let frame = rx.try_recv().unwrap();
        assert_eq!(frame["method"], "spt/custom");
        assert_eq!(frame["params"]["x"], 1);
    }
}
