//! Audit hook surface.
//!
//! `Ssh2Session` builder injects an [`AuditHook`] into the obfuscation
//! pipeline; the hook fires once per `connect` with the transport name so
//! Bwire's audit subscriber records every selection. The default
//! [`NoopAuditHook`] keeps the hot path free of overhead when no subscriber
//! is attached.

use std::sync::Arc;

use parking_lot::Mutex;

/// Subscriber for obfuscation-transport selection events.
///
/// Implementations must be cheap when the subscriber is not actively
/// recording — the connect path is on the critical login latency budget.
pub trait AuditHook: Send + Sync {
    /// Called once per `connect` with the static transport name (`obfs4`,
    /// `meek-http`, `ssh-over-websocket`, `ssh-over-shadowsocks`) and the
    /// caller-supplied `target` (host:port form).
    fn on_connect(&self, transport: &'static str, target: &str);
}

/// Default hook — drops every event on the floor.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditHook;

impl AuditHook for NoopAuditHook {
    fn on_connect(&self, _transport: &'static str, _target: &str) {}
}

/// In-memory recorder used by integration tests.
///
/// Mirrors the `HookRecorder` pattern from t6-e7's scripting crate.
#[derive(Debug, Default, Clone)]
pub struct MockAuditHook {
    entries: Arc<Mutex<Vec<(&'static str, String)>>>,
}

impl MockAuditHook {
    /// Construct an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of recorded `(transport, target)` pairs in firing order.
    #[must_use]
    pub fn entries(&self) -> Vec<(&'static str, String)> {
        self.entries.lock().clone()
    }

    /// Number of entries recorded so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// True when no entries have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

impl AuditHook for MockAuditHook {
    fn on_connect(&self, transport: &'static str, target: &str) {
        self.entries.lock().push((transport, target.to_owned()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_records_in_order() {
        let h = MockAuditHook::new();
        h.on_connect("a", "x:1");
        h.on_connect("b", "y:2");
        let e = h.entries();
        assert_eq!(e.len(), 2);
        assert_eq!(e[0], ("a", "x:1".to_owned()));
        assert_eq!(e[1], ("b", "y:2".to_owned()));
    }
}
