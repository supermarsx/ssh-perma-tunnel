//! Audit-hook surface for GSS / SSPI token exchanges.
//!
//! Each token round-trip and each MIC operation fires an [`AuditHook`] event
//! so that the supervisor's audit subscriber (wired by Phase B1 of t7) can
//! record per-step provenance: the package name (`"kerberos"`, `"ntlm"`,
//! `"negotiate"`), the round-trip ordinal, and the `complete` flag.
//!
//! Mirrors the [`spt_obfs::audit`] surface (`AuditHook`, `NoopAuditHook`,
//! `MockAuditHook`) so subscribers can be written once and applied across
//! the two crates.

use std::sync::Arc;

use parking_lot::Mutex;

/// One observable event from the `gssapi-with-mic` state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEvent {
    /// One `initialize_security_context` / `gss_init_sec_context` round
    /// trip completed. `round` is 1-based; `complete` mirrors
    /// [`crate::GssOutput::complete`].
    TokenExchange {
        /// SSPI / GSSAPI package name (`"kerberos"`, `"ntlm"`, `"negotiate"`).
        package: &'static str,
        /// 1-based round-trip ordinal.
        round: u32,
        /// `true` on the final round of the exchange.
        complete: bool,
    },
    /// A MIC was computed via `gss_get_mic` / `make_signature`.
    MicIssued {
        /// SSPI / GSSAPI package name.
        package: &'static str,
        /// Length in bytes of the issued MIC.
        mic_len: usize,
    },
    /// A peer MIC was verified via `gss_verify_mic` / `verify_signature`.
    MicVerified {
        /// SSPI / GSSAPI package name.
        package: &'static str,
        /// `true` iff the underlying verify call returned `Ok(())`.
        ok: bool,
    },
}

/// Subscriber for GSS / SSPI provider events.
///
/// Implementations must be cheap when the subscriber is not actively
/// recording — the auth path is on the critical login latency budget.
pub trait AuditHook: Send + Sync + std::fmt::Debug {
    /// Fired for every observable event.
    fn on_event(&self, event: &AuditEvent);
}

/// Default hook — drops every event on the floor.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditHook;

impl AuditHook for NoopAuditHook {
    fn on_event(&self, _event: &AuditEvent) {}
}

/// In-memory recorder used by integration tests.
#[derive(Debug, Default, Clone)]
pub struct MockAuditHook {
    entries: Arc<Mutex<Vec<AuditEvent>>>,
}

impl MockAuditHook {
    /// Construct an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of recorded events in firing order.
    #[must_use]
    pub fn entries(&self) -> Vec<AuditEvent> {
        self.entries.lock().clone()
    }

    /// Number of events recorded so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// True when no events have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}

impl AuditHook for MockAuditHook {
    fn on_event(&self, event: &AuditEvent) {
        self.entries.lock().push(event.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_records_in_order() {
        let h = MockAuditHook::new();
        h.on_event(&AuditEvent::TokenExchange {
            package: "kerberos",
            round: 1,
            complete: false,
        });
        h.on_event(&AuditEvent::TokenExchange {
            package: "kerberos",
            round: 2,
            complete: true,
        });
        h.on_event(&AuditEvent::MicIssued {
            package: "kerberos",
            mic_len: 32,
        });
        let e = h.entries();
        assert_eq!(e.len(), 3);
        assert!(matches!(e[1], AuditEvent::TokenExchange { round: 2, complete: true, .. }));
        assert!(matches!(e[2], AuditEvent::MicIssued { mic_len: 32, .. }));
    }
}
