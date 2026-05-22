//! Audit-hook surface for script-engine load and per-hook invocation.
//!
//! `ScriptEngine` fires events through a caller-supplied [`AuditSink`] so
//! the supervisor's audit subscriber (wired by Phase B1 of t7) can record
//! per-script provenance:
//!
//! * [`AuditSink::on_loaded`] — the AST has compiled successfully against
//!   the sandbox limits. Carries the script path and a SHA-256 of the
//!   source bytes so the audit subscriber can pin provenance even across
//!   on-disk renames.
//! * [`AuditSink::on_invoked`] — one hook dispatch finished. Carries the
//!   hook discriminator, the wall-clock duration, and the
//!   [`HookOutcome`].
//!
//! The default [`NoopAuditSink`] drops every event, keeping the hot path
//! free of overhead when no subscriber is attached. The
//! [`MockAuditSink`] recorder is used by integration tests to assert call
//! sites without spinning up the full supervisor.
//!
//! Mirrors the `spt_obfs::audit` / `spt_auth_sspi::audit` surfaces so
//! subscribers can be written once and applied across the three crates.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use crate::config::HookName;

/// Per-invocation outcome reported through [`AuditSink::on_invoked`].
///
/// `Skipped` is fired when the configured hook has no body declared in
/// the script (typo in the config, deliberately deferred hook, …). The
/// session-side dispatcher does not treat `Skipped` as a failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookOutcome {
    /// The hook function ran and returned without raising.
    Ok,
    /// The hook function raised a runtime error (script-side or
    /// sandbox-limit) and the invocation was aborted.
    Err,
    /// The hook was not declared in the script — the dispatcher
    /// short-circuited without entering the engine.
    Skipped,
}

impl HookOutcome {
    /// Stable wire identifier (`"ok"`, `"err"`, `"skipped"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Err => "err",
            Self::Skipped => "skipped",
        }
    }
}

impl std::fmt::Display for HookOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Subscriber for script-engine load and per-hook invocation events.
///
/// Implementations must be cheap when the subscriber is not actively
/// recording — the invocation path is on the per-event critical budget.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Fired once at [`crate::ScriptEngine::load`] time, after the AST
    /// has successfully compiled.
    fn on_loaded(&self, path: &Path, sha256: &[u8; 32]);
    /// Fired once per [`crate::ScriptEngine::invoke`] call, regardless of
    /// whether the underlying function ran, was missing, or raised.
    fn on_invoked(&self, hook: HookName, duration: Duration, outcome: HookOutcome);
}

/// Default sink — drops every event on the floor.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopAuditSink;

impl AuditSink for NoopAuditSink {
    fn on_loaded(&self, _path: &Path, _sha256: &[u8; 32]) {}
    fn on_invoked(&self, _hook: HookName, _duration: Duration, _outcome: HookOutcome) {}
}

/// One observable audit entry recorded by [`MockAuditSink`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditEntry {
    /// A [`AuditSink::on_loaded`] call.
    Loaded {
        /// Path that was loaded.
        path: PathBuf,
        /// SHA-256 of the source bytes.
        sha256: [u8; 32],
    },
    /// A [`AuditSink::on_invoked`] call.
    Invoked {
        /// Hook slot.
        hook: HookName,
        /// Wall-clock duration of the invocation.
        duration: Duration,
        /// Invocation outcome.
        outcome: HookOutcome,
    },
}

/// In-memory recorder used by integration tests.
#[derive(Debug, Default, Clone)]
pub struct MockAuditSink {
    entries: Arc<Mutex<Vec<AuditEntry>>>,
}

impl MockAuditSink {
    /// Construct an empty recorder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of recorded entries in firing order.
    #[must_use]
    pub fn entries(&self) -> Vec<AuditEntry> {
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

impl AuditSink for MockAuditSink {
    fn on_loaded(&self, path: &Path, sha256: &[u8; 32]) {
        self.entries.lock().push(AuditEntry::Loaded {
            path: path.to_path_buf(),
            sha256: *sha256,
        });
    }
    fn on_invoked(&self, hook: HookName, duration: Duration, outcome: HookOutcome) {
        self.entries.lock().push(AuditEntry::Invoked {
            hook,
            duration,
            outcome,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_string_form_is_stable() {
        assert_eq!(HookOutcome::Ok.as_str(), "ok");
        assert_eq!(HookOutcome::Err.as_str(), "err");
        assert_eq!(HookOutcome::Skipped.as_str(), "skipped");
        assert_eq!(format!("{}", HookOutcome::Ok), "ok");
    }

    #[test]
    fn mock_records_in_order() {
        let sink = MockAuditSink::new();
        sink.on_loaded(Path::new("/tmp/h.rhai"), &[0u8; 32]);
        sink.on_invoked(
            HookName::PreConnect,
            Duration::from_micros(123),
            HookOutcome::Ok,
        );
        let e = sink.entries();
        assert_eq!(e.len(), 2);
        assert!(matches!(e[0], AuditEntry::Loaded { .. }));
        assert!(matches!(
            e[1],
            AuditEntry::Invoked {
                hook: HookName::PreConnect,
                outcome: HookOutcome::Ok,
                ..
            }
        ));
    }

    #[test]
    fn noop_sink_drops_everything() {
        let sink = NoopAuditSink;
        // No panic, no side-effects observable.
        sink.on_loaded(Path::new("/x"), &[7u8; 32]);
        sink.on_invoked(
            HookName::OnEvent,
            Duration::from_millis(1),
            HookOutcome::Skipped,
        );
    }
}
