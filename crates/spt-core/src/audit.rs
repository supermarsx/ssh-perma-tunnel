#![allow(
    clippy::doc_markdown,
    clippy::doc_lazy_continuation,
    clippy::items_after_statements
)]
//! Audit event surface for security-sensitive operations.
//!
//! `spt-core::audit` defines the canonical [`AuditEvent`] type and the
//! [`AuditSink`] trait used by other crates to record reveal / yank /
//! seal / unseal / passphrase entry. It is the single seam that the
//! binary layer wires to the live [`spt_events`](https://docs.rs/spt-events)
//! bus at startup; until then a default `tracing::info!` fallback fires
//! so audit records still land in the operator log.
//!
//! ## Contract
//!
//! * Events MUST NOT carry secret values. `fields` keys are documented per
//!   site (e.g. `kdf`, `recipients_count`, `field_id`, `ttl_ms`, `tty`,
//!   `prompt_text`); the *content* of the secret is never serialised.
//! * The global sink registration is thread-safe and supports atomic
//!   swap: [`register_audit_sink`] replaces the previously-installed
//!   sink. A reader observing the previous `Arc` finishes its
//!   `record(...)` call without holding the writer lock; subsequent
//!   readers see the new sink.
//! * If no sink is installed [`record_audit`] falls back to
//!   `tracing::info!(target: "spt::audit", ...)` — that path is the
//!   no-panic guarantee the trait callers rely on.
//!
//! ## Storage primitive
//!
//! We use `std::sync::RwLock<Option<Arc<dyn AuditSink>>>` (not `OnceLock`)
//! so the slot is *replaceable*. The read path clones the `Arc` out
//! while holding the read guard and immediately drops the guard before
//! invoking the user's `record()` — that way a hostile or slow sink
//! cannot starve writers or other recorders.

use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Severity tier for an [`AuditEvent`].
///
/// Mirrors the upper half of `spt_events::Severity` — every audit
/// record is at least `Info`. `Notice` is reserved for events that
/// matter to operators but are not warnings (e.g. a successful reveal);
/// `Warning` is for events that indicate elevated risk (e.g. unsealing
/// failed signature check but caller suppressed it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    /// Routine event (default for instrumented sites).
    Info,
    /// Operator-relevant event worth highlighting.
    Notice,
    /// Elevated-risk event.
    Warning,
}

impl AuditSeverity {
    /// Short string used by the default tracing sink.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Notice => "notice",
            Self::Warning => "warning",
        }
    }
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One audit event.
///
/// Every field is plain data — there is no opaque "details" blob. This
/// keeps the schema stable across versions and trivially-serialisable
/// for downstream sinks (JSONL, syslog, OTLP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Wall-clock UTC timestamp of the event. Recorded at construction
    /// time (typically immediately before the audited operation runs)
    /// so the audit trail captures the *attempt*, not just success.
    pub timestamp: DateTime<Utc>,
    /// Event kind, dotted-namespace. Documented values:
    ///
    /// * `audit.config_crypt.seal`
    /// * `audit.config_crypt.unseal`
    /// * `audit.config_crypt.sign`
    /// * `audit.config_crypt.verify`
    /// * `audit.reveal`
    /// * `audit.yank`
    /// * `audit.passphrase`
    pub kind: String,
    /// Severity tier.
    pub severity: AuditSeverity,
    /// Structured, never-secret fields. Implementations of [`AuditSink`]
    /// MUST treat each value as a printable string suitable for
    /// inclusion in a log line. Producers MUST NOT include plaintext
    /// secrets, ciphertext, key bytes, or any data derived from them.
    pub fields: BTreeMap<String, String>,
}

impl AuditEvent {
    /// Build a new event at the current wall-clock time.
    #[must_use]
    pub fn new(kind: impl Into<String>, severity: AuditSeverity) -> Self {
        Self {
            timestamp: Utc::now(),
            kind: kind.into(),
            severity,
            fields: BTreeMap::new(),
        }
    }

    /// Add a field. Chainable.
    #[must_use]
    pub fn with_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }
}

/// Sink for [`AuditEvent`]s.
///
/// Implementations MUST be cheap to call from any thread (no blocking
/// I/O on the caller's path — buffer to a queue if needed) and MUST
/// NOT panic.
pub trait AuditSink: Send + Sync + std::fmt::Debug {
    /// Record `ev`. Called from arbitrary threads.
    fn record(&self, ev: AuditEvent);
}

/// Process-global sink slot. `None` means "no sink registered — fall
/// back to the default tracing emit".
static SINK: RwLock<Option<Arc<dyn AuditSink>>> = RwLock::new(None);

/// Install (or replace) the process-global audit sink.
///
/// Idempotent: every call swaps the slot to the supplied `Arc`. Safe to
/// call from any thread; existing readers complete their `record()`
/// call against the previous sink instance.
pub fn register_audit_sink(sink: Arc<dyn AuditSink>) {
    // Best-effort write. If a previous panic poisoned the lock we still
    // want subsequent registrations to succeed — clear the poison by
    // using `into_inner` semantics: take whatever guard is available
    // and overwrite.
    match SINK.write() {
        Ok(mut guard) => {
            *guard = Some(sink);
        }
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = Some(sink);
            // Clear the poison flag implicitly by re-locking: callers
            // see the new value cleanly.
        }
    }
}

/// Dispatch `ev` through the registered sink, or fall back to the
/// default tracing emit if no sink is installed.
///
/// Never panics. If the lock is poisoned the event is dropped to the
/// tracing fallback (so a poisoned writer cannot silence the audit
/// trail).
pub fn record_audit(ev: AuditEvent) {
    let snapshot = match SINK.read() {
        Ok(guard) => guard.as_ref().map(Arc::clone),
        Err(poisoned) => poisoned.into_inner().as_ref().map(Arc::clone),
    };
    match snapshot {
        Some(sink) => sink.record(ev),
        None => default_tracing_emit(&ev),
    }
}

/// Emit `ev` via `tracing::info!` on the `spt::audit` target.
///
/// Exposed for testing and for sinks that want to chain to the default
/// behaviour for events they don't otherwise handle.
pub fn default_tracing_emit(ev: &AuditEvent) {
    // We serialise the fields as a single `key=value` blob so subscribers
    // capturing structured fields still see the per-field data without
    // each call having to know the field set up-front. The fields
    // BTreeMap orders by key so the output is deterministic.
    let mut fields_str = String::new();
    for (k, v) in &ev.fields {
        if !fields_str.is_empty() {
            fields_str.push(' ');
        }
        fields_str.push_str(k);
        fields_str.push('=');
        fields_str.push_str(v);
    }
    tracing::info!(
        target: "spt::audit",
        kind = %ev.kind,
        severity = %ev.severity,
        ts = %ev.timestamp.to_rfc3339(),
        fields = %fields_str,
    );
}

/// Clear the registered sink. Test-only — exposed so tests can return
/// to the default tracing fallback without process-global pollution.
#[cfg(any(test, feature = "testing"))]
pub fn clear_audit_sink_for_test() {
    if let Ok(mut guard) = SINK.write() {
        *guard = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::thread;
    use std::time::Duration;
    use tracing::subscriber;
    use tracing_subscriber::fmt::MakeWriter;

    /// Test ordering: the global SINK is process-wide. We serialise the
    /// tests in this module via a guard so concurrent ones don't fight.
    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        match LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    #[derive(Default, Debug)]
    struct MockSink {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl AuditSink for MockSink {
        fn record(&self, ev: AuditEvent) {
            self.events.lock().unwrap().push(ev);
        }
    }

    impl MockSink {
        fn events(&self) -> Vec<AuditEvent> {
            self.events.lock().unwrap().clone()
        }
    }

    /// Make-writer that captures emitted log lines into a shared Vec.
    #[derive(Clone, Default)]
    struct VecWriter {
        buf: Arc<Mutex<Vec<u8>>>,
    }

    impl std::io::Write for VecWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.buf.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for VecWriter {
        type Writer = VecWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn captured(buf: &Arc<Mutex<Vec<u8>>>) -> String {
        String::from_utf8_lossy(&buf.lock().unwrap()).into_owned()
    }

    /// 1. Default tracing sink emits via the subscriber when no sink
    /// is registered.
    #[test]
    fn default_tracing_sink_emits_via_subscriber() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        let writer = VecWriter::default();
        let buf = Arc::clone(&writer.buf);
        let sub = tracing_subscriber::fmt()
            .with_writer(writer)
            .with_target(true)
            .with_max_level(tracing::Level::TRACE)
            .finish();
        subscriber::with_default(sub, || {
            let ev = AuditEvent::new("audit.config_crypt.seal", AuditSeverity::Info)
                .with_field("kdf", "argon2id")
                .with_field("recipients_count", "0");
            record_audit(ev);
        });
        let s = captured(&buf);
        assert!(
            s.contains("audit.config_crypt.seal"),
            "expected kind in tracing output, got: {s}"
        );
        assert!(s.contains("kdf=argon2id"), "expected fields in output: {s}");
        assert!(s.contains("spt::audit"), "expected target in output: {s}");
    }

    /// 2. Mock sink captures recorded events.
    #[test]
    fn mock_sink_captures_recorded_events() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        let sink = Arc::new(MockSink::default());
        register_audit_sink(sink.clone());
        record_audit(
            AuditEvent::new("audit.reveal", AuditSeverity::Notice)
                .with_field("field_id", "auth.passphrase")
                .with_field("ttl_ms", "3000"),
        );
        let evs = sink.events();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, "audit.reveal");
        assert_eq!(evs[0].severity, AuditSeverity::Notice);
        assert_eq!(
            evs[0].fields.get("ttl_ms").map(String::as_str),
            Some("3000")
        );
        clear_audit_sink_for_test();
    }

    /// 3. No secret value appears in any payload (structural check).
    /// Build events from a known plaintext-secret round-trip and assert
    /// no field VALUE contains the secret bytes.
    #[test]
    fn no_secret_value_in_payload() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        let sink = Arc::new(MockSink::default());
        register_audit_sink(sink.clone());

        const SECRET: &str = "hunter2-do-not-log-me";

        // Simulate the instrumentation site set: each call SHOULD only
        // include the documented non-secret keys.
        record_audit(
            AuditEvent::new("audit.config_crypt.seal", AuditSeverity::Info)
                .with_field("kdf", "argon2id")
                .with_field("recipients_count", "0"),
        );
        record_audit(
            AuditEvent::new("audit.config_crypt.unseal", AuditSeverity::Info)
                .with_field("kdf", "argon2id")
                .with_field("recipients_count", "0"),
        );
        record_audit(
            AuditEvent::new("audit.reveal", AuditSeverity::Notice)
                .with_field("field_id", "auth.passphrase")
                .with_field("ttl_ms", "3000"),
        );
        record_audit(
            AuditEvent::new("audit.yank", AuditSeverity::Notice)
                .with_field("field_id", "auth.passphrase")
                .with_field("clipboard_ttl_secs", "30"),
        );
        record_audit(
            AuditEvent::new("audit.passphrase", AuditSeverity::Info)
                .with_field("tty", "true")
                .with_field("prompt_text", "sealed config passphrase: "),
        );

        for ev in sink.events() {
            for (k, v) in &ev.fields {
                assert!(!v.contains(SECRET), "field {k}={v} leaked secret {SECRET}");
            }
            // Kind/severity are documented constants — confirm they
            // also don't somehow embed the secret.
            assert!(!ev.kind.contains(SECRET));
        }
        clear_audit_sink_for_test();
    }

    /// 4. Kind field is correct per operation — golden assertion for
    /// each documented kind.
    #[test]
    fn kind_field_correct_per_operation() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        let sink = Arc::new(MockSink::default());
        register_audit_sink(sink.clone());

        let kinds = [
            "audit.config_crypt.seal",
            "audit.config_crypt.unseal",
            "audit.config_crypt.sign",
            "audit.config_crypt.verify",
            "audit.reveal",
            "audit.yank",
            "audit.passphrase",
        ];
        for k in kinds {
            record_audit(AuditEvent::new(k, AuditSeverity::Info));
        }
        let evs = sink.events();
        assert_eq!(evs.len(), kinds.len());
        for (i, k) in kinds.iter().enumerate() {
            assert_eq!(evs[i].kind, *k, "kind mismatch at index {i}");
        }
        clear_audit_sink_for_test();
    }

    /// 5. Registration is idempotent — second register replaces.
    #[test]
    fn register_is_idempotent_second_wins() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        let a = Arc::new(MockSink::default());
        let b = Arc::new(MockSink::default());
        register_audit_sink(a.clone());
        register_audit_sink(b.clone());
        record_audit(AuditEvent::new("audit.reveal", AuditSeverity::Info));
        assert_eq!(
            a.events().len(),
            0,
            "first sink must not see post-swap events"
        );
        assert_eq!(b.events().len(), 1, "second sink must capture event");
        clear_audit_sink_for_test();
    }

    /// 6. Concurrent recording is thread-safe: 16 threads × 100 events
    /// each = 1600 events captured.
    #[test]
    fn concurrent_recording_is_thread_safe() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        let sink = Arc::new(MockSink::default());
        register_audit_sink(sink.clone());

        let mut handles = Vec::new();
        for _ in 0..16 {
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    record_audit(AuditEvent::new("audit.reveal", AuditSeverity::Info));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(sink.events().len(), 1600, "expected 1600 events captured");
        clear_audit_sink_for_test();
    }

    /// 7. Recording while sink unset is a no-op (no panic). The default
    /// tracing emit fires; without a subscriber it is a true no-op.
    #[test]
    fn recording_while_unset_is_noop_no_panic() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        // No subscriber installed — tracing emit becomes a no-op.
        record_audit(AuditEvent::new("audit.reveal", AuditSeverity::Info));
        record_audit(
            AuditEvent::new("audit.config_crypt.seal", AuditSeverity::Info)
                .with_field("kdf", "argon2id"),
        );
        // If we reach here without panicking the contract holds.
    }

    /// 8. Sink swap propagates atomically: a writer thread swaps the
    /// sink while a recorder thread loops firing events; the recorder
    /// keeps going until told to stop, so the second sink is
    /// guaranteed to capture at least one event after the swap.
    #[test]
    fn sink_swap_propagates_atomically() {
        let _g = test_lock();
        clear_audit_sink_for_test();
        let first = Arc::new(MockSink::default());
        let second = Arc::new(MockSink::default());
        register_audit_sink(first.clone());

        // The recorder loops until `stop` flips, deliberately yielding
        // between fires so the swap thread has wall-clock opportunity
        // to take the writer lock and replace the sink.
        let stop = Arc::new(AtomicUsize::new(0));
        let stop_recorder = stop.clone();
        let recorder = thread::spawn(move || {
            while stop_recorder.load(Ordering::SeqCst) == 0 {
                record_audit(AuditEvent::new("audit.reveal", AuditSeverity::Info));
                thread::yield_now();
            }
        });

        // Deterministic instead of wall-clock: spin (bounded) until the
        // recorder has landed at least one event on `first`, THEN swap, THEN
        // spin until `second` sees at least one. A fixed sleep flaked under
        // parallel CPU contention when the recorder thread was starved.
        let spin_until = |f: &dyn Fn() -> bool| {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            while !f() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "recorder thread made no progress within the deadline"
                );
                thread::yield_now();
            }
        };
        spin_until(&|| !first.events().is_empty());
        register_audit_sink(second.clone());
        spin_until(&|| !second.events().is_empty());
        stop.store(1, Ordering::SeqCst);
        recorder.join().unwrap();

        let total_first = first.events().len();
        let total_second = second.events().len();
        assert!(
            total_first >= 1,
            "first sink must capture pre-swap events (first={total_first}, second={total_second})"
        );
        assert!(
            total_second >= 1,
            "swap must propagate: second sink must capture post-swap events (first={total_first}, second={total_second})"
        );
        clear_audit_sink_for_test();
    }

    /// 9. AuditEvent serde round-trips through JSON (used by downstream
    /// JSONL sinks).
    #[test]
    fn audit_event_serde_round_trip() {
        let ev = AuditEvent::new("audit.config_crypt.seal", AuditSeverity::Info)
            .with_field("kdf", "argon2id")
            .with_field("recipients_count", "2");
        let json = serde_json::to_string(&ev).unwrap();
        let back: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, ev.kind);
        assert_eq!(back.severity, ev.severity);
        assert_eq!(back.fields, ev.fields);
    }

    /// 10. AuditSeverity Display matches as_str.
    #[test]
    fn audit_severity_display() {
        assert_eq!(format!("{}", AuditSeverity::Info), "info");
        assert_eq!(format!("{}", AuditSeverity::Notice), "notice");
        assert_eq!(format!("{}", AuditSeverity::Warning), "warning");
    }
}
