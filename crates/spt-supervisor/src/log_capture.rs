//! Test-only tracing capture (w8-supervisor).
//!
//! A minimal [`tracing::Subscriber`] that records every event's level,
//! `message`, and structured fields into a shared buffer so tests can assert
//! that the supervisor mirrors its lifecycle *decisions* (give-up, reconnect,
//! failover, instability, connect-ok, session-failure, cooldown) to `tracing`
//! at the right level with the right fields.
//!
//! We roll our own subscriber (rather than pull in `tracing-subscriber`) to
//! honor the "no new deps" constraint — `tracing` is already a dependency.
//!
//! Install with [`tracing::subscriber::set_default`] (thread-local): on the
//! single-threaded `#[tokio::test(flavor = "current_thread")]` runtime the
//! spawned `ProfileTask` polls on the same thread, so its events are captured
//! while the returned guard is alive.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span;
use tracing::{Event, Level, Metadata, Subscriber};

/// One captured tracing event.
#[derive(Debug, Clone)]
pub(crate) struct CapturedEvent {
    /// Verbosity level of the event.
    pub level: Level,
    /// The event's `message` (format string), if any.
    pub message: String,
    /// Structured key/value fields, stringified.
    pub fields: BTreeMap<String, String>,
}

impl CapturedEvent {
    /// Look up a structured field by name.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields.get(name).map(String::as_str)
    }
}

/// Thread-safe, cloneable capture sink.
#[derive(Clone, Default)]
pub(crate) struct CaptureSubscriber {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl CaptureSubscriber {
    /// New empty sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of every captured event so far.
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.events.lock().unwrap().clone()
    }

    /// First captured event whose `message` contains `needle`.
    pub fn find(&self, needle: &str) -> Option<CapturedEvent> {
        self.events()
            .into_iter()
            .find(|e| e.message.contains(needle))
    }
}

#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: BTreeMap<String, String>,
}

impl FieldVisitor {
    fn put(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = value;
        } else {
            self.fields.insert(field.name().to_owned(), value);
        }
    }
}

impl Visit for FieldVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.put(field, value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.put(field, format!("{value:?}"));
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.put(field, value.to_string());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.put(field, value.to_string());
    }
}

impl Subscriber for CaptureSubscriber {
    fn enabled(&self, _meta: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _attrs: &span::Attributes<'_>) -> span::Id {
        span::Id::from_u64(1)
    }

    fn record(&self, _span: &span::Id, _values: &span::Record<'_>) {}

    fn record_follows_from(&self, _span: &span::Id, _follows: &span::Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut v = FieldVisitor::default();
        event.record(&mut v);
        self.events.lock().unwrap().push(CapturedEvent {
            level: *event.metadata().level(),
            message: v.message,
            fields: v.fields,
        });
    }

    fn enter(&self, _span: &span::Id) {}

    fn exit(&self, _span: &span::Id) {}
}
