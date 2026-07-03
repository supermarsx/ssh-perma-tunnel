//! Minimal in-crate `tracing` capture for unit tests.
//!
//! Implements a tiny [`tracing::Subscriber`] that records each event's level
//! and flattened `field=value` text (including the `message`) into a shared
//! buffer, so tests can assert on emitted logs without pulling in an extra
//! dev-dependency. Installed for the current thread via
//! [`tracing::subscriber::with_default`], so it composes with a
//! `current_thread` runtime's `block_on`.

use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Level, Metadata, Subscriber};

/// One captured tracing event.
#[derive(Clone, Debug)]
pub(crate) struct CapturedEvent {
    /// Event severity.
    pub level: Level,
    /// Flattened `field=value` text, including the `message` field.
    pub fields: String,
}

#[derive(Clone, Default)]
struct Collector {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
    next_id: Arc<AtomicU64>,
}

struct FieldVisitor(String);

impl Visit for FieldVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        let _ = write!(self.0, "{}={} ", field.name(), value);
    }
}

impl Subscriber for Collector {
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        // Ids must be non-zero; hand out a fresh one per span.
        Id::from_u64(self.next_id.fetch_add(1, Ordering::Relaxed) + 1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut visitor = FieldVisitor(String::new());
        event.record(&mut visitor);
        self.events.lock().unwrap().push(CapturedEvent {
            level: *event.metadata().level(),
            fields: visitor.0,
        });
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Run `f` with a capturing subscriber installed as the thread-local default,
/// returning `f`'s result alongside every event emitted during the call.
pub(crate) fn capture<T>(f: impl FnOnce() -> T) -> (T, Vec<CapturedEvent>) {
    let collector = Collector::default();
    let events = collector.events.clone();
    let out = tracing::subscriber::with_default(collector, f);
    let captured = events.lock().unwrap().clone();
    (out, captured)
}
