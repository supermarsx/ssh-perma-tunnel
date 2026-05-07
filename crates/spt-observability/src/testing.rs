//! Test fixtures for `spt-observability`.
//!
//! Gated behind the `testing` feature. Provides a [`CapturingLayer`] that
//! records every `tracing::Event` into a shared `Vec`, plus helpers for
//! isolated Prometheus metric tests.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::Mutex;
use prometheus::{Encoder, Registry, TextEncoder};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

/// One captured tracing event.
#[derive(Debug, Clone)]
pub struct CapturedEvent {
    /// Event level (`"TRACE"`, `"DEBUG"`, `"INFO"`, `"WARN"`, `"ERROR"`).
    pub level: String,
    /// Event target (typically the module path).
    pub target: String,
    /// All non-`message` fields, stringified.
    pub fields: HashMap<String, String>,
    /// The `message` field value if present, else empty.
    pub message: String,
}

/// A `tracing_subscriber::Layer` that pushes every observed event into a
/// shared `Vec<CapturedEvent>`. Cheap, lock-based; intended for tests.
///
/// # Examples
///
/// ```
/// use spt_observability::testing::CapturingLayer;
///
/// let layer = CapturingLayer::new();
/// // Register the layer with `tracing_subscriber::registry().with(layer.clone())`
/// // — see [`with_capturing_subscriber`] for the common pattern.
/// assert!(layer.events().is_empty());
/// ```
#[derive(Clone, Default)]
pub struct CapturingLayer {
    events: Arc<Mutex<Vec<CapturedEvent>>>,
}

impl CapturingLayer {
    /// Construct an empty layer.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Snapshot of currently-captured events.
    #[must_use]
    pub fn events(&self) -> Vec<CapturedEvent> {
        self.events.lock().clone()
    }

    /// How many events have been captured.
    #[must_use]
    pub fn len(&self) -> usize {
        self.events.lock().len()
    }

    /// True if no events have been captured.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.lock().is_empty()
    }

    /// Drain all captured events.
    pub fn take(&self) -> Vec<CapturedEvent> {
        std::mem::take(&mut *self.events.lock())
    }
}

impl std::fmt::Debug for CapturingLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapturingLayer")
            .field("len", &self.len())
            .finish()
    }
}

#[derive(Default)]
struct StringVisitor {
    message: String,
    fields: HashMap<String, String>,
}

impl Visit for StringVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            value.clone_into(&mut self.message);
        } else {
            self.fields.insert(field.name().to_owned(), value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        let s = format!("{value:?}");
        if field.name() == "message" {
            self.message = s;
        } else {
            self.fields.insert(field.name().to_owned(), s);
        }
    }
}

impl<S> Layer<S> for CapturingLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut v = StringVisitor::default();
        event.record(&mut v);
        let meta = event.metadata();
        self.events.lock().push(CapturedEvent {
            level: meta.level().to_string(),
            target: meta.target().to_owned(),
            fields: v.fields,
            message: v.message,
        });
    }
}

/// Install a [`CapturingLayer`] as the thread-local default subscriber for
/// the duration of `f`, returning whatever `f` returns. The closure receives
/// a clone of the layer so it can read captured events.
///
/// This uses `tracing::subscriber::with_default`, which scopes the subscriber
/// to the calling thread — safe to call concurrently from multiple tests.
///
/// # Examples
///
/// ```
/// use spt_observability::testing::with_capturing_subscriber;
///
/// let count = with_capturing_subscriber(|layer| {
///     tracing::info!(target: "demo", answer = 42, "hello");
///     layer.len()
/// });
/// assert_eq!(count, 1);
/// ```
pub fn with_capturing_subscriber<F, R>(f: F) -> R
where
    F: FnOnce(CapturingLayer) -> R,
{
    let layer = CapturingLayer::new();
    let subscriber = tracing_subscriber::registry().with(layer.clone());
    tracing::subscriber::with_default(subscriber, || f(layer))
}

/// Build an empty `prometheus::Registry`. Useful when isolating a metrics
/// test from the global default registry.
///
/// # Examples
///
/// ```
/// use spt_observability::testing::fake_metrics_registry;
///
/// let r = fake_metrics_registry();
/// assert!(r.gather().is_empty());
/// ```
#[must_use]
pub fn fake_metrics_registry() -> Registry {
    Registry::new()
}

/// Flatten every counter/gauge in `reg` to `(metric_name, value)` pairs.
///
/// Histograms are not represented (they have multiple component metrics);
/// only `Counter`/`IntCounter`/`Gauge`/`IntGauge` (and their `*Vec`
/// counterparts, one row per label combination) appear. The metric name is
/// suffixed with the label values when labels are present, e.g.
/// `spt_bytes_in_total{forward_id=fwd-1}`.
///
/// # Examples
///
/// ```
/// use prometheus::IntCounter;
/// use spt_observability::testing::{fake_metrics_registry, snapshot_metrics};
///
/// let reg = fake_metrics_registry();
/// let c = IntCounter::new("hits", "hit count").unwrap();
/// reg.register(Box::new(c.clone())).unwrap();
/// c.inc_by(5);
/// let pairs = snapshot_metrics(&reg);
/// assert_eq!(pairs, vec![("hits".to_string(), 5.0)]);
/// ```
#[must_use]
pub fn snapshot_metrics(reg: &Registry) -> Vec<(String, f64)> {
    let mut out = Vec::new();
    for mf in reg.gather() {
        let name = mf.get_name();
        for m in mf.get_metric() {
            let label_suffix = if m.get_label().is_empty() {
                String::new()
            } else {
                let parts: Vec<String> = m
                    .get_label()
                    .iter()
                    .map(|l| format!("{}={}", l.get_name(), l.get_value()))
                    .collect();
                format!("{{{}}}", parts.join(","))
            };
            let key = format!("{name}{label_suffix}");
            // Cover the four scalar metric shapes Prometheus exposes.
            if m.has_counter() {
                out.push((key, m.get_counter().get_value()));
            } else if m.has_gauge() {
                out.push((key, m.get_gauge().get_value()));
            } else if m.has_untyped() {
                out.push((key, m.get_untyped().get_value()));
            }
            // Histograms / summaries deliberately skipped.
        }
    }
    out
}

/// Render `reg` to Prometheus text-format bytes. Convenience helper around
/// [`prometheus::TextEncoder`] for tests that want to assert on the wire
/// representation.
///
/// # Errors
/// Returns the underlying [`prometheus::Error`] if encoding fails.
///
/// # Examples
///
/// ```
/// use spt_observability::testing::{fake_metrics_registry, render_metrics_text};
/// let reg = fake_metrics_registry();
/// let text = render_metrics_text(&reg).unwrap();
/// assert!(text.is_empty() || text.contains('\n'));
/// ```
pub fn render_metrics_text(reg: &Registry) -> Result<String, prometheus::Error> {
    let mut buf = Vec::new();
    TextEncoder::new().encode(&reg.gather(), &mut buf)?;
    Ok(String::from_utf8(buf).unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::{Gauge, IntCounter};

    #[test]
    fn capturing_layer_records_events() {
        let count = with_capturing_subscriber(|layer| {
            tracing::info!(target: "spt_observability::testing::tests", flag = true, "hello world");
            tracing::warn!(target: "spt_observability::testing::tests", "second");
            let evs = layer.events();
            assert_eq!(evs.len(), 2);
            assert_eq!(evs[0].level, "INFO");
            assert_eq!(evs[0].message, "hello world");
            assert_eq!(evs[0].fields.get("flag").map(String::as_str), Some("true"));
            assert_eq!(evs[1].level, "WARN");
            evs.len()
        });
        assert_eq!(count, 2);
    }

    #[test]
    fn fake_registry_starts_empty() {
        let r = fake_metrics_registry();
        assert!(snapshot_metrics(&r).is_empty());
    }

    #[test]
    fn snapshot_collects_counter_and_gauge() {
        let r = fake_metrics_registry();
        let c = IntCounter::new("n_calls", "calls").unwrap();
        let g = Gauge::new("temp", "temp celsius").unwrap();
        r.register(Box::new(c.clone())).unwrap();
        r.register(Box::new(g.clone())).unwrap();
        c.inc_by(3);
        g.set(21.5);
        let mut s = snapshot_metrics(&r);
        s.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(s.len(), 2);
        assert!(s.iter().any(|(k, v)| k == "n_calls" && (*v - 3.0).abs() < 1e-9));
        assert!(s.iter().any(|(k, v)| k == "temp" && (*v - 21.5).abs() < 1e-9));
    }

    #[test]
    fn render_metrics_text_includes_help() {
        let r = fake_metrics_registry();
        let c = IntCounter::new("hits", "hit count").unwrap();
        r.register(Box::new(c.clone())).unwrap();
        c.inc();
        let text = render_metrics_text(&r).unwrap();
        assert!(text.contains("hits"));
        assert!(text.contains("hit count"));
    }

    #[test]
    fn take_drains_events() {
        with_capturing_subscriber(|layer| {
            tracing::info!("a");
            tracing::info!("b");
            assert_eq!(layer.len(), 2);
            let drained = layer.take();
            assert_eq!(drained.len(), 2);
            assert!(layer.is_empty());
        });
    }
}
