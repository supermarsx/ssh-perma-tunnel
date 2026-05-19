//! `StateSnapshotSource` trait — adapter the supervisor implements at
//! Phase-B wiring time to feed live state into the read-only server.
//!
//! Handlers in [`crate::handlers`] only depend on this trait so unit tests
//! can use an in-memory fake without dragging in `spt-supervisor`.

use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use spt_state::status::StatusSnapshot;

/// Read-only source of [`StatusSnapshot`]s.
///
/// Implementors must be cheap to call repeatedly — handlers may invoke
/// `snapshot()` multiple times per request (once per endpoint shape). The
/// supervisor's production implementation typically wraps an
/// `Arc<spt_state::status::StatusWriter>` and returns a clone of its inner
/// snapshot.
#[async_trait]
pub trait StateSnapshotSource: Send + Sync + 'static {
    /// Return the current snapshot (cloned).
    async fn snapshot(&self) -> StatusSnapshot;

    /// Render the Prometheus metrics page (text format, version 0.0.4).
    ///
    /// The default implementation returns an empty body — callers that have
    /// a real `spt-observability::metrics` registry should override.
    async fn metrics_prom(&self) -> String {
        String::new()
    }
}

/// In-memory `StateSnapshotSource` used in tests and by the spt-bin status
/// CLI when the supervisor isn't running.
///
/// Wraps a `parking_lot::RwLock<StatusSnapshot>` so callers can mutate via
/// [`InMemorySource::set`] / [`InMemorySource::update`].
#[derive(Default, Clone)]
pub struct InMemorySource {
    inner: Arc<RwLock<StatusSnapshot>>,
    metrics: Arc<RwLock<String>>,
}

impl InMemorySource {
    /// Construct an empty source with a default snapshot.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct from an existing snapshot.
    #[must_use]
    pub fn with_snapshot(snap: StatusSnapshot) -> Self {
        Self {
            inner: Arc::new(RwLock::new(snap)),
            metrics: Arc::new(RwLock::new(String::new())),
        }
    }

    /// Replace the entire snapshot.
    pub fn set(&self, snap: StatusSnapshot) {
        *self.inner.write() = snap;
    }

    /// Mutate the snapshot under the write lock.
    pub fn update<F: FnOnce(&mut StatusSnapshot)>(&self, f: F) {
        f(&mut self.inner.write());
    }

    /// Replace the metrics text body.
    pub fn set_metrics(&self, body: impl Into<String>) {
        *self.metrics.write() = body.into();
    }
}

#[async_trait]
impl StateSnapshotSource for InMemorySource {
    async fn snapshot(&self) -> StatusSnapshot {
        self.inner.read().clone()
    }

    async fn metrics_prom(&self) -> String {
        self.metrics.read().clone()
    }
}
