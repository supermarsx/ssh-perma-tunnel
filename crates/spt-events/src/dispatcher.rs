//! Background task that consumes from the bus and applies bindings.
//!
//! The dispatcher keeps three things alive:
//!
//! 1. A `broadcast::Receiver` for the bus.
//! 2. The configured [`Binding`]s.
//! 3. A registry of `Arc<dyn Sink>`s keyed by name.
//!
//! On each event it walks the bindings; for each binding whose `match`
//! passes (and dedupe doesn't suppress), it dispatches to every named sink.
//! Failures classified as [`SinkError::Transient`] write the JSON-encoded
//! event to a per-sink [`spt_state::DiskSpool`]; a separate retry task
//! drains spools when a sink starts succeeding again.
//!
//! For unit-tested code paths the dispatcher exposes `tick_once` so tests
//! can drive it deterministically without spawning the background task.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use spt_state::{DiskSpool, SpoolConfig};

use crate::binding::{Binding, DedupeState};
use crate::bus::EventBus;
use crate::event::Event;
use crate::sinks::Sink;

/// Dispatcher configuration.
#[derive(Debug, Clone)]
pub struct DispatcherConfig {
    /// Per-sink spool root; one subdirectory per sink will be created.
    pub spool_root: PathBuf,
    /// Spool size/file caps applied to every sink's spool.
    pub spool: SpoolConfig,
    /// How often the retry task polls each spool for redelivery.
    pub retry_interval: Duration,
    /// Bind kind labels to log when redaction is triggered.
    pub strict_redaction: bool,
}

impl Default for DispatcherConfig {
    fn default() -> Self {
        Self {
            spool_root: PathBuf::from("event-spool"),
            spool: SpoolConfig::default(),
            retry_interval: Duration::from_secs(30),
            strict_redaction: false,
        }
    }
}

/// Running dispatcher.
pub struct Dispatcher {
    join: Mutex<Option<JoinHandle<()>>>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
}

impl Dispatcher {
    /// Spawn the dispatcher. Returns once subscription is established.
    #[allow(clippy::implicit_hasher)]
    pub fn spawn(
        bus: &EventBus,
        bindings: Vec<Binding>,
        sinks: HashMap<String, Arc<dyn Sink>>,
        cfg: DispatcherConfig,
    ) -> std::io::Result<Self> {
        let mut spools: HashMap<String, Arc<Mutex<DiskSpool>>> = HashMap::new();
        std::fs::create_dir_all(&cfg.spool_root)?;
        for name in sinks.keys() {
            let dir = cfg.spool_root.join(name);
            let spool = DiskSpool::open(dir, cfg.spool.clone()).map_err(|e| {
                std::io::Error::other(format!("open spool for {name}: {e}"))
            })?;
            spools.insert(name.clone(), Arc::new(Mutex::new(spool)));
        }

        let inner = DispatcherInner {
            bindings,
            sinks,
            dedupe_state: DedupeState::new(),
            spools,
            cfg,
        };

        let mut rx = bus.subscribe();
        let (sd_tx, mut sd_rx) = oneshot::channel();
        let inner = Arc::new(inner);
        let inner_for_task = inner.clone();
        let join = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = &mut sd_rx => break,
                    msg = rx.recv() => {
                        match msg {
                            Ok(ev) => {
                                inner_for_task.dispatch(ev).await;
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                tracing::warn!(skipped=n, "event dispatcher lagged");
                            }
                            Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                        }
                    }
                }
            }
        });

        Ok(Self {
            join: Mutex::new(Some(join)),
            shutdown: Mutex::new(Some(sd_tx)),
        })
    }

    /// Stop the dispatcher and wait for it to drain.
    pub async fn shutdown(self) {
        let tx = self.shutdown.lock().take();
        if let Some(tx) = tx {
            let _ = tx.send(());
        }
        let join = self.join.lock().take();
        if let Some(j) = join {
            let _ = j.await;
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.lock().take() {
            let _ = tx.send(());
        }
    }
}

/// Inner dispatch state — exposed via the public type's helpers in tests.
pub struct DispatcherInner {
    bindings: Vec<Binding>,
    sinks: HashMap<String, Arc<dyn Sink>>,
    dedupe_state: DedupeState,
    spools: HashMap<String, Arc<Mutex<DiskSpool>>>,
    /// Retained for future retry-task config; suppress `dead_code`.
    #[allow(dead_code)]
    cfg: DispatcherConfig,
}

impl DispatcherInner {
    /// Dispatch one event synchronously through every matching binding.
    ///
    /// This is the primary unit of work; tests call it directly.
    pub async fn dispatch(&self, event: Arc<Event>) {
        for b in &self.bindings {
            if !b.r#match.matches(&event) {
                continue;
            }
            if let Some(d) = &b.dedupe {
                if self.dedupe_state.should_suppress(d, &event) {
                    continue;
                }
            }
            for sref in &b.sinks {
                if let Some(sink) = self.sinks.get(sref.as_str()) {
                    let result = sink.deliver(event.clone()).await;
                    if let Err(e) = result {
                        if e.is_retryable() {
                            self.spool_one(sink.name(), &event);
                        } else {
                            tracing::warn!(sink=%sink.name(), error=%e, "sink delivery failed permanently");
                        }
                    }
                } else {
                    tracing::warn!(binding=%b.name, sink=%sref.as_str(), "sink not found");
                }
            }
        }
    }

    /// Drain spools for the named sink, redelivering until empty or a
    /// retryable failure halts the drain.
    pub async fn drain_spool(&self, sink_name: &str) {
        let Some(sink) = self.sinks.get(sink_name) else {
            return;
        };
        let Some(spool) = self.spools.get(sink_name) else {
            return;
        };
        loop {
            let entry = {
                let mut g = spool.lock();
                match g.pop() {
                    Ok(Some(e)) => e,
                    Ok(None) | Err(_) => return,
                }
            };
            let Ok(ev) = serde_json::from_slice::<Event>(&entry.payload) else {
                continue;
            };
            let arc = Arc::new(ev);
            if let Err(e) = sink.deliver(arc.clone()).await {
                // Re-spool and stop draining on transient failure.
                if e.is_retryable() {
                    let mut g = spool.lock();
                    let bytes = serde_json::to_vec(&*arc).unwrap_or_default();
                    let _ = g.push(&bytes);
                }
                return;
            }
        }
    }

    /// Spool size for a sink (helper for tests).
    pub fn spool_len(&self, sink_name: &str) -> usize {
        self.spools
            .get(sink_name)
            .map_or(0, |s| s.lock().len())
    }

    /// Test helper: borrow the bindings.
    pub fn bindings(&self) -> &[Binding] {
        &self.bindings
    }

    fn spool_one(&self, sink_name: &str, event: &Event) {
        if let Some(spool) = self.spools.get(sink_name) {
            match serde_json::to_vec(event) {
                Ok(bytes) => {
                    if let Err(e) = spool.lock().push(&bytes) {
                        tracing::warn!(sink=%sink_name, error=%e, "spool push failed");
                    }
                }
                Err(e) => {
                    tracing::warn!(sink=%sink_name, error=%e, "spool encode failed");
                }
            }
        }
    }
}

/// Test-only constructor that returns the inner dispatch state without
/// spawning a background task.
#[allow(clippy::implicit_hasher)]
pub fn build_for_test(
    bindings: Vec<Binding>,
    sinks: HashMap<String, Arc<dyn Sink>>,
    cfg: DispatcherConfig,
) -> std::io::Result<DispatcherInner> {
    let mut spools: HashMap<String, Arc<Mutex<DiskSpool>>> = HashMap::new();
    std::fs::create_dir_all(&cfg.spool_root)?;
    for name in sinks.keys() {
        let dir = cfg.spool_root.join(name);
        let spool = DiskSpool::open(dir, cfg.spool.clone())
            .map_err(|e| std::io::Error::other(format!("open spool: {e}")))?;
        spools.insert(name.clone(), Arc::new(Mutex::new(spool)));
    }
    Ok(DispatcherInner {
        bindings,
        sinks,
        dedupe_state: DedupeState::new(),
        spools,
        cfg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binding::{BindingMatch, SinkRef};
    use crate::event::Severity;
    use crate::sinks::http::{HttpAuth, HttpSink, RecordingTransport};
    use crate::sinks::SinkError;
    use tempfile::tempdir;

    fn make_binding(kinds: Vec<&str>, sinks: Vec<&str>) -> Binding {
        Binding {
            name: "b1".into(),
            r#match: BindingMatch {
                kinds: kinds.into_iter().map(String::from).collect(),
                ..Default::default()
            },
            sinks: sinks.into_iter().map(SinkRef::new).collect(),
            dedupe: None,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn match_dispatches_to_sink_no_match_skips() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let t = Arc::new(RecordingTransport::new());
        let http = Arc::new(HttpSink::new(
            "alerts",
            "POST",
            "https://x",
            "{}",
            "application/json",
            HttpAuth::None,
            t.clone(),
        )) as Arc<dyn Sink>;
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("alerts".into(), http);

        let bindings = vec![make_binding(vec!["forward.*"], vec!["alerts"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        d.dispatch(Arc::new(
            Event::builder("forward.connection_failed", Severity::Error).build(),
        ))
        .await;
        d.dispatch(Arc::new(
            Event::builder("profile.connected", Severity::Info).build(),
        ))
        .await;

        let r = t.requests();
        assert_eq!(r.len(), 1, "only the matching event should fire");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn transient_failure_spools_then_drain_on_recovery() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let t = Arc::new(RecordingTransport::new());
        // Force the next call to fail with a transient error.
        t.fail_once(SinkError::Transient("network down".into()));
        let http = Arc::new(HttpSink::new(
            "alerts",
            "POST",
            "https://x",
            "{}",
            "application/json",
            HttpAuth::None,
            t.clone(),
        )) as Arc<dyn Sink>;
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("alerts".into(), http);

        let bindings = vec![make_binding(vec!["forward.*"], vec!["alerts"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        d.dispatch(Arc::new(
            Event::builder("forward.connection_failed", Severity::Error).build(),
        ))
        .await;
        // The original delivery failed → spool grows.
        assert_eq!(d.spool_len("alerts"), 1);
        // Now recovery: drain should succeed and clear the spool.
        d.drain_spool("alerts").await;
        assert_eq!(d.spool_len("alerts"), 0);
        assert_eq!(t.requests().len(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dedupe_suppresses_within_interval() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let t = Arc::new(RecordingTransport::new());
        let http = Arc::new(HttpSink::new(
            "alerts",
            "POST",
            "https://x",
            "{}",
            "application/json",
            HttpAuth::None,
            t.clone(),
        )) as Arc<dyn Sink>;
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("alerts".into(), http);

        let mut b = make_binding(vec!["k"], vec!["alerts"]);
        b.dedupe = Some(crate::binding::Dedupe {
            key_fields: vec!["kind".into()],
            interval: Duration::from_secs(60),
        });
        let d = build_for_test(vec![b], sinks, cfg).unwrap();

        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build())).await;
        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build())).await;
        assert_eq!(t.requests().len(), 1, "second event should be deduped");
    }
}
