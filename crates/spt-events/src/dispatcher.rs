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
//! Failures classified as `SinkError::Transient` write the JSON-encoded
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
use tokio::sync::{broadcast, oneshot};
use tokio::task::JoinHandle;

use spt_state::{DiskSpool, SpoolConfig};

/// Best-effort budget for draining events already buffered in the broadcast
/// receiver when the dispatcher is told to shut down (F-L2). Bounds teardown so
/// a slow/black-holed sink can never hang shutdown.
const SHUTDOWN_DRAIN_BUDGET: Duration = Duration::from_secs(2);

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

impl DispatcherConfig {
    /// Override the per-sink spool root (e.g. mapped from the schema
    /// `Events.spool_dir`). Chainable, additive, preserves every other field.
    #[must_use]
    pub fn with_spool_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.spool_root = root.into();
        self
    }

    /// Override the per-sink spool size cap in bytes (e.g. mapped from the
    /// schema `Events.spool_max_bytes`). Other [`SpoolConfig`] fields keep
    /// their current values.
    #[must_use]
    pub fn with_spool_max_bytes(mut self, max_bytes: u64) -> Self {
        self.spool.max_bytes = max_bytes;
        self
    }

    /// Replace the whole [`SpoolConfig`] for finer control.
    #[must_use]
    pub fn with_spool(mut self, spool: SpoolConfig) -> Self {
        self.spool = spool;
        self
    }

    /// Override how often the retry task drains spools (e.g. mapped from the
    /// schema `Events.retry_interval`).
    #[must_use]
    pub fn with_retry_interval(mut self, retry_interval: Duration) -> Self {
        self.retry_interval = retry_interval;
        self
    }
}

/// Running dispatcher.
pub struct Dispatcher {
    join: Mutex<Option<JoinHandle<()>>>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
    /// Background spool-retry task that periodically redelivers spooled
    /// events for sinks that have since recovered.
    retry_join: Mutex<Option<JoinHandle<()>>>,
    retry_shutdown: Mutex<Option<oneshot::Sender<()>>>,
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
            let spool = DiskSpool::open(dir, cfg.spool.clone())
                .map_err(|e| std::io::Error::other(format!("open spool for {name}: {e}")))?;
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
                    _ = &mut sd_rx => {
                        // F-L2: before exiting, drain events still buffered in
                        // the broadcast receiver (last-gasp lifecycle/profile-stop
                        // events emitted during orchestrator shutdown). Each is
                        // delivered to its sinks or spooled on failure — not
                        // silently dropped. Bounded by SHUTDOWN_DRAIN_BUDGET so
                        // teardown cannot hang.
                        let _ = tokio::time::timeout(
                            SHUTDOWN_DRAIN_BUDGET,
                            inner_for_task.drain_buffered(&mut rx),
                        )
                        .await;
                        break;
                    }
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

        // Spool-retry task: every `retry_interval`, attempt to drain each
        // sink whose spool is non-empty. A sink that has healed redelivers its
        // backlog; a sink still failing re-spools and we try again next tick.
        // M-1 (defensive): `tokio::time::interval` PANICS on a zero period.
        // Config validation rejects a zero `events.retry_interval`, but a config
        // built programmatically (bypassing validation) could still carry one;
        // clamp a non-positive interval up to the default cadence so spawning the
        // dispatcher can never abort the process.
        let retry_interval = if inner.cfg.retry_interval.is_zero() {
            tracing::warn!(
                "events.retry_interval is zero; clamping to 30s (a zero interval would panic \
                 tokio::time::interval)"
            );
            std::time::Duration::from_secs(30)
        } else {
            inner.cfg.retry_interval
        };
        let (retry_sd_tx, mut retry_sd_rx) = oneshot::channel();
        let inner_for_retry = inner.clone();
        let retry_join = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(retry_interval);
            // The first immediate tick is uninteresting (nothing spooled yet);
            // skip it so the first real attempt happens after one interval.
            ticker.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = &mut retry_sd_rx => break,
                    _ = ticker.tick() => {
                        inner_for_retry.drain_pending_spools().await;
                    }
                }
            }
        });

        Ok(Self {
            join: Mutex::new(Some(join)),
            shutdown: Mutex::new(Some(sd_tx)),
            retry_join: Mutex::new(Some(retry_join)),
            retry_shutdown: Mutex::new(Some(retry_sd_tx)),
        })
    }

    /// Stop the dispatcher and wait for it to drain.
    pub async fn shutdown(self) {
        if let Some(tx) = self.retry_shutdown.lock().take() {
            let _ = tx.send(());
        }
        if let Some(tx) = self.shutdown.lock().take() {
            let _ = tx.send(());
        }
        let retry_join = self.retry_join.lock().take();
        if let Some(j) = retry_join {
            let _ = j.await;
        }
        let join = self.join.lock().take();
        if let Some(j) = join {
            let _ = j.await;
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        if let Some(tx) = self.retry_shutdown.lock().take() {
            let _ = tx.send(());
        }
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
    /// Dispatcher config; consumed by the spool-retry task (`retry_interval`).
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
            // Peek WITHOUT removing (at-least-once): only delete after the sink
            // confirms delivery, so a crash mid-delivery re-delivers instead of
            // losing the event.
            let entry = {
                let g = spool.lock();
                match g.peek() {
                    Ok(Some(e)) => e,
                    Ok(None) | Err(_) => return,
                }
            };
            let Ok(ev) = serde_json::from_slice::<Event>(&entry.payload) else {
                // Undecodable payload: it can never be delivered, and leaving it
                // at the front would loop forever. Quarantine (move-aside) so the
                // drain makes progress — bounded: one entry leaves per pass.
                tracing::warn!(
                    sink = %sink_name,
                    seq = entry.seq,
                    "spool entry is undecodable; quarantining poison entry"
                );
                spool.lock().quarantine(entry.seq);
                continue;
            };
            let arc = Arc::new(ev);
            match sink.deliver(arc).await {
                Ok(()) => {
                    // Delivered: now safe to delete. Passing the peeked seq keeps
                    // FIFO intact and avoids deleting an entry evicted meanwhile.
                    spool.lock().remove(entry.seq);
                }
                Err(e) if e.is_retryable() => {
                    // Transient: leave the entry spooled in place (original seq,
                    // original position) and stop draining. The retry task tries
                    // again next tick — ordering across retries is preserved.
                    return;
                }
                Err(e) => {
                    // Permanent failure: this entry will never be accepted.
                    // Remove it so it cannot wedge the drain, and log.
                    tracing::warn!(
                        sink = %sink_name,
                        seq = entry.seq,
                        error = %e,
                        "spooled event rejected permanently; dropping"
                    );
                    spool.lock().remove(entry.seq);
                }
            }
        }
    }

    /// Drain events already buffered in `rx` on shutdown, dispatching each
    /// through the normal binding/sink path (delivered, or spooled on transient
    /// failure). Stops as soon as the receiver is empty or closed. Callers bound
    /// the total time (see [`SHUTDOWN_DRAIN_BUDGET`]); this method itself does
    /// not block on new events.
    pub async fn drain_buffered(&self, rx: &mut broadcast::Receiver<Arc<Event>>) {
        loop {
            match rx.try_recv() {
                Ok(ev) => self.dispatch(ev).await,
                Err(broadcast::error::TryRecvError::Lagged(n)) => {
                    tracing::warn!(skipped = n, "event dispatcher lagged during shutdown drain");
                }
                Err(
                    broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed,
                ) => break,
            }
        }
    }

    /// Drain every sink whose spool currently holds at least one entry.
    ///
    /// Called on each retry tick by the background task spawned in
    /// [`Dispatcher::spawn`]. Sinks with empty spools are skipped (no sink
    /// I/O); sinks still failing re-spool inside [`Self::drain_spool`] and are
    /// retried on the next tick.
    pub async fn drain_pending_spools(&self) {
        // Snapshot the names with a non-empty spool first so we don't hold the
        // per-spool lock across the `.await` in `drain_spool`.
        let pending: Vec<String> = self
            .spools
            .iter()
            .filter(|(_, s)| !s.lock().is_empty()) // 1.88 lint: len_zero
            .map(|(name, _)| name.clone())
            .collect();
        for name in pending {
            self.drain_spool(&name).await;
        }
    }

    /// Spool size for a sink (helper for tests).
    pub fn spool_len(&self, sink_name: &str) -> usize {
        self.spools.get(sink_name).map_or(0, |s| s.lock().len())
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

    /// Test sink that records delivered event kinds in order and can be told to
    /// fail its next `n` deliveries with a transient (retryable) error.
    struct RecordingSink {
        name: String,
        delivered: Mutex<Vec<String>>,
        fail_next: Mutex<usize>,
    }

    impl RecordingSink {
        fn new(name: &str) -> Arc<Self> {
            Arc::new(Self {
                name: name.into(),
                delivered: Mutex::new(Vec::new()),
                fail_next: Mutex::new(0),
            })
        }
        fn fail_next(&self, n: usize) {
            *self.fail_next.lock() = n;
        }
        fn kinds(&self) -> Vec<String> {
            self.delivered.lock().clone()
        }
    }

    #[async_trait::async_trait]
    impl Sink for RecordingSink {
        fn name(&self) -> &str {
            &self.name
        }
        fn kind(&self) -> &'static str {
            "recording"
        }
        async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError> {
            {
                let mut n = self.fail_next.lock();
                if *n > 0 {
                    *n -= 1;
                    return Err(SinkError::Transient("boom".into()));
                }
            }
            self.delivered.lock().push(event.kind.as_str().to_string());
            Ok(())
        }
    }

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

        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
        assert_eq!(t.requests().len(), 1, "second event should be deduped");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn permanent_failure_path_logs_no_spool() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let t = Arc::new(RecordingTransport::new());
        t.fail_once(SinkError::Permanent("4xx".into()));
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
        let bindings = vec![make_binding(vec!["k"], vec!["alerts"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();
        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
        assert_eq!(d.spool_len("alerts"), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_spool_unknown_sink_returns_quickly() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let d = build_for_test(Vec::new(), HashMap::new(), cfg).unwrap();
        d.drain_spool("nope").await;
        assert_eq!(d.spool_len("nope"), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_spool_re_spools_on_repeated_transient() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let t = Arc::new(RecordingTransport::new());
        t.fail_once(SinkError::Transient("net".into()));
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
        let bindings = vec![make_binding(vec!["k"], vec!["alerts"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();
        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
        t.fail_once(SinkError::Transient("still down".into()));
        d.drain_spool("alerts").await;
        assert_eq!(d.spool_len("alerts"), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_delivers_before_delete_and_preserves_fifo_order() {
        // MED-1: two events spool via the live path (transient failures), then
        // the healed sink redelivers them in their ORIGINAL order on drain and
        // the spool empties. Pre-fix the re-spool assigned a new back-of-queue
        // seq, breaking FIFO; here order is preserved and nothing is lost.
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let sink = RecordingSink::new("r");
        sink.fail_next(2); // fail both live deliveries so both spool
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("r".into(), sink.clone() as Arc<dyn Sink>);
        let bindings = vec![make_binding(vec!["k*"], vec!["r"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        d.dispatch(Arc::new(Event::builder("k1", Severity::Info).build()))
            .await;
        d.dispatch(Arc::new(Event::builder("k2", Severity::Info).build()))
            .await;
        assert_eq!(d.spool_len("r"), 2, "both transient failures spool");
        assert!(sink.kinds().is_empty(), "nothing delivered yet");

        // Healed: drain redelivers in FIFO order and clears the spool.
        d.drain_spool("r").await;
        assert_eq!(d.spool_len("r"), 0, "spool drained clean");
        assert_eq!(
            sink.kinds(),
            vec!["k1".to_string(), "k2".to_string()],
            "redelivered in original order"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_leaves_entry_spooled_on_transient_and_redelivers_next_drain() {
        // MED-1: a delivery failure during drain must LEAVE the entry spooled
        // (deliver-before-delete), and a later drain redelivers it. Pre-fix the
        // entry was popped (deleted) before delivery, so a failure lost it.
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let sink = RecordingSink::new("r");
        sink.fail_next(1); // fail the initial live delivery so it spools
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("r".into(), sink.clone() as Arc<dyn Sink>);
        let bindings = vec![make_binding(vec!["k*"], vec!["r"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        d.dispatch(Arc::new(Event::builder("k1", Severity::Info).build()))
            .await;
        assert_eq!(d.spool_len("r"), 1);

        // Drain while the sink is still failing: entry stays spooled.
        sink.fail_next(1);
        d.drain_spool("r").await;
        assert_eq!(
            d.spool_len("r"),
            1,
            "transient failure leaves entry spooled"
        );
        assert!(sink.kinds().is_empty(), "not delivered while failing");

        // Now healed: the very same event redelivers and the spool clears.
        d.drain_spool("r").await;
        assert_eq!(d.spool_len("r"), 0);
        assert_eq!(sink.kinds(), vec!["k1".to_string()]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_quarantines_poison_entry_without_infinite_loop() {
        // MED-1: an undecodable spool entry must be moved aside (quarantined)
        // so the drain makes progress and terminates — pre-fix `pop` deleted it
        // silently, but with peek-based drains a non-quarantining loop would spin
        // forever on the same front entry.
        let tmp = tempdir().unwrap();
        let sink_dir = tmp.path().join("r");
        std::fs::create_dir_all(&sink_dir).unwrap();
        // Write a garbage entry directly into the sink's spool dir so `open`
        // loads it into the queue.
        let garbage = sink_dir.join(format!("{:020}.bin", 1));
        std::fs::write(&garbage, b"not json at all").unwrap();

        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let sink = RecordingSink::new("r");
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("r".into(), sink.clone() as Arc<dyn Sink>);
        let bindings = vec![make_binding(vec!["k*"], vec!["r"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();
        assert_eq!(d.spool_len("r"), 1, "garbage entry loaded on open");

        // Must terminate (bounded), quarantine the poison, and never deliver.
        d.drain_spool("r").await;
        assert_eq!(d.spool_len("r"), 0, "poison entry removed from queue");
        assert!(sink.kinds().is_empty(), "poison never delivered");
        assert!(
            sink_dir.join(format!("{:020}.bin.poison", 1)).exists(),
            "poison bytes retained in a .poison sidecar"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_drain_delivers_buffered_events_not_dropped() {
        // F-L2: events already buffered in the broadcast receiver at shutdown
        // must be delivered, not silently dropped. Pre-fix the loop broke
        // immediately on the shutdown signal and never drained `rx`.
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let sink = RecordingSink::new("r");
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("r".into(), sink.clone() as Arc<dyn Sink>);
        let bindings = vec![make_binding(vec!["k*"], vec!["r"])];

        let bus = EventBus::new(&crate::bus::EventBusConfig::default());
        let mut rx = bus.subscribe();
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        // Buffer several events with no live consumer draining them.
        for i in 0..5 {
            bus.emit(Event::builder(format!("k{i}"), Severity::Info).build());
        }
        // Simulate the shutdown-time drain.
        d.drain_buffered(&mut rx).await;
        assert_eq!(
            sink.kinds().len(),
            5,
            "all buffered events delivered on shutdown drain"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn shutdown_drain_spools_failed_delivery_not_dropped() {
        // F-L2: a buffered event whose delivery fails transiently during the
        // shutdown drain must be spooled (durable), not dropped.
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let sink = RecordingSink::new("r");
        sink.fail_next(1);
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("r".into(), sink.clone() as Arc<dyn Sink>);
        let bindings = vec![make_binding(vec!["k*"], vec!["r"])];

        let bus = EventBus::new(&crate::bus::EventBusConfig::default());
        let mut rx = bus.subscribe();
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        bus.emit(Event::builder("k1", Severity::Info).build());
        d.drain_buffered(&mut rx).await;
        assert_eq!(d.spool_len("r"), 1, "failed shutdown delivery is spooled");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unknown_sink_in_binding_is_skipped() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert(
            "exists".into(),
            Arc::new(HttpSink::new(
                "exists",
                "POST",
                "https://x",
                "{}",
                "application/json",
                HttpAuth::None,
                Arc::new(RecordingTransport::new()),
            )) as Arc<dyn Sink>,
        );
        let bindings = vec![make_binding(vec!["k"], vec!["does-not-exist"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();
        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatcher_config_default_values() {
        let c = DispatcherConfig::default();
        assert_eq!(c.retry_interval, Duration::from_secs(30));
        assert!(!c.strict_redaction);
        assert!(c.spool.max_bytes > 0);
        assert!(c.spool.max_files > 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn config_builders_set_retry_interval_and_spool() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig::default()
            .with_spool_root(tmp.path())
            .with_retry_interval(Duration::from_millis(123))
            .with_spool_max_bytes(4096);
        assert_eq!(cfg.spool_root, tmp.path());
        assert_eq!(cfg.retry_interval, Duration::from_millis(123));
        assert_eq!(cfg.spool.max_bytes, 4096);
        // Built dispatcher inner uses the chosen spool_root (subdir per sink)
        // and carries the chosen retry_interval in cfg.
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert(
            "alerts".into(),
            Arc::new(HttpSink::new(
                "alerts",
                "POST",
                "https://x",
                "{}",
                "application/json",
                HttpAuth::None,
                Arc::new(RecordingTransport::new()),
            )) as Arc<dyn Sink>,
        );
        let d = build_for_test(Vec::new(), sinks, cfg).unwrap();
        assert_eq!(d.cfg.retry_interval, Duration::from_millis(123));
        assert_eq!(d.cfg.spool.max_bytes, 4096);
        assert!(tmp.path().join("alerts").is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_for_test_creates_spool_subdirs_per_sink() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert(
            "a".into(),
            Arc::new(HttpSink::new(
                "a",
                "POST",
                "https://x",
                "{}",
                "application/json",
                HttpAuth::None,
                Arc::new(RecordingTransport::new()),
            )) as Arc<dyn Sink>,
        );
        sinks.insert(
            "b".into(),
            Arc::new(HttpSink::new(
                "b",
                "POST",
                "https://x",
                "{}",
                "application/json",
                HttpAuth::None,
                Arc::new(RecordingTransport::new()),
            )) as Arc<dyn Sink>,
        );
        let _ = build_for_test(Vec::new(), sinks, cfg).unwrap();
        assert!(tmp.path().join("a").is_dir());
        assert!(tmp.path().join("b").is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn dispatcher_bindings_accessor_returns_configured_bindings() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let bindings = vec![
            make_binding(vec!["a"], vec![]),
            make_binding(vec!["b"], vec![]),
        ];
        let d = build_for_test(bindings, HashMap::new(), cfg).unwrap();
        assert_eq!(d.bindings().len(), 2);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_forwards_emitted_events_to_sink() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let bus = EventBus::new(&crate::bus::EventBusConfig::default());
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

        let bindings = vec![make_binding(vec!["k"], vec!["alerts"])];
        let d = Dispatcher::spawn(&bus, bindings, sinks, cfg).unwrap();

        bus.emit(Event::builder("k", Severity::Info).build());
        for _ in 0..50 {
            if !t.requests().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(t.requests().len(), 1);
        d.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn zero_retry_interval_does_not_panic_at_interval_site() {
        // M-1 (defensive): a zero `retry_interval` reaching
        // `tokio::time::interval` panics (release abort). The dispatcher clamps
        // it to the default cadence, so spawning + emitting must succeed without
        // panicking. Fails against the unclamped code (the spawned retry task
        // panics on `interval(ZERO)`); passes after the clamp.
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            retry_interval: Duration::ZERO,
            ..DispatcherConfig::default()
        };
        let bus = EventBus::new(&crate::bus::EventBusConfig::default());
        let d = Dispatcher::spawn(&bus, Vec::new(), HashMap::new(), cfg).unwrap();
        bus.emit(Event::builder("k", Severity::Info).build());
        // Yield so the spawned retry task gets a chance to construct its ticker.
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        d.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn drain_pending_spools_redelivers_only_nonempty_sinks() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        // Sink "a" will spool one event; sink "b" stays empty.
        let ta = Arc::new(RecordingTransport::new());
        ta.fail_once(SinkError::Transient("down".into()));
        let tb = Arc::new(RecordingTransport::new());
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert(
            "a".into(),
            Arc::new(HttpSink::new(
                "a",
                "POST",
                "https://x",
                "{}",
                "application/json",
                HttpAuth::None,
                ta.clone(),
            )) as Arc<dyn Sink>,
        );
        sinks.insert(
            "b".into(),
            Arc::new(HttpSink::new(
                "b",
                "POST",
                "https://x",
                "{}",
                "application/json",
                HttpAuth::None,
                tb.clone(),
            )) as Arc<dyn Sink>,
        );
        let bindings = vec![make_binding(vec!["k"], vec!["a"])];
        let d = build_for_test(bindings, sinks, cfg).unwrap();

        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
        assert_eq!(d.spool_len("a"), 1, "transient failure should spool");
        assert_eq!(d.spool_len("b"), 0);

        // Recovery: draining all pending spools redelivers "a" and never
        // touches the empty "b".
        d.drain_pending_spools().await;
        assert_eq!(d.spool_len("a"), 0, "healed sink's spool should clear");
        assert_eq!(ta.requests().len(), 1, "spooled event redelivered once");
        assert!(tb.requests().is_empty(), "empty sink not contacted");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawned_retry_task_redelivers_spooled_event_after_recovery() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            // Short interval so the test does not wait the 30s default.
            retry_interval: Duration::from_millis(20),
            ..DispatcherConfig::default()
        };
        let bus = EventBus::new(&crate::bus::EventBusConfig::default());
        let t = Arc::new(RecordingTransport::new());
        // The very first delivery (via the live dispatch path) fails
        // transiently and spools; the retry task's redelivery then succeeds.
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
        let bindings = vec![make_binding(vec!["k"], vec!["alerts"])];
        let d = Dispatcher::spawn(&bus, bindings, sinks, cfg).unwrap();

        // Emit one event: the live delivery fails and spools it.
        bus.emit(Event::builder("k", Severity::Info).build());

        // The background retry task should drain the spool once the sink heals.
        let mut redelivered = false;
        for _ in 0..200 {
            if t.requests().len() == 1 {
                redelivered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            redelivered,
            "retry task should have redelivered the spooled event"
        );
        d.shutdown().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spawn_drop_triggers_shutdown_without_panic() {
        let tmp = tempdir().unwrap();
        let cfg = DispatcherConfig {
            spool_root: tmp.path().into(),
            ..DispatcherConfig::default()
        };
        let bus = EventBus::new(&crate::bus::EventBusConfig::default());
        let sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        let d = Dispatcher::spawn(&bus, Vec::new(), sinks, cfg).unwrap();
        drop(d);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    #[test]
    fn open_spool_fails_when_root_is_a_file() {
        let tmp = tempdir().unwrap();
        let path = tmp.path().join("blocking");
        std::fs::write(&path, b"blocked").unwrap();
        let cfg = DispatcherConfig {
            spool_root: path,
            ..DispatcherConfig::default()
        };
        let err = match build_for_test(Vec::new(), HashMap::new(), cfg) {
            Ok(_) => panic!("expected an IO error"),
            Err(e) => e,
        };
        assert!(err.kind() != std::io::ErrorKind::NotFound);
    }
}
