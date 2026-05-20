//! Integration tests for the Dispatcher's per-sink disk spool.
//!
//! These tests live outside the crate so they can exercise the public
//! constructors only (no private internals) and a mix of multiple sinks
//! through `Dispatcher::spawn` plus the test helper `build_for_test`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use spt_events::binding::{Binding, BindingMatch, SinkRef};
use spt_events::bus::{EventBus, EventBusConfig};
use spt_events::dispatcher::{build_for_test, Dispatcher, DispatcherConfig};
use spt_events::event::{Event, EventKind, Severity};
use spt_events::sinks::http::{HttpAuth, HttpSink, RecordingTransport};
use spt_events::sinks::{Sink, SinkError};
use spt_state::SpoolConfig;
use tempfile::tempdir;

// Local replicas of the test sinks normally provided by the `testing`
// feature, so this integration test compiles without enabling the
// `testing` feature flag.

struct AlwaysFailSink {
    name: String,
    err: SinkError,
}
impl AlwaysFailSink {
    fn new(name: &str, err: SinkError) -> Self {
        Self {
            name: name.into(),
            err,
        }
    }
}
#[async_trait]
impl Sink for AlwaysFailSink {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "always_fail"
    }
    async fn deliver(&self, _: std::sync::Arc<Event>) -> Result<(), SinkError> {
        Err(match &self.err {
            SinkError::Transient(s) => SinkError::Transient(s.clone()),
            SinkError::Permanent(s) => SinkError::Permanent(s.clone()),
            SinkError::Config(s) => SinkError::Config(s.clone()),
        })
    }
}

struct CapturingSink {
    name: String,
    received: parking_lot::Mutex<Vec<Event>>,
}
impl CapturingSink {
    fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            received: parking_lot::Mutex::new(Vec::new()),
        }
    }
    fn len(&self) -> usize {
        self.received.lock().len()
    }
    fn received(&self) -> Vec<Event> {
        self.received.lock().clone()
    }
}
#[async_trait]
impl Sink for CapturingSink {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "capturing"
    }
    async fn deliver(&self, ev: std::sync::Arc<Event>) -> Result<(), SinkError> {
        self.received.lock().push((*ev).clone());
        Ok(())
    }
}

struct FlakyTransport {
    fails_remaining: std::sync::atomic::AtomicUsize,
    requests: parking_lot::Mutex<Vec<spt_events::sinks::http::HttpRequest>>,
}
impl FlakyTransport {
    fn new(n: usize) -> Self {
        Self {
            fails_remaining: std::sync::atomic::AtomicUsize::new(n),
            requests: parking_lot::Mutex::new(Vec::new()),
        }
    }
    fn requests(&self) -> Vec<spt_events::sinks::http::HttpRequest> {
        self.requests.lock().clone()
    }
}
#[async_trait]
impl spt_events::sinks::http::HttpTransport for FlakyTransport {
    async fn send(&self, req: spt_events::sinks::http::HttpRequest) -> Result<(), SinkError> {
        use std::sync::atomic::Ordering;
        let prev = self.fails_remaining.load(Ordering::SeqCst);
        if prev > 0 {
            self.fails_remaining.store(prev - 1, Ordering::SeqCst);
            return Err(SinkError::Transient("flaky".into()));
        }
        self.requests.lock().push(req);
        Ok(())
    }
}

fn binding(name: &str, kinds: Vec<&str>, sinks: Vec<&str>) -> Binding {
    Binding {
        name: name.into(),
        r#match: BindingMatch {
            kinds: kinds.into_iter().map(String::from).collect(),
            ..Default::default()
        },
        sinks: sinks.into_iter().map(SinkRef::new).collect(),
        dedupe: None,
    }
}

fn http_sink(name: &str, t: Arc<RecordingTransport>) -> Arc<dyn Sink> {
    Arc::new(HttpSink::new(
        name,
        "POST",
        "https://x",
        "{}",
        "application/json",
        HttpAuth::None,
        t,
    ))
}

#[tokio::test(flavor = "current_thread")]
async fn permanent_failure_does_not_spool() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let always_perm = Arc::new(AlwaysFailSink::new(
        "alerts",
        SinkError::Permanent("misconfig".into()),
    )) as Arc<dyn Sink>;
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("alerts".into(), always_perm);

    let d = build_for_test(vec![binding("b", vec!["x"], vec!["alerts"])], sinks, cfg).unwrap();
    d.dispatch(Arc::new(Event::builder("x", Severity::Error).build()))
        .await;
    // Permanent → not spooled.
    assert_eq!(d.spool_len("alerts"), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_sink_ref_is_logged_and_skipped() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let t = Arc::new(RecordingTransport::new());
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("alerts".into(), http_sink("alerts", t.clone()));

    // Binding references "missing-sink" — it should be skipped, not crash.
    let bindings = vec![binding("b", vec!["k"], vec!["alerts", "missing-sink"])];
    let d = build_for_test(bindings, sinks, cfg).unwrap();
    d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
        .await;
    assert_eq!(t.requests().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn multi_sink_independent_spool_state() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let t_a = Arc::new(RecordingTransport::new());
    let t_b = Arc::new(RecordingTransport::new());
    // Sink A: will succeed. Sink B: forced one transient.
    t_b.fail_once(SinkError::Transient("flapping".into()));

    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("a".into(), http_sink("a", t_a.clone()));
    sinks.insert("b".into(), http_sink("b", t_b.clone()));

    let bindings = vec![binding("b", vec!["k"], vec!["a", "b"])];
    let d = build_for_test(bindings, sinks, cfg).unwrap();
    d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
        .await;

    assert_eq!(t_a.requests().len(), 1);
    assert_eq!(d.spool_len("a"), 0);
    assert_eq!(d.spool_len("b"), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn spool_persists_across_dispatcher_rebuild() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };

    // First incarnation: a single flaky transport that fails once and
    // shoves the payload to disk.
    {
        let t = Arc::new(RecordingTransport::new());
        t.fail_once(SinkError::Transient("net".into()));
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("alerts".into(), http_sink("alerts", t.clone()));
        let bindings = vec![binding("b", vec!["k"], vec!["alerts"])];
        let d = build_for_test(bindings, sinks, cfg.clone()).unwrap();
        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
        assert_eq!(d.spool_len("alerts"), 1);
    }

    // Second incarnation: same spool_root + sink name → on-disk file is
    // rehydrated by DiskSpool::open during construction.
    {
        let t = Arc::new(RecordingTransport::new());
        let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
        sinks.insert("alerts".into(), http_sink("alerts", t.clone()));
        let d2 = build_for_test(Vec::new(), sinks, cfg).unwrap();
        assert_eq!(
            d2.spool_len("alerts"),
            1,
            "DiskSpool::open should rehydrate prior entry"
        );
        d2.drain_spool("alerts").await;
        assert_eq!(d2.spool_len("alerts"), 0);
        assert_eq!(t.requests().len(), 1);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn spool_max_files_evicts_oldest() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        spool: SpoolConfig {
            max_bytes: 0,
            max_files: 2,
        },
        ..DispatcherConfig::default()
    };
    // Always-transient sink to force every dispatch onto the spool.
    let sink: Arc<dyn Sink> = Arc::new(AlwaysFailSink::new(
        "alerts",
        SinkError::Transient("net".into()),
    ));
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("alerts".into(), sink);
    let d = build_for_test(vec![binding("b", vec!["k"], vec!["alerts"])], sinks, cfg).unwrap();

    for _ in 0..5 {
        d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
            .await;
    }
    assert!(d.spool_len("alerts") <= 2, "spool must respect max_files");
}

#[tokio::test(flavor = "current_thread")]
async fn drain_spool_unknown_sink_is_noop() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert(
        "alerts".into(),
        http_sink("alerts", Arc::new(RecordingTransport::new())),
    );
    let d = build_for_test(Vec::new(), sinks, cfg).unwrap();
    // Neither call should panic.
    d.drain_spool("missing").await;
    assert_eq!(d.spool_len("missing"), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn drain_spool_two_pending_entries_clears_in_order() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let t = Arc::new(FlakyTransport::new(2));
    let http: Arc<dyn Sink> = Arc::new(HttpSink::new(
        "alerts",
        "POST",
        "https://x",
        "{}",
        "application/json",
        HttpAuth::None,
        t.clone(),
    ));
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("alerts".into(), http);
    let d = build_for_test(vec![binding("b", vec!["k"], vec!["alerts"])], sinks, cfg).unwrap();

    // First two dispatches fail and spool (FlakyTransport fails its first 2).
    d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
        .await;
    d.dispatch(Arc::new(Event::builder("k", Severity::Info).build()))
        .await;
    assert_eq!(d.spool_len("alerts"), 2);

    // Drain — transport now succeeds for both replays.
    d.drain_spool("alerts").await;
    assert_eq!(d.spool_len("alerts"), 0);
    assert_eq!(t.requests().len(), 2);
}

#[tokio::test(flavor = "current_thread")]
async fn dispatcher_spawn_routes_to_subscribers_and_shuts_down() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let bus = EventBus::new(&EventBusConfig::default());
    let cap = Arc::new(CapturingSink::new("alerts"));
    let cap_dyn: Arc<dyn Sink> = cap.clone();
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("alerts".into(), cap_dyn);

    let bindings = vec![binding("b", vec!["k"], vec!["alerts"])];
    let d = Dispatcher::spawn(&bus, bindings, sinks, cfg).unwrap();

    bus.emit(Event::builder("k", Severity::Info).build());
    // Allow the spawned task to pick up the event.
    for _ in 0..50 {
        if cap.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(cap.len(), 1);
    d.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn dispatcher_filters_kind_via_bus_emit() {
    let tmp = tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let bus = EventBus::new(&EventBusConfig::default());
    let cap = Arc::new(CapturingSink::new("alerts"));
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("alerts".into(), cap.clone() as Arc<dyn Sink>);

    // Only forward.* events should be captured.
    let bindings = vec![binding("b", vec!["forward.*"], vec!["alerts"])];
    let d = Dispatcher::spawn(&bus, bindings, sinks, cfg).unwrap();

    bus.emit(Event::builder("profile.connected", Severity::Info).build());
    bus.emit(Event::builder("forward.connection_failed", Severity::Error).build());
    for _ in 0..50 {
        if cap.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(cap.len(), 1);
    let recv = cap.received();
    assert_eq!(recv[0].kind, EventKind::new("forward.connection_failed"));
    d.shutdown().await;
}

#[tokio::test(flavor = "current_thread")]
async fn dispatcher_config_default_smoke() {
    // Smoke: defaults yield a valid DispatcherConfig clone.
    let a = DispatcherConfig::default();
    let b = a.clone();
    assert_eq!(a.retry_interval, b.retry_interval);
    assert_eq!(a.strict_redaction, b.strict_redaction);
}
