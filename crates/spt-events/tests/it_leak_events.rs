//! Dedicated memory-leak / bounded-growth test binary for `spt-events`.
//!
//! Installs [`CountingAllocator`] as the process `#[global_allocator]` (one per
//! dedicated `tests/it_leak_*.rs` bin — never mixed with unit tests). Leak
//! assertions compare the *net-live-byte delta* between two iteration counts
//! with generous slack; bounded-growth assertions use `receiver_count()` /
//! `spool_len()` caps.
//!
//! The test is self-contained (no `spt-events/testing` feature): it defines a
//! tiny in-test capturing sink and builds bindings by hand so the crate's plain
//! `cargo test -p spt-events` gate compiles it without extra features.
//!
//! Coverage:
//! * `subscriber_drop_returns_receiver_count_to_baseline` — dropping
//!   subscribers frees their broadcast slots (no slot leak).
//! * `lagged_subscriber_does_not_grow_unbounded` — a slow subscriber on a
//!   capacity-bounded channel never grows past the channel capacity.
//! * `spool_drain_does_not_leak_across_cycles` — many emit/dispatch/drain
//!   cycles leave the spool empty and live bytes bounded.
//! * `dispatcher_retry_task_joins_on_shutdown` — `shutdown().await` joins both
//!   the dispatch and retry tasks (no leaked task).
//! * `emit_dispatch_alloc_delta_bounded` — emit+dispatch N events at 1k vs 10k:
//!   net live bounded.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;

use spt_events::binding::{Binding, BindingMatch};
use spt_events::bus::{EventBus, EventBusConfig};
use spt_events::dispatcher::{build_for_test, Dispatcher, DispatcherConfig, DispatcherInner};
use spt_events::event::{Event, Severity};
use spt_events::{Sink, SinkError, SinkRef};

use spt_mem_hygiene::testing::CountingAllocator;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

fn ev(kind: &str) -> Event {
    Event::builder(kind, Severity::Info).message("x").build()
}

/// Minimal always-succeeds sink that counts deliveries. Defined in-test to
/// avoid pulling in the `spt-events/testing` feature for the plain test gate.
struct CountingSink {
    name: String,
    count: AtomicUsize,
}

impl CountingSink {
    fn new(name: &str) -> Self {
        Self {
            name: name.into(),
            count: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl Sink for CountingSink {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "counting"
    }
    async fn deliver(&self, _event: Arc<Event>) -> Result<(), SinkError> {
        self.count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

fn binding(kind: &str, sink: &str) -> Binding {
    Binding {
        name: "b".into(),
        r#match: BindingMatch {
            kinds: vec![kind.into()],
            ..Default::default()
        },
        sinks: vec![SinkRef::new(sink)],
        dedupe: None,
        throttle: None,
    }
}

// ---------------------------------------------------------------------------
// Broadcast subscriber slot bookkeeping
// ---------------------------------------------------------------------------

#[test]
fn subscriber_drop_returns_receiver_count_to_baseline() {
    let bus = EventBus::new(&EventBusConfig { capacity: 64 });
    assert_eq!(bus.receiver_count(), 0);

    // Repeatedly create and drop a batch of subscribers; the count must come
    // back to zero each round (no leaked slot in the broadcast channel).
    for _ in 0..1_000 {
        let subs: Vec<_> = (0..16).map(|_| bus.subscribe()).collect();
        assert_eq!(bus.receiver_count(), 16);
        drop(subs);
        assert_eq!(
            bus.receiver_count(),
            0,
            "dropping all subscribers must return receiver_count to baseline"
        );
    }
}

#[test]
fn lagged_subscriber_does_not_grow_unbounded() {
    // A slow/lagged subscriber on a capacity-bounded broadcast channel can
    // never retain more than `capacity` buffered messages: excess is dropped
    // and surfaced as `Lagged`. Emit far more than capacity without reading,
    // then confirm draining yields at most `capacity` real messages (plus the
    // Lagged signal) — i.e. the per-subscriber buffer is bounded.
    let capacity = 8usize;
    let bus = EventBus::new(&EventBusConfig { capacity });
    let mut rx = bus.subscribe();

    for _ in 0..10_000 {
        bus.emit(ev("k"));
    }

    let mut delivered = 0usize;
    let mut lagged = 0usize;
    loop {
        match rx.try_recv() {
            Ok(_) => delivered += 1,
            Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => lagged += 1,
            Err(_) => break,
        }
    }
    assert!(
        delivered <= capacity,
        "buffered messages must be bounded by capacity: delivered={delivered} cap={capacity}"
    );
    assert!(
        lagged >= 1,
        "an overflowed slow subscriber should observe Lagged"
    );
}

// ---------------------------------------------------------------------------
// Dispatcher spool: drain across many cycles
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "current_thread")]
async fn spool_drain_does_not_leak_across_cycles() {
    // Counting sink always succeeds, so emit+dispatch never spools. Run many
    // cycles and assert the spool stays empty and live bytes stay bounded
    // across 1k vs 10k iterations (no per-dispatch retention).
    async fn run(d: &DispatcherInner, iters: usize) -> usize {
        let before = GLOBAL.live_bytes();
        for _ in 0..iters {
            d.dispatch(Arc::new(ev("k"))).await;
            // No transient failure → nothing spooled. Drain anyway to exercise
            // the (empty) drain path each cycle.
            d.drain_spool("cap").await;
        }
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let tmp = tempfile::tempdir().unwrap();
    let cfg = DispatcherConfig {
        spool_root: tmp.path().into(),
        ..DispatcherConfig::default()
    };
    let sink = Arc::new(CountingSink::new("cap"));
    let mut sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
    sinks.insert("cap".into(), sink.clone() as Arc<dyn Sink>);
    let d = build_for_test(vec![binding("k", "cap")], sinks, cfg).unwrap();

    let small = run(&d, 1_000).await;
    let large = run(&d, 10_000).await;
    assert_eq!(
        d.spool_len("cap"),
        0,
        "no transient failures must leave spool empty"
    );
    assert!(
        large <= small + 256 * 1024,
        "emit/dispatch/drain net-live grew with iterations (leak?): 1k={small} 10k={large}"
    );
}

// ---------------------------------------------------------------------------
// No leaked task: dispatcher dispatch + retry tasks join on shutdown
// ---------------------------------------------------------------------------

#[test]
fn dispatcher_retry_task_joins_on_shutdown() {
    // Spawn + shutdown many dispatchers (each spawns a dispatch task AND a
    // spool-retry task). If either task leaked, live bytes would scale with the
    // number of cycles. Compare deltas across 50 vs 500 cycles. Plain `#[test]`
    // so each delta() can build its own runtime without nesting.
    fn delta(cycles: usize) -> usize {
        let before = GLOBAL.live_bytes();
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for _ in 0..cycles {
                let tmp = tempfile::tempdir().unwrap();
                let cfg = DispatcherConfig {
                    spool_root: tmp.path().into(),
                    retry_interval: Duration::from_millis(5),
                    ..DispatcherConfig::default()
                };
                let bus = EventBus::new(&EventBusConfig::default());
                let sinks: HashMap<String, Arc<dyn Sink>> = HashMap::new();
                let d = Dispatcher::spawn(&bus, Vec::new(), sinks, cfg).unwrap();
                tokio::task::yield_now().await;
                // shutdown() returning proves both tasks joined.
                d.shutdown().await;
            }
        });
        drop(rt);
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let small = delta(50);
    let large = delta(500);
    assert!(
        large <= small + 1024 * 1024,
        "dispatcher spawn/shutdown leak suspected: 50x={small} 500x={large}"
    );
}

// ---------------------------------------------------------------------------
// Allocator-delta: emit + dispatch N events at 1k vs 10k
// ---------------------------------------------------------------------------

#[test]
fn emit_dispatch_alloc_delta_bounded() {
    fn run(
        bus: &EventBus,
        rx: &mut tokio::sync::broadcast::Receiver<Arc<Event>>,
        iters: usize,
    ) -> usize {
        let before = GLOBAL.live_bytes();
        for _ in 0..iters {
            bus.emit(ev("k"));
            // Drain so the broadcast buffer doesn't retain (a legitimate
            // bounded buffer, not a leak) — isolates per-emit allocation.
            while rx.try_recv().is_ok() {}
        }
        GLOBAL.live_bytes().saturating_sub(before)
    }

    let bus = EventBus::new(&EventBusConfig { capacity: 64 });
    let mut rx = bus.subscribe();

    let small = run(&bus, &mut rx, 1_000);
    let large = run(&bus, &mut rx, 10_000);
    assert!(
        large <= small + 256 * 1024,
        "emit+dispatch net-live grew with iterations (leak?): 1k={small} 10k={large}"
    );
}
