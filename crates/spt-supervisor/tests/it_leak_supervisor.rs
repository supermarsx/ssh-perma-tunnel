//! Dedicated memory-leak / bounded-growth test binary for `spt-supervisor`.
//!
//! Dedicated test binary so it can install the process-global
//! [`CountingAllocator`] (see `.orchestration/logs/memleak-e2.md`). Never mix
//! with unit tests. Allocator assertions compare deltas at two iteration
//! counts with generous slack — never an absolute floor.
//!
//! Coverage:
//!
//! * Reconnect [`Backoff`] — state across many `next_delay` + `reset` cycles is
//!   a fixed `(cfg, attempt)`; allocator-delta is bounded.
//! * [`InstabilityDetector`] — the disconnect event window is a sliding
//!   `VecDeque` bounded by the time window; sustained churn does not grow it.
//! * Endpoint selectors ([`PolicySelector`] round-robin + legacy
//!   [`EndpointSelector`]) — per-endpoint health/error maps are keyed by a
//!   fixed endpoint set; repeated `next`/`record_*` calls do not grow state.
//! * No-leaked-task — a spawned [`ProfileSupervisor`] (via the testing
//!   [`OrchestratorBuilder`] + [`MockTunnelProtocol`]) joins its background
//!   task on shutdown: after `stop_profile`, the state watcher is closed
//!   (the task has exited), proving no task is leaked.

use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::SeedableRng;
use spt_config::round_robin::{RoundRobinConfig, SelectionPolicy};
use spt_core::Error;
use spt_mem_hygiene::testing::CountingAllocator;
use spt_protocol::Endpoint;
use spt_supervisor::failover::{EndpointSelector as LegacySelector, FailoverMode};
use spt_supervisor::instability::{InstabilityDetector, InstabilityWindow};
use spt_supervisor::reconnect::{Backoff, BackoffConfig};
use spt_supervisor::round_robin::{make_selector, EndpointSelector as PolicySelector};
use spt_supervisor::testing::{
    wait_for_state, MockTunnelProtocol, OrchestratorBuilder, ProfileStateName,
};
use tokio::time::Instant;

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator::new();

const SLACK_BYTES: usize = 256 * 1024;

/// Serialize allocator-delta measurements: the `#[global_allocator]` is
/// process-global and tests in this binary run on parallel threads, so a
/// concurrent allocator-heavy test would pollute a `live_bytes()` delta. Each
/// allocator-sensitive test acquires this gate for its full body.
static ALLOC_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn alloc_gate() -> std::sync::MutexGuard<'static, ()> {
    ALLOC_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn live_delta<F: FnMut(usize)>(iters: usize, mut op: F) -> usize {
    GLOBAL.reset_peak();
    let before = GLOBAL.live_bytes();
    for i in 0..iters {
        op(i);
    }
    GLOBAL.live_bytes().saturating_sub(before)
}

fn ep(host: &str, port: u16, weight: u32) -> Endpoint {
    Endpoint {
        host: host.into(),
        port,
        address_family: None,
        priority: 0,
        weight,
    }
}

// ---------------------------------------------------------------------------
// Backoff: bounded state across many reconnect cycles
// ---------------------------------------------------------------------------

#[test]
fn backoff_state_bounded_across_cycles() {
    let _gate = alloc_gate();
    let mut rng = StdRng::seed_from_u64(1);
    let mut b = Backoff::new(BackoffConfig::default());
    let run = |iters: usize, b: &mut Backoff, rng: &mut StdRng| -> usize {
        live_delta(iters, |i| {
            let _ = b.next_delay(rng);
            // Periodically reset so the attempt counter cycles like a real
            // flapping link rather than saturating.
            if i % 8 == 7 {
                b.reset();
            }
        })
    };
    let small = run(10_000, &mut b, &mut rng);
    let large = run(100_000, &mut b, &mut rng);
    assert!(
        large <= small + SLACK_BYTES,
        "Backoff cycle looks like a leak: small={small} large={large}"
    );
}

// ---------------------------------------------------------------------------
// InstabilityDetector: sliding window bounded under churn
// ---------------------------------------------------------------------------

#[test]
fn instability_window_bounded_under_churn() {
    let _gate = alloc_gate();
    let cfg = InstabilityWindow {
        window: Duration::from_secs(10),
        max_disconnects: 3,
        clear_after: Duration::from_secs(30),
    };
    let mut d = InstabilityDetector::new(cfg);
    let base = Instant::now();
    // Feed 100k disconnects spread across time. Because the detector ages out
    // events older than `window`, the event deque can never hold more than
    // roughly `window / inter-event-gap` entries regardless of total events.
    let mut max_count = 0usize;
    for i in 0..100_000u64 {
        // One event per simulated second → at most ~window seconds of events
        // (~10) live at once.
        let now = base + Duration::from_secs(i);
        d.record_disconnect(now);
        max_count = max_count.max(d.count());
        // Heartbeat so the detector can clear and not stay latched forever.
        if i % 50 == 0 {
            d.tick_healthy(now);
        }
    }
    assert!(
        max_count <= 16,
        "instability event window grew unbounded: max_count={max_count} \
         (expected ~window seconds of events, not total event count)"
    );
}

#[test]
fn instability_detector_record_alloc_bounded() {
    let _gate = alloc_gate();
    let cfg = InstabilityWindow {
        window: Duration::from_secs(5),
        max_disconnects: 3,
        clear_after: Duration::from_secs(10),
    };
    let mut d = InstabilityDetector::new(cfg);
    let base = Instant::now();
    let run = |iters: usize, d: &mut InstabilityDetector| -> usize {
        live_delta(iters, |i| {
            let now = base + Duration::from_millis(i as u64 * 500);
            d.record_disconnect(now);
        })
    };
    let small = run(10_000, &mut d);
    let large = run(100_000, &mut d);
    assert!(
        large <= small + SLACK_BYTES,
        "InstabilityDetector record looks like a leak: small={small} large={large}"
    );
}

// ---------------------------------------------------------------------------
// Endpoint selectors: per-endpoint state keyed by a fixed endpoint set
// ---------------------------------------------------------------------------

#[test]
fn policy_selector_state_does_not_grow() {
    let _gate = alloc_gate();
    let cfg = RoundRobinConfig {
        enabled: true,
        policy: SelectionPolicy::LeastErrors,
        cooldown_after_failure: Duration::from_millis(1),
        ..Default::default()
    };
    let endpoints = vec![ep("a", 22, 1), ep("b", 22, 1), ep("c", 22, 1)];
    let mut sel: Box<dyn PolicySelector> =
        make_selector(endpoints, &cfg).expect("enabled selector");

    // Hammer next/record_success/record_failure. Every id is one of the three
    // fixed endpoints, so the internal health/error maps cannot grow beyond 3
    // keys. A leak would show up as linear allocator growth.
    let run = |iters: usize, sel: &mut Box<dyn PolicySelector>| -> usize {
        live_delta(iters, |i| {
            let _ = sel.next();
            let id = match i % 3 {
                0 => "a:22",
                1 => "b:22",
                _ => "c:22",
            };
            if i % 2 == 0 {
                sel.record_failure(id, &Error::NetworkUnreachable("flap".into()));
            } else {
                sel.record_success(id);
            }
        })
    };
    let small = run(10_000, &mut sel);
    let large = run(100_000, &mut sel);
    assert!(
        large <= small + SLACK_BYTES,
        "PolicySelector state looks like a leak: small={small} large={large}"
    );
}

#[test]
fn legacy_selector_state_does_not_grow() {
    let _gate = alloc_gate();
    let endpoints = vec![ep("a", 22, 1), ep("b", 22, 1), ep("c", 22, 1)];
    let mut sel = LegacySelector::new(FailoverMode::Priority, endpoints)
        .with_fail_after(2)
        .with_cooldown(1);
    let mut rng = StdRng::seed_from_u64(7);
    let base = Instant::now();
    let run = |iters: usize, sel: &mut LegacySelector, rng: &mut StdRng| -> usize {
        live_delta(iters, |i| {
            let now = base + Duration::from_millis(i as u64);
            let _ = sel.pick(rng, now);
            let (host, port) = match i % 3 {
                0 => ("a", 22u16),
                1 => ("b", 22),
                _ => ("c", 22),
            };
            if i % 2 == 0 {
                sel.record_failure(host, port, now);
            } else {
                sel.record_success(host, port);
            }
        })
    };
    let small = run(10_000, &mut sel, &mut rng);
    let large = run(100_000, &mut sel, &mut rng);
    assert!(
        large <= small + SLACK_BYTES,
        "legacy EndpointSelector state looks like a leak: small={small} large={large}"
    );
}

// ---------------------------------------------------------------------------
// No-leaked-task: spawned ProfileSupervisor joins on shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn profile_supervisor_task_joins_on_shutdown() {
    let proto = Arc::new(MockTunnelProtocol::new());
    let orch = OrchestratorBuilder::new()
        .with_profile_named("p", proto)
        .build();
    wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(5))
        .await
        .expect("profile should reach Active");

    // Grab a state watcher BEFORE stopping. After the supervisor task exits
    // (joined by stop_profile), the watch sender is dropped, so `changed()`
    // resolves with an Err — observable proof the background task ended rather
    // than leaking.
    let sup = orch.profile_handle("p").expect("running profile");
    let mut rx = sup.watch_state();
    drop(sup);

    orch.stop_profile("p").await;

    // The task is joined inside stop_profile; the watcher must now close. The
    // task holds the only `watch::Sender`, so once it exits, `changed()`
    // resolves with `Err(_)`. Drain any pending state changes until the channel
    // closes; a timeout means the task is still alive (leaked).
    let closed = tokio::time::timeout(Duration::from_secs(5), async {
        while rx.changed().await.is_ok() {
            // A state transition queued before exit — keep draining.
        }
    })
    .await;
    assert!(
        closed.is_ok(),
        "supervisor task did not exit: state watcher still open after shutdown (leaked task)"
    );

    // Profile is gone from the registry too.
    assert!(orch.profile_handle("p").is_none(), "profile not removed");
}

#[tokio::test]
async fn many_supervisor_spawn_shutdown_cycles_do_not_leak_tasks() {
    // Spawn + shut down a profile many times. If each shutdown leaks its task,
    // the runtime accumulates detached tasks; a clean join keeps it flat. We
    // assert behaviourally (every cycle reaches Active then is removed) rather
    // than via the allocator, since tokio task pools muddy allocator deltas.
    for cycle in 0..30 {
        let proto = Arc::new(MockTunnelProtocol::new());
        let orch = OrchestratorBuilder::new()
            .with_profile_named("p", proto)
            .build();
        wait_for_state(&orch, "p", ProfileStateName::Active, Duration::from_secs(5))
            .await
            .unwrap_or_else(|e| panic!("cycle {cycle}: {e}"));
        orch.stop_profile("p").await;
        assert!(
            orch.profile_handle("p").is_none(),
            "cycle {cycle}: profile not removed after stop"
        );
    }
}
