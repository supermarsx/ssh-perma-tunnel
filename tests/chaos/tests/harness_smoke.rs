//! Smoke tests for C1 harness infrastructure.
//!
//! These tests exercise the harness's plumbing — the actual reconnect
//! scenarios (12 of them) land in `src/scenarios/` via C2.

#![deny(unsafe_op_in_unsafe_fn)]

use std::sync::Arc;
use std::time::Duration;

use spt_chaos_proxy::ChaosBehaviour;
use spt_chaos_tests::{AuditEvent, ChaosHarness, MockAuditSink};
use spt_supervisor::reconnect::{install_test_hook, ReconnectObserver};

#[tokio::test]
async fn harness_launches_spt_against_proxy() {
    // C1: "launch" does NOT spawn the `spt` binary — see SptProcess.
    // It DOES bring up the chaos proxy + stub SSH server and wire the
    // observer. Assert all three.
    let h = ChaosHarness::launch(ChaosBehaviour::Pristine).await;

    // Proxy is bound to a real loopback port.
    let addr = h.proxy_addr();
    assert!(addr.ip().is_loopback());
    assert_ne!(addr.port(), 0, "proxy must have a concrete port");

    // SshServer is up.
    assert!(h.ssh_server.addr().ip().is_loopback());

    // Subprocess slot is empty in C1.
    assert!(!h.spt_bin.is_spawned());

    h.shutdown().await;
}

#[tokio::test]
async fn harness_captures_audit_events() {
    // Drive a synthetic reconnect attempt through the supervisor hook and
    // assert the harness recorded it.
    let h = ChaosHarness::launch(ChaosBehaviour::LatencyMs(10)).await;

    // First event should be HarnessLaunched.
    let first = h.audit_events();
    assert!(
        matches!(first.first(), Some(AuditEvent::HarnessLaunched(_))),
        "expected HarnessLaunched, got {first:?}"
    );

    // Fire a supervisor-side notification — this exercises the
    // install_test_hook / on_attempt path that C2 scenarios will rely on.
    spt_supervisor::reconnect::notify_attempt_for_test(3, Duration::from_millis(250));

    // Give the observer a brief moment to land the event.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let evs = h.audit_events();
    let saw_attempt = evs.iter().any(|e| {
        matches!(
            e,
            AuditEvent::ReconnectAttempted {
                attempt: 3,
                delay_ms: 250
            }
        )
    });
    assert!(saw_attempt, "expected ReconnectAttempted, got {evs:?}");

    // observe_reconnect_attempts surfaces the same data shape.
    let observed = h.observe_reconnect_attempts(Duration::from_millis(100)).await;
    assert!(observed.iter().any(|r| r.attempt == 3
        && r.delay == Duration::from_millis(250)));

    h.shutdown().await;
}

/// Verifies a custom `ReconnectObserver` can replace the harness's
/// internal observer. This is the seam C2 will use for scenario-specific
/// matchers.
#[tokio::test]
async fn install_test_hook_accepts_custom_observer() {
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Counter(AtomicU32);
    impl ReconnectObserver for Counter {
        fn on_attempt(&self, _: u32, _: Duration) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn on_success(&self, _: u32) {}
        fn on_max_exhausted(&self, _: u32) {}
    }

    let c = Arc::new(Counter(AtomicU32::new(0)));
    let _prev = install_test_hook(c.clone());

    spt_supervisor::reconnect::notify_attempt_for_test(1, Duration::from_millis(5));
    spt_supervisor::reconnect::notify_attempt_for_test(2, Duration::from_millis(10));

    assert_eq!(c.0.load(Ordering::SeqCst), 2);
    let _ = spt_supervisor::reconnect::clear_test_hook();
}

/// MockAuditSink standalone — useful as a sanity test for the data
/// container before C2 starts driving it from scenario code.
#[test]
fn mock_audit_sink_collects_and_clears() {
    let s = MockAuditSink::new();
    assert!(s.events().is_empty());
    s.push(AuditEvent::Note("a".into()));
    s.push(AuditEvent::Note("b".into()));
    assert_eq!(s.events().len(), 2);
    s.clear();
    assert!(s.events().is_empty());
}
