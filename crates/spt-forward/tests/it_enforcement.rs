//! Runtime ENFORCEMENT tests for `spt-forward`.
//!
//! The W2 #7 coverage gap: bind-conflict policy, the token-bucket rate-limit
//! math (now under release `overflow-checks`), the UDP flow-table `max_flows`
//! admission/eviction cap, the idle-timeout / bidir half-close liveness of the
//! copy loop, and the per-second `RateGate` admission cap are config-parsed but
//! under-tested for actual *behaviour*. These tests assert observable
//! enforcement against real loopback sockets / in-memory duplex streams — not
//! that a config string parses.
//!
//! All tests are hermetic: ephemeral `127.0.0.1:0` ports and `tokio::io::duplex`
//! pipes only. No SSH, no external services.

use std::time::Duration;

use spt_forward::{
    bind_with_policy, copy_bidirectional_throttled, copy_bidirectional_throttled_idle,
    ConnectionGate, RateGate, TokenBucket, UdpFlowKey, UdpFlowTable, UdpFlowTableConfig,
};
use spt_protocol::BindConflictPolicy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Bind-conflict policy — enforced at *bind time*, not merely parsed.
// ---------------------------------------------------------------------------

/// `Fail` on a free address binds successfully and reports a concrete port.
#[tokio::test]
async fn bind_fail_succeeds_on_free_port() {
    let bound = bind_with_policy("127.0.0.1:0".parse().unwrap(), BindConflictPolicy::Fail)
        .await
        .unwrap();
    assert_ne!(bound.addr.port(), 0, "must report the OS-chosen port");
    // The listener is live: a connect attempt succeeds.
    let port = bound.addr.port();
    let _conn = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("listener accepts connections");
}

/// `Fail` against an already-bound address surfaces a hard error — the second
/// forward does NOT silently take a different port.
#[tokio::test]
async fn bind_fail_rejects_conflict() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = occupied.local_addr().unwrap();
    let err = bind_with_policy(addr, BindConflictPolicy::Fail)
        .await
        .unwrap_err();
    assert!(
        matches!(err, spt_core::Error::LocalBindFailed { .. }),
        "Fail policy must error on conflict, got {err:?}"
    );
}

/// `NextPort` against an occupied address falls forward to a *different,
/// higher* free port — and that port is actually bound and accepting.
#[tokio::test]
async fn bind_next_port_falls_forward_and_is_live() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = occupied.local_addr().unwrap();
    let bound = bind_with_policy(addr, BindConflictPolicy::NextPort)
        .await
        .unwrap();
    assert_ne!(bound.addr.port(), addr.port());
    assert!(bound.addr.port() > addr.port(), "NextPort increments");
    // The fallen-forward listener is live.
    let _conn = tokio::net::TcpStream::connect(("127.0.0.1", bound.addr.port()))
        .await
        .expect("fallen-forward listener accepts connections");
}

/// `Retry` eventually binds once the conflicting listener is released. The
/// retry loop must observe the freed port rather than giving up.
#[tokio::test]
async fn bind_retry_succeeds_after_release() {
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = occupied.local_addr().unwrap();
    // Release the port shortly after the retry loop starts; the loop's backoff
    // (200ms) gives us a window to drop it before the first retry.
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(occupied);
    });
    let bound = bind_with_policy(addr, BindConflictPolicy::Retry)
        .await
        .expect("Retry must bind once the port is freed");
    assert_eq!(
        bound.addr.port(),
        addr.port(),
        "Retry rebinds the SAME port, not a different one"
    );
}

// ---------------------------------------------------------------------------
// TokenBucket rate-limit math — integer accounting, overflow-safe.
// ---------------------------------------------------------------------------

/// A zero-rate bucket is unlimited: acquire is immediate for any byte count,
/// including a request that would overflow the scaled-units multiply if it
/// were not gated by `is_active()`.
#[tokio::test(start_paused = true)]
async fn token_bucket_zero_rate_is_unlimited_and_overflow_safe() {
    let b = TokenBucket::new(0, 0);
    assert!(!b.is_active());
    // u64::MAX bytes through an unlimited bucket must not panic (no scaled
    // multiply happens because is_active() short-circuits).
    let start = tokio::time::Instant::now();
    b.acquire(u64::MAX).await;
    assert!(start.elapsed() < Duration::from_millis(1));
}

/// A huge `burst` does not overflow construction under release overflow-checks:
/// `burst * NANOS_PER_SEC` is computed with saturating math. The bucket stays
/// usable.
#[test]
fn token_bucket_huge_burst_construction_is_saturating() {
    // burst = u64::MAX would overflow `burst as u128 * 1e9` only if not
    // saturating; the impl uses saturating_mul. Construction must not panic.
    let b = TokenBucket::new(1024, u64::MAX);
    assert_eq!(b.rate_bps(), 1024);
    // A modest acquire still works without panicking.
    assert!(b.try_acquire(1).is_none());
}

/// `try_acquire` past the burst returns a positive wait, and the reported wait
/// is consistent: after the bucket is drained a follow-up request is throttled.
#[test]
fn token_bucket_throttles_past_burst() {
    let b = TokenBucket::new(1000, 1000);
    // Drain the full burst.
    assert!(b.try_acquire(1000).is_none());
    // The next byte must wait — the bucket is empty.
    let wait = b
        .try_acquire(1)
        .expect("a drained bucket must report a wait");
    assert!(wait > Duration::ZERO);
}

/// The cumulative-consumption invariant under a tiny rate and many small
/// zero-wait acquires: bytes consumed never exceed `rate*elapsed + burst`.
/// This is the core throttle correctness property and must hold under
/// overflow-checks (all internal math is u128 saturating).
#[test]
fn token_bucket_never_exceeds_rate_plus_burst() {
    let rate_bps: u64 = 2048;
    let burst: u64 = 2048;
    let b = TokenBucket::new(rate_bps, burst);
    let start = std::time::Instant::now();
    let mut consumed: u128 = 0;
    for _ in 0..2000 {
        if b.try_acquire(64).is_none() {
            consumed += 64;
        }
        let elapsed_nanos = start.elapsed().as_nanos();
        let allowed =
            elapsed_nanos.saturating_mul(u128::from(rate_bps)) / 1_000_000_000 + u128::from(burst);
        assert!(
            consumed <= allowed,
            "consumed {consumed} exceeded rate+burst budget {allowed}"
        );
    }
}

/// End-to-end: a real throttled copy over duplex pipes actually slows
/// throughput. A 4 KiB/s bucket on a 16 KiB payload takes meaningfully long.
#[tokio::test]
async fn throttled_copy_slows_real_throughput() {
    let (mut left_app, mut left_tun) = tokio::io::duplex(64 * 1024);
    let (mut right_tun, mut right_app) = tokio::io::duplex(64 * 1024);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::new(4 * 1024, 4 * 1024),
            TokenBucket::unlimited(),
        )
        .await
    });

    let payload = vec![0x5A; 16 * 1024];
    left_app.write_all(&payload).await.unwrap();
    left_app.shutdown().await.unwrap();
    right_app.shutdown().await.unwrap();

    let start = std::time::Instant::now();
    let mut got = vec![0u8; payload.len()];
    right_app.read_exact(&mut got).await.unwrap();
    let dt = start.elapsed();
    assert!(
        dt >= Duration::from_millis(2000),
        "16 KiB at 4 KiB/s should take >=2s, took {dt:?}"
    );
    assert_eq!(got, payload);
    let _ = bridge.await.unwrap();
}

// ---------------------------------------------------------------------------
// RateGate — new-connection / packets-per-second admission cap.
// ---------------------------------------------------------------------------

/// A rate-0 gate is unlimited: every event admits, the gate reports inactive.
#[tokio::test(start_paused = true)]
async fn rate_gate_zero_is_unlimited() {
    let g = RateGate::new(0, 0);
    assert!(!g.is_active());
    for _ in 0..5000 {
        assert!(g.admit());
    }
}

/// A configured gate admits its burst instantly then denies, and refills at
/// `1/rate` cadence — the cap is actually enforced over time.
#[tokio::test(start_paused = true)]
async fn rate_gate_enforces_per_second_cap() {
    let g = RateGate::new(4, 4);
    assert!(g.is_active());
    for i in 0..4 {
        assert!(g.admit(), "burst slot {i} should admit");
    }
    assert!(!g.admit(), "5th event denied once burst drained");
    // 1/4s later exactly one token refills.
    tokio::time::advance(Duration::from_millis(251)).await;
    assert!(g.admit(), "one token refilled after 1/4s");
    assert!(!g.admit(), "only one token, not two");
}

// ---------------------------------------------------------------------------
// ConnectionGate — concurrent-connection cap (max_flows for TCP).
// ---------------------------------------------------------------------------

/// A capped gate admits exactly `cap` concurrent permits and rejects the next;
/// releasing a permit re-opens a slot.
#[tokio::test]
async fn connection_gate_enforces_cap_and_recovers() {
    let g = ConnectionGate::new(3);
    let p1 = g.try_acquire().expect("slot 1");
    let p2 = g.try_acquire().expect("slot 2");
    let p3 = g.try_acquire().expect("slot 3");
    assert!(g.try_acquire().is_none(), "cap exhausted");
    assert_eq!(g.in_flight(), 3);
    drop(p2);
    let _p4 = g.try_acquire().expect("freed slot reusable");
    assert_eq!(g.in_flight(), 3);
    drop(p1);
    drop(p3);
}

/// A cap-0 gate is unlimited: thousands of permits, never blocks, reports 0
/// in-flight (the documented "unlimited" sentinel).
#[tokio::test]
async fn connection_gate_zero_cap_is_unlimited() {
    let g = ConnectionGate::new(0);
    let permits: Vec<_> = (0..2000).map(|_| g.try_acquire().unwrap()).collect();
    assert_eq!(g.in_flight(), 0);
    drop(permits);
}

// ---------------------------------------------------------------------------
// UDP flow table — max_flows admission cap, eviction, oversized drop, pps.
// ---------------------------------------------------------------------------

fn addr(p: u16) -> std::net::SocketAddr {
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), p)
}

/// `max_flows = N` admits exactly N distinct flows and rejects the (N+1)th,
/// bumping the rejected-full counter. Re-touching an existing flow never
/// counts against the cap.
#[tokio::test]
async fn udp_max_flows_caps_admission() {
    let cfg = UdpFlowTableConfig {
        max_flows: 3,
        ..UdpFlowTableConfig::default()
    };
    let t: UdpFlowTable<UdpFlowKey, u32> = UdpFlowTable::new(cfg);
    assert!(t.touch_or_insert(addr(1), || 1));
    assert!(t.touch_or_insert(addr(2), || 2));
    assert!(t.touch_or_insert(addr(3), || 3));
    assert_eq!(t.len(), 3);
    // Fourth distinct flow is rejected.
    assert!(!t.touch_or_insert(addr(4), || 4));
    assert_eq!(t.rejected_full_count(), 1);
    assert_eq!(t.len(), 3);
    // Re-touching an admitted flow is free.
    assert!(t.touch_or_insert(addr(1), || 99));
    assert_eq!(t.len(), 3);
    assert_eq!(t.rejected_full_count(), 1);
}

/// `max_flows = 0` is explicitly *unbounded*: far more than DEFAULT_MAX_FLOWS
/// distinct flows are all admitted with zero rejections. This is the
/// power-user escape hatch and must NOT silently apply the default cap.
#[tokio::test]
async fn udp_max_flows_zero_is_unbounded() {
    let cfg = UdpFlowTableConfig {
        max_flows: 0,
        ..UdpFlowTableConfig::default()
    };
    let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::new(cfg);
    // 5000 distinct flows; with any finite cap below this we'd see rejects.
    for p in 0..5000u16 {
        assert!(t.touch_or_insert(addr(p), || ()));
    }
    assert_eq!(t.len(), 5000);
    assert_eq!(t.rejected_full_count(), 0, "0 = unbounded, no rejections");
}

/// Idle eviction reclaims flows past the idle timeout, freeing slots so a
/// previously-full table admits new flows again.
#[tokio::test(start_paused = true)]
async fn udp_idle_eviction_frees_slots() {
    let cfg = UdpFlowTableConfig {
        max_flows: 2,
        idle_timeout: Duration::from_secs(10),
        ..UdpFlowTableConfig::default()
    };
    let t: UdpFlowTable<UdpFlowKey, u32> = UdpFlowTable::new(cfg);
    assert!(t.touch_or_insert(addr(1), || 1));
    assert!(t.touch_or_insert(addr(2), || 2));
    assert!(!t.touch_or_insert(addr(3), || 3)); // full
                                                // Age everything past the idle window, then evict.
    tokio::time::advance(Duration::from_secs(20)).await;
    assert_eq!(t.evict_idle(), 2);
    assert!(t.is_empty());
    // A slot is free again.
    assert!(t.touch_or_insert(addr(3), || 3));
    assert_eq!(t.len(), 1);
}

/// Oversized datagrams are rejected and counted; in-bound size at the limit is
/// admitted (boundary check).
#[tokio::test]
async fn udp_oversized_datagram_dropped_at_boundary() {
    let cfg = UdpFlowTableConfig {
        max_datagram_size: 1500,
        ..UdpFlowTableConfig::default()
    };
    let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::new(cfg);
    assert!(t.admit_size(1500), "exactly at the limit is admitted");
    assert!(!t.admit_size(1501), "one over the limit is dropped");
    assert_eq!(t.oversized_count(), 1);
}

/// The packets-per-second gate on the UDP path drops excess datagrams and
/// refills over time.
#[tokio::test(start_paused = true)]
async fn udp_pps_cap_drops_excess() {
    let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::with_pps(UdpFlowTableConfig::default(), 2);
    assert!(t.admit_packet());
    assert!(t.admit_packet());
    assert!(!t.admit_packet(), "burst of 2 drained");
    assert_eq!(t.rejected_pps_count(), 1);
    tokio::time::advance(Duration::from_millis(501)).await;
    assert!(t.admit_packet(), "refilled after 1/2s");
}

// ---------------------------------------------------------------------------
// Bidirectional copy — half-close liveness and idle-timeout enforcement.
// ---------------------------------------------------------------------------

/// A half-close on one side must NOT hang the other: after `a` sends EOF, `b`
/// can still deliver its payload and the copy returns clean per-direction
/// totals.
#[tokio::test]
async fn bidir_half_close_does_not_hang_peer() {
    let (mut left_app, mut left_tun) = tokio::io::duplex(1024);
    let (mut right_tun, mut right_app) = tokio::io::duplex(1024);

    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
        )
        .await
    });

    // Left writes then half-closes its write side.
    left_app.write_all(b"from-left").await.unwrap();
    left_app.shutdown().await.unwrap();

    // The reverse direction must STILL work after the forward half-closed.
    right_app.write_all(b"from-right").await.unwrap();
    right_app.shutdown().await.unwrap();

    let mut got_right = Vec::new();
    right_app.read_to_end(&mut got_right).await.unwrap();
    let mut got_left = Vec::new();
    left_app.read_to_end(&mut got_left).await.unwrap();
    assert_eq!(got_right, b"from-left");
    assert_eq!(got_left, b"from-right");

    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats.a_to_b, 9);
    assert_eq!(stats.b_to_a, 10);
}

/// With an idle timeout configured and NO bytes ever flowing, the copy must
/// self-terminate at the idle deadline instead of blocking forever.
#[tokio::test(start_paused = true)]
async fn bidir_idle_timeout_closes_silent_bridge() {
    let (_left_app, mut left_tun) = tokio::io::duplex(64);
    let (mut right_tun, _right_app) = tokio::io::duplex(64);
    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
            Some(Duration::from_secs(1)),
        )
        .await
    });
    // Push well past two idle windows so the watchdog fires.
    tokio::time::advance(Duration::from_secs(5)).await;
    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats.a_to_b, 0);
    assert_eq!(stats.b_to_a, 0);
}

/// An active bridge whose bytes keep flowing within each idle window must NOT
/// be idle-closed prematurely — the watchdog resets on activity.
#[tokio::test(start_paused = true)]
async fn bidir_idle_timeout_not_triggered_while_active() {
    let (mut left_app, mut left_tun) = tokio::io::duplex(1024);
    let (mut right_tun, mut right_app) = tokio::io::duplex(1024);
    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
            Some(Duration::from_secs(2)),
        )
        .await
    });
    // Keep activity inside the 2s idle window for several rounds.
    for _ in 0..4 {
        left_app.write_all(b"beat").await.unwrap();
        let mut buf = [0u8; 4];
        right_app.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"beat");
        tokio::time::advance(Duration::from_secs(1)).await;
    }
    // Now let it go quiet and close naturally.
    left_app.shutdown().await.unwrap();
    right_app.shutdown().await.unwrap();
    let _ = bridge.await.unwrap();
}

/// The idle path with `None` timeout behaves exactly like the plain throttled
/// copy: payload is delivered and counted, no premature close.
#[tokio::test]
async fn bidir_idle_none_is_plain_copy() {
    let (mut left_app, mut left_tun) = tokio::io::duplex(64);
    let (mut right_tun, mut right_app) = tokio::io::duplex(64);
    let bridge = tokio::spawn(async move {
        copy_bidirectional_throttled_idle(
            &mut left_tun,
            &mut right_tun,
            TokenBucket::unlimited(),
            TokenBucket::unlimited(),
            None,
        )
        .await
    });
    left_app.write_all(b"payload").await.unwrap();
    left_app.shutdown().await.unwrap();
    right_app.shutdown().await.unwrap();
    let mut got = Vec::new();
    right_app.read_to_end(&mut got).await.unwrap();
    assert_eq!(got, b"payload");
    let stats = bridge.await.unwrap().unwrap();
    assert_eq!(stats.a_to_b, 7);
}

// ---------------------------------------------------------------------------
// Shared-bucket composition — one bucket throttling many connections.
// ---------------------------------------------------------------------------

/// A single shared `TokenBucket` (the per-forward / per-profile case) enforces
/// an aggregate cap across cloned handles: total admitted across all clones
/// stays within `rate*elapsed + burst`.
#[test]
fn shared_bucket_enforces_aggregate_cap() {
    let rate_bps: u64 = 1024;
    let burst: u64 = 1024;
    let shared = TokenBucket::new(rate_bps, burst);
    let clones: Vec<TokenBucket> = (0..4).map(|_| shared.clone()).collect();
    let start = std::time::Instant::now();
    let mut consumed: u128 = 0;
    for round in 0..1000 {
        let b = &clones[round % clones.len()];
        if b.try_acquire(32).is_none() {
            consumed += 32;
        }
        let elapsed_nanos = start.elapsed().as_nanos();
        let allowed =
            elapsed_nanos.saturating_mul(u128::from(rate_bps)) / 1_000_000_000 + u128::from(burst);
        assert!(
            consumed <= allowed,
            "shared bucket leaked: {consumed} > {allowed}"
        );
    }
}
