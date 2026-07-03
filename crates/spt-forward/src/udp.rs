//! UDP flow table — NAT-style mapping of (client-src) → upstream socket with
//! idle-eviction and oversized-datagram drop counting.
//!
//! Used by SSH3 (the only backend with UDP support) inside its UDP forwarding
//! task. The table is generic over the per-flow value `V`, so the backend can
//! attach whatever it needs (a QUIC datagram sender, a sequence number, …).

use std::hash::Hash;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::time::Instant;

use crate::limits::{RateGate, TokenBucket};

/// Key into a [`UdpFlowTable`]. Defaults to peer socket address — backends may
/// supply a richer key (e.g. (peer, server-port)) by parameterising the table.
pub type UdpFlowKey = SocketAddr;

/// Configuration for a [`UdpFlowTable`].
#[derive(Debug, Clone, Copy)]
pub struct UdpFlowTableConfig {
    /// Per-flow idle eviction. A flow is dropped if no packet (in either
    /// direction) was observed for this long.
    pub idle_timeout: Duration,
    /// Maximum permitted datagram size in bytes. Larger datagrams bump the
    /// oversized counter and are *not* admitted.
    pub max_datagram_size: u32,
    /// Cap on the number of concurrent flows.
    ///
    /// `0` = unlimited (no hard cap; only idle eviction bounds the table — a
    /// power-user escape hatch). The [`Default`] is [`DEFAULT_MAX_FLOWS`], a
    /// generous-but-finite cap that bounds worst-case memory (a flow entry is
    /// ~100 bytes, so 65536 flows is a few MB) without limiting realistic
    /// concurrent-UDP-flow counts on a single forward. Set this to `0`
    /// explicitly in config to opt back into unbounded behaviour.
    pub max_flows: u32,
}

/// Default hard cap on concurrent UDP flows per table (see
/// [`UdpFlowTableConfig::max_flows`]). Generous enough never to limit a
/// realistic forward, but finite so a runaway flood cannot grow the table
/// without bound. An explicit `max_flows = 0` in config still means unbounded.
pub const DEFAULT_MAX_FLOWS: u32 = 65_536;

impl Default for UdpFlowTableConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            max_datagram_size: 1500,
            max_flows: DEFAULT_MAX_FLOWS,
        }
    }
}

/// A bounded per-flow value. Backends embed any per-flow state they need.
#[derive(Debug)]
struct Entry<V> {
    value: V,
    last_seen: Instant,
}

/// UDP flow table.
#[derive(Debug)]
pub struct UdpFlowTable<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    cfg: UdpFlowTableConfig,
    map: Arc<DashMap<K, Entry<V>>>,
    oversized: Arc<AtomicU64>,
    rejected_full: Arc<AtomicU64>,
    /// Per-datagram packets-per-second admission gate. Unlimited unless a
    /// `max_packets_per_sec` limit was configured via [`UdpFlowTable::with_pps`].
    pps_gate: RateGate,
    /// Count of datagrams dropped because the pps gate was exhausted.
    rejected_pps: Arc<AtomicU64>,
    /// Aggregate byte-rate admission gate across the table. Unlimited unless a
    /// `max_bytes_per_sec` cap was configured via
    /// [`UdpFlowTable::with_byte_rate`].
    byte_gate: TokenBucket,
    /// Count of datagrams dropped because the byte-rate gate was exhausted.
    rejected_bytes: Arc<AtomicU64>,
}

impl<K, V> Clone for UdpFlowTable<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg,
            map: Arc::clone(&self.map),
            oversized: Arc::clone(&self.oversized),
            rejected_full: Arc::clone(&self.rejected_full),
            pps_gate: self.pps_gate.clone(),
            rejected_pps: Arc::clone(&self.rejected_pps),
            byte_gate: self.byte_gate.clone(),
            rejected_bytes: Arc::clone(&self.rejected_bytes),
        }
    }
}

impl<K, V> UdpFlowTable<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    /// New table with no packets-per-second cap.
    #[must_use]
    pub fn new(cfg: UdpFlowTableConfig) -> Self {
        Self::with_pps(cfg, 0)
    }

    /// New table with a `max_packets_per_sec` cap (`0` = unlimited).
    ///
    /// When non-zero, [`admit_packet`](Self::admit_packet) meters inbound
    /// datagrams through a [`RateGate`] (one token per `1/pps` seconds, burst
    /// of `pps`); excess datagrams are dropped and counted by
    /// [`rejected_pps_count`](Self::rejected_pps_count).
    #[must_use]
    pub fn with_pps(cfg: UdpFlowTableConfig, max_packets_per_sec: u32) -> Self {
        Self {
            cfg,
            map: Arc::new(DashMap::new()),
            oversized: Arc::new(AtomicU64::new(0)),
            rejected_full: Arc::new(AtomicU64::new(0)),
            pps_gate: RateGate::new(max_packets_per_sec, max_packets_per_sec),
            rejected_pps: Arc::new(AtomicU64::new(0)),
            byte_gate: TokenBucket::unlimited(),
            rejected_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Attach an aggregate byte-rate cap (`max_bytes_per_sec` bytes/second with
    /// a `burst_bytes` allowance). `0` disables the cap.
    ///
    /// Chains after [`new`](Self::new) / [`with_pps`](Self::with_pps) so a
    /// backend can compose packet-rate and byte-rate limits:
    /// `UdpFlowTable::with_pps(cfg, pps).with_byte_rate(bps, burst)`. Admission
    /// is checked via [`admit_bytes`](Self::admit_bytes).
    #[must_use]
    pub fn with_byte_rate(mut self, max_bytes_per_sec: u64, burst_bytes: u64) -> Self {
        self.byte_gate = TokenBucket::new(max_bytes_per_sec, burst_bytes);
        self
    }

    /// Admit one inbound datagram of `len` bytes against the byte-rate cap.
    ///
    /// Returns `true` if the datagram fits the current byte budget (always
    /// `true` when no `max_bytes_per_sec` was configured); `false` when the
    /// byte-rate gate is exhausted, in which case the datagram should be dropped
    /// and the [`rejected_bytes_count`](Self::rejected_bytes_count) counter is
    /// incremented.
    ///
    /// Non-blocking: unlike [`TokenBucket::acquire`](crate::limits::TokenBucket::acquire)
    /// this never waits — a datagram that would exceed the budget is dropped,
    /// matching the packets-per-second and oversized-datagram admission
    /// semantics (a stalled UDP forward must not build unbounded latency).
    pub fn admit_bytes(&self, len: usize) -> bool {
        if self.byte_gate.try_acquire(len as u64).is_none() {
            true
        } else {
            self.rejected_bytes.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Count of datagrams dropped because the byte-rate cap was hit.
    #[must_use]
    pub fn rejected_bytes_count(&self) -> u64 {
        self.rejected_bytes.load(Ordering::Relaxed)
    }

    /// Admit one inbound datagram against the packets-per-second cap.
    ///
    /// Returns `true` if the datagram may be processed (always `true` when no
    /// `max_packets_per_sec` was configured); `false` if the pps gate is
    /// exhausted, in which case the datagram should be dropped — the
    /// [`rejected_pps_count`](Self::rejected_pps_count) counter is incremented.
    pub fn admit_packet(&self) -> bool {
        if self.pps_gate.admit() {
            true
        } else {
            self.rejected_pps.fetch_add(1, Ordering::Relaxed);
            false
        }
    }

    /// Count of datagrams dropped because the packets-per-second cap was hit.
    #[must_use]
    pub fn rejected_pps_count(&self) -> u64 {
        self.rejected_pps.load(Ordering::Relaxed)
    }

    /// Number of flows currently tracked.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Count of dropped oversized datagrams.
    pub fn oversized_count(&self) -> u64 {
        self.oversized.load(Ordering::Relaxed)
    }

    /// Count of datagrams rejected because the flow table was full.
    pub fn rejected_full_count(&self) -> u64 {
        self.rejected_full.load(Ordering::Relaxed)
    }

    /// Test whether a datagram of `len` bytes is admissible.
    ///
    /// Returns `true` if the datagram is small enough; otherwise increments
    /// the oversized counter and returns `false`.
    pub fn admit_size(&self, len: usize) -> bool {
        if len > self.cfg.max_datagram_size as usize {
            self.oversized.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    /// Touch (or insert via `make`) a flow. Returns `true` if a flow exists or
    /// was inserted; `false` if the table was full.
    ///
    /// `make` is only invoked on insert.
    pub fn touch_or_insert<F: FnOnce() -> V>(&self, key: K, make: F) -> bool {
        use dashmap::mapref::entry::Entry as DmEntry;
        // Snapshot the flow count *before* acquiring the entry lock (see the
        // self-deadlock note below for why it can't be read inside the entry).
        let len_snapshot = self.map.len() as u32;
        // E1-F10: atomic get-or-insert via DashMap's `entry()` API. Holding the
        // entry lock across the occupied/vacant decision closes the TOCTOU
        // window where two concurrent datagrams for the same key both `insert`
        // (the second silently dropping the first `make()` value — for a
        // PeerTable that orphans an allocated reply channel).
        match self.map.entry(key) {
            DmEntry::Occupied(mut occ) => {
                occ.get_mut().last_seen = Instant::now();
                true
            }
            DmEntry::Vacant(vac) => {
                // Cap check. We must NOT call `self.map.len()` while holding a
                // vacant entry: `len()` re-locks every shard for read, including
                // the shard this entry write-locks, which would self-deadlock.
                // So the cap is checked against a `len()` snapshot taken before
                // the entry was acquired. The vacant entry still guarantees this
                // *key* is inserted atomically; the only residual race is two
                // *distinct* keys racing the cap and momentarily overshooting by
                // up to the number of concurrent writers — a small,
                // self-correcting overshoot that idle eviction reclaims. The
                // value-dropping race (the correctness-relevant half) is fully
                // closed.
                if self.cfg.max_flows > 0 && len_snapshot >= self.cfg.max_flows {
                    self.rejected_full.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                vac.insert(Entry {
                    value: make(),
                    last_seen: Instant::now(),
                });
                true
            }
        }
    }

    /// Apply `f` to the per-flow value if present; returns `true` if found.
    pub fn with_value<F: FnOnce(&V)>(&self, key: &K, f: F) -> bool {
        if let Some(e) = self.map.get(key) {
            f(&e.value);
            true
        } else {
            false
        }
    }

    /// Evict flows that haven't been touched within `idle_timeout`. Returns
    /// the number of evicted entries.
    pub fn evict_idle(&self) -> usize {
        let cutoff = Instant::now()
            .checked_sub(self.cfg.idle_timeout)
            .unwrap_or_else(Instant::now);
        // E1-F10: single-pass `retain` instead of a scan-then-remove. The old
        // two-phase approach snapshotted stale keys and removed them later
        // without re-checking `last_seen`, so a flow touched between the scan
        // and the remove was evicted while active (forcing a needless
        // NAT-style rebind / channel reallocation on its next packet). `retain`
        // evaluates the predicate under the shard lock at removal time, so a
        // concurrently-touched flow whose `last_seen` was bumped past the cutoff
        // is kept.
        let before = self.map.len();
        self.map.retain(|_, e| e.last_seen >= cutoff);
        before.saturating_sub(self.map.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(p: u16) -> SocketAddr {
        SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), p)
    }

    #[tokio::test]
    async fn admit_size_drops_oversized() {
        let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::new(UdpFlowTableConfig {
            max_datagram_size: 100,
            ..Default::default()
        });
        assert!(t.admit_size(50));
        assert!(!t.admit_size(200));
        assert_eq!(t.oversized_count(), 1);
    }

    #[tokio::test]
    async fn touch_inserts_and_caps() {
        let t: UdpFlowTable<UdpFlowKey, u32> = UdpFlowTable::new(UdpFlowTableConfig {
            max_flows: 2,
            ..Default::default()
        });
        assert!(t.touch_or_insert(addr(1), || 1));
        assert!(t.touch_or_insert(addr(2), || 2));
        // third is rejected
        assert!(!t.touch_or_insert(addr(3), || 3));
        assert_eq!(t.len(), 2);
        assert_eq!(t.rejected_full_count(), 1);
        // touching existing key does not create a new flow
        assert!(t.touch_or_insert(addr(1), || 99));
        assert_eq!(t.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_eviction() {
        let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::new(UdpFlowTableConfig {
            idle_timeout: Duration::from_secs(10),
            ..Default::default()
        });
        t.touch_or_insert(addr(1), || ());
        assert_eq!(t.evict_idle(), 0);
        tokio::time::advance(Duration::from_secs(20)).await;
        assert_eq!(t.evict_idle(), 1);
        assert!(t.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn evict_keeps_recently_touched_flow() {
        // E1-F10: a flow whose last_seen is bumped past the cutoff must survive
        // eviction. With the old two-phase scan it could be removed anyway.
        let t: UdpFlowTable<UdpFlowKey, u32> = UdpFlowTable::new(UdpFlowTableConfig {
            idle_timeout: Duration::from_secs(10),
            ..Default::default()
        });
        t.touch_or_insert(addr(1), || 1);
        t.touch_or_insert(addr(2), || 2);
        // Age both past the cutoff...
        tokio::time::advance(Duration::from_secs(20)).await;
        // ...but re-touch addr(1) right before eviction.
        assert!(t.touch_or_insert(addr(1), || 99));
        assert_eq!(t.evict_idle(), 1); // only addr(2) is stale
        assert_eq!(t.len(), 1);
        assert!(t.with_value(&addr(1), |_| {}));
        assert!(!t.with_value(&addr(2), |_| {}));
    }

    #[tokio::test(start_paused = true)]
    async fn pps_unlimited_admits_everything() {
        let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::new(UdpFlowTableConfig::default());
        for _ in 0..10_000 {
            assert!(t.admit_packet());
        }
        assert_eq!(t.rejected_pps_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn pps_cap_drops_excess_datagrams() {
        // 3 packets/sec, burst 3: first 3 admit, 4th is dropped and counted.
        let t: UdpFlowTable<UdpFlowKey, ()> =
            UdpFlowTable::with_pps(UdpFlowTableConfig::default(), 3);
        assert!(t.admit_packet());
        assert!(t.admit_packet());
        assert!(t.admit_packet());
        assert!(!t.admit_packet());
        assert_eq!(t.rejected_pps_count(), 1);
        // After ~1/3s one token refills.
        tokio::time::advance(Duration::from_millis(334)).await;
        assert!(t.admit_packet());
        assert_eq!(t.rejected_pps_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn byte_rate_unlimited_admits_everything() {
        // With no byte-rate cap configured, every datagram is admitted.
        let t: UdpFlowTable<UdpFlowKey, ()> = UdpFlowTable::new(UdpFlowTableConfig::default());
        for _ in 0..1000 {
            assert!(t.admit_bytes(1500));
        }
        assert_eq!(t.rejected_bytes_count(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn byte_rate_cap_drops_excess_bytes() {
        // 1000 bytes/sec, burst 1000: the first 600-byte datagram admits, the
        // second exceeds the remaining budget and is dropped + counted; after
        // ~0.7s of refill it admits again.
        let t: UdpFlowTable<UdpFlowKey, ()> =
            UdpFlowTable::new(UdpFlowTableConfig::default()).with_byte_rate(1000, 1000);
        assert!(t.admit_bytes(600));
        assert!(!t.admit_bytes(600));
        assert_eq!(t.rejected_bytes_count(), 1);
        tokio::time::advance(Duration::from_millis(700)).await;
        assert!(t.admit_bytes(600));
        assert_eq!(t.rejected_bytes_count(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn byte_rate_composes_with_pps() {
        // A backend can layer packet-rate and byte-rate caps on one table; the
        // two gates are independent counters.
        let t: UdpFlowTable<UdpFlowKey, ()> =
            UdpFlowTable::with_pps(UdpFlowTableConfig::default(), 100).with_byte_rate(1000, 1000);
        // Byte gate trips first here (600 + 600 > 1000-byte budget) while the
        // pps gate (100/s) still has tokens.
        assert!(t.admit_packet());
        assert!(t.admit_bytes(600));
        assert!(t.admit_packet());
        assert!(!t.admit_bytes(600));
        assert_eq!(t.rejected_bytes_count(), 1);
        assert_eq!(t.rejected_pps_count(), 0);
    }

    #[tokio::test]
    async fn touch_existing_does_not_replace_value() {
        // E1-F10: re-touching an existing key keeps the original value (the
        // `make` closure is not re-invoked), so an allocated per-flow resource
        // is never silently dropped.
        let t: UdpFlowTable<UdpFlowKey, u32> = UdpFlowTable::new(UdpFlowTableConfig::default());
        assert!(t.touch_or_insert(addr(1), || 1));
        assert!(t.touch_or_insert(addr(1), || 999));
        let mut seen = 0u32;
        assert!(t.with_value(&addr(1), |v| seen = *v));
        assert_eq!(seen, 1, "original value preserved on re-touch");
    }
}
