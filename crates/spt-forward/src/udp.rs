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
    /// Optional cap on the number of concurrent flows. `0` = unlimited.
    pub max_flows: u32,
}

impl Default for UdpFlowTableConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Duration::from_secs(60),
            max_datagram_size: 1500,
            max_flows: 0,
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
        }
    }
}

impl<K, V> UdpFlowTable<K, V>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    V: Send + Sync + 'static,
{
    /// New table.
    #[must_use]
    pub fn new(cfg: UdpFlowTableConfig) -> Self {
        Self {
            cfg,
            map: Arc::new(DashMap::new()),
            oversized: Arc::new(AtomicU64::new(0)),
            rejected_full: Arc::new(AtomicU64::new(0)),
        }
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
        if let Some(mut e) = self.map.get_mut(&key) {
            e.last_seen = Instant::now();
            return true;
        }
        if self.cfg.max_flows > 0 && (self.map.len() as u32) >= self.cfg.max_flows {
            self.rejected_full.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.map.insert(
            key,
            Entry {
                value: make(),
                last_seen: Instant::now(),
            },
        );
        true
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
        let mut evict_keys = Vec::new();
        for entry in self.map.iter() {
            if entry.value().last_seen < cutoff {
                evict_keys.push(entry.key().clone());
            }
        }
        let n = evict_keys.len();
        for k in evict_keys {
            self.map.remove(&k);
        }
        n
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
}
