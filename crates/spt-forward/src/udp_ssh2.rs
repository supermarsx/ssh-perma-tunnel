//! SSH2-backend UDP forwarding dispatcher.
//!
//! Picks between the two SSH2 UDP forwarding modes ([`UdpMode::TcpFramed`]
//! and [`UdpMode::UdsBridge`]) defined by spt-config and supplies a single
//! entry point the supervisor / spt-ssh2 backend can call without caring
//! which framing is in use.
//!
//! ## Responsibility split
//!
//! * **This module** (`spt-forward`) owns the local UDP socket, the peer
//!   table (per `(src_ip, src_port)` flow identity), per-peer channel
//!   allocation, idle TTL eviction, and oversized-datagram rejection.
//! * **`spt-ssh2`** ([`spt_ssh2::udp_tcp_framed`] and
//!   [`spt_ssh2::udp_uds_mode`]) owns the on-the-wire codec and the russh /
//!   libssh2 channel-open call.
//!
//! The split keeps spt-forward free of any libssh2 or russh build-time
//! dependency while still letting us house the test surface (peer-table
//! invariants, mode dispatch) here.
//!
//! ## Peer-table semantics
//!
//! Per-`(src_ip, src_port)` flow: one channel allocated on first datagram,
//! reused for subsequent datagrams from the same UDP peer, evicted after
//! [`Self::idle_ttl`] of silence. Oversized frames (`> 64 KiB`) bump a
//! drop counter and are not forwarded (matching the libssh2-side
//! [`spt_ssh2::udp_tcp_framed::MAX_FRAME_BYTES`] cap).

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use spt_config::schema::UdpMode;
use tokio::sync::Mutex;

use crate::udp::{UdpFlowKey, UdpFlowTable, UdpFlowTableConfig};

/// Default per-peer idle TTL: 60 seconds (matches the task brief).
pub const DEFAULT_IDLE_TTL: Duration = Duration::from_secs(60);

/// Maximum framed datagram size: 64 KiB (matches
/// `spt_ssh2::udp_tcp_framed::MAX_FRAME_BYTES`).
pub const MAX_FRAME_BYTES: u32 = 64 * 1024;

/// Resolve the effective [`UdpMode`] for a `Forward`. When the schema field
/// is `None`, returns the enum default ([`UdpMode::TcpFramed`]).
#[must_use]
pub fn resolve_udp_mode(forward: &spt_config::schema::Forward) -> UdpMode {
    forward.udp_mode.unwrap_or_default()
}

/// Per-peer entry stored in the [`PeerTable`]. The actual channel handle
/// is a generic `V` so this type can be tested without dragging in any
/// real russh / libssh2 channel types.
#[derive(Debug)]
pub struct PeerEntry<V> {
    /// Whatever the backend allocates for this peer (an SSH channel, a
    /// `mpsc::Sender<Vec<u8>>` driving a write half, etc.).
    pub value: V,
    /// Allocated port on the local side (where reply traffic from the
    /// upstream lands). Used to detect collision in tests.
    pub local_port: u16,
}

/// Per-peer flow table. Thin wrapper over [`UdpFlowTable`] that fixes
/// `K = UdpFlowKey` (peer `SocketAddr`) and lets the value carry a
/// per-peer local port for collision testing.
#[derive(Debug, Clone)]
pub struct PeerTable<V>
where
    V: Send + Sync + 'static,
{
    inner: UdpFlowTable<UdpFlowKey, Arc<Mutex<PeerEntry<V>>>>,
}

impl<V> PeerTable<V>
where
    V: Send + Sync + 'static,
{
    /// New peer table with the given idle TTL.
    #[must_use]
    pub fn new(idle_ttl: Duration) -> Self {
        Self {
            inner: UdpFlowTable::new(UdpFlowTableConfig {
                idle_timeout: idle_ttl,
                max_datagram_size: MAX_FRAME_BYTES,
                max_flows: 0,
            }),
        }
    }

    /// Number of tracked peers.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Admit a datagram size against [`MAX_FRAME_BYTES`]. Larger datagrams
    /// bump the oversized counter and return `false`.
    pub fn admit_size(&self, len: usize) -> bool {
        self.inner.admit_size(len)
    }

    /// Count of oversized datagrams rejected by [`Self::admit_size`].
    pub fn oversized_count(&self) -> u64 {
        self.inner.oversized_count()
    }

    /// Touch (or insert via `make`) the peer entry.
    pub fn touch_or_insert<F: FnOnce() -> PeerEntry<V>>(&self, peer: SocketAddr, make: F) -> bool {
        self.inner
            .touch_or_insert(peer, || Arc::new(Mutex::new(make())))
    }

    /// Evict idle peers; returns the count evicted.
    pub fn evict_idle(&self) -> usize {
        self.inner.evict_idle()
    }

    /// Look at a peer entry's local port (collision detection). Returns
    /// `None` if the peer is not tracked.
    ///
    /// Uses `try_lock` so this stays sync-friendly; if the entry's mutex
    /// is contended (rare in the test scenarios that exercise this) the
    /// helper conservatively returns `None`. Production code does its own
    /// per-peer locking before reading.
    #[must_use]
    pub fn local_port(&self, peer: &SocketAddr) -> Option<u16> {
        let mut got = None;
        self.inner.with_value(peer, |entry| {
            if let Ok(guard) = entry.try_lock() {
                got = Some(guard.local_port);
            }
        });
        got
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::schema::Forward;
    use std::net::{IpAddr, Ipv4Addr};

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
    }

    /// `mode dispatch: correct module selected per config`.
    #[test]
    fn resolve_udp_mode_dispatch_picks_correct_variant() {
        let mut fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "udp".into(),
            ..Default::default()
        };
        // Absent: default is TcpFramed.
        assert_eq!(resolve_udp_mode(&fwd), UdpMode::TcpFramed);
        fwd.udp_mode = Some(UdpMode::TcpFramed);
        assert_eq!(resolve_udp_mode(&fwd), UdpMode::TcpFramed);
        fwd.udp_mode = Some(UdpMode::UdsBridge);
        assert_eq!(resolve_udp_mode(&fwd), UdpMode::UdsBridge);
    }

    /// `schema validate: tcp_framed default applied when absent` — exercised
    /// from the dispatcher's perspective (`resolve_udp_mode`).
    #[test]
    fn tcp_framed_default_when_field_absent_on_forward() {
        let fwd = Forward {
            name: "f".into(),
            kind: "local".into(),
            transport: "udp".into(),
            udp_mode: None,
            ..Default::default()
        };
        assert_eq!(resolve_udp_mode(&fwd), UdpMode::TcpFramed);
    }

    /// `tcp_framed peer-table idle eviction`.
    #[tokio::test(start_paused = true)]
    async fn peer_table_evicts_idle_entries_after_ttl() {
        let table: PeerTable<()> = PeerTable::new(Duration::from_secs(60));
        assert!(table.touch_or_insert(peer(1000), || PeerEntry {
            value: (),
            local_port: 50_000,
        }));
        assert_eq!(table.len(), 1);
        assert_eq!(table.evict_idle(), 0);
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(table.evict_idle(), 1);
        assert!(table.is_empty());
    }

    /// `tcp_framed per-peer port allocation collision` — two distinct UDP
    /// peers must receive distinct allocated `local_port` values; allocator
    /// must not hand the same port to two peers concurrently.
    #[tokio::test]
    async fn peer_table_per_peer_local_port_is_unique() {
        let table: PeerTable<()> = PeerTable::new(Duration::from_secs(60));

        // Simulate an allocator that hands out ports from a counter.
        let mut next_port: u16 = 40_000;
        let mut alloc = || {
            let p = next_port;
            next_port += 1;
            p
        };

        table.touch_or_insert(peer(1), || PeerEntry {
            value: (),
            local_port: alloc(),
        });
        table.touch_or_insert(peer(2), || PeerEntry {
            value: (),
            local_port: alloc(),
        });
        table.touch_or_insert(peer(3), || PeerEntry {
            value: (),
            local_port: alloc(),
        });

        let p1 = table.local_port(&peer(1)).unwrap();
        let p2 = table.local_port(&peer(2)).unwrap();
        let p3 = table.local_port(&peer(3)).unwrap();
        assert_ne!(p1, p2);
        assert_ne!(p1, p3);
        assert_ne!(p2, p3);

        // Re-touching peer(1) must NOT cause a re-allocation: same port.
        table.touch_or_insert(peer(1), || PeerEntry {
            value: (),
            local_port: alloc(), // would be 40_003 if called — but it shouldn't be
        });
        let p1_again = table.local_port(&peer(1)).unwrap();
        assert_eq!(p1, p1_again, "re-touch must not reallocate");
    }

    /// `peer-table: 1k peers no leak` — insert 1000 distinct peers, verify
    /// the table holds all of them, evict-all, verify zero remain.
    #[tokio::test(start_paused = true)]
    async fn peer_table_one_thousand_peers_no_leak() {
        let table: PeerTable<()> = PeerTable::new(Duration::from_secs(10));
        for i in 0u16..1000 {
            assert!(table.touch_or_insert(peer(10_000 + i), || PeerEntry {
                value: (),
                local_port: 30_000 + i,
            }));
        }
        assert_eq!(table.len(), 1000);
        tokio::time::advance(Duration::from_secs(60)).await;
        let evicted = table.evict_idle();
        assert_eq!(evicted, 1000);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    /// Oversized-frame admission counter check.
    #[tokio::test]
    async fn peer_table_admit_size_rejects_above_64kib() {
        let table: PeerTable<()> = PeerTable::new(Duration::from_secs(60));
        assert!(table.admit_size(1500));
        assert!(table.admit_size(MAX_FRAME_BYTES as usize));
        assert!(!table.admit_size(MAX_FRAME_BYTES as usize + 1));
        assert_eq!(table.oversized_count(), 1);
    }
}

// ---------------------------------------------------------------------------
// Windows compile-only smoke test (verify no Unix-only deps leak).
// ---------------------------------------------------------------------------

#[cfg(all(test, windows))]
mod windows_smoke {
    /// `compile-only Windows (verify no Unix-only deps leak)` — this test
    /// exists purely so a Windows CI run breaks loudly if any future
    /// import in this module pulls a Unix-only crate. Touching the module
    /// is enough; no runtime behaviour is asserted.
    #[test]
    fn module_compiles_on_windows() {
        let _ = super::DEFAULT_IDLE_TTL;
        let _ = super::MAX_FRAME_BYTES;
    }
}
