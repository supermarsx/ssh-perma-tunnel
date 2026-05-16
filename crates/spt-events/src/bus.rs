//! Broadcast event bus.
//!
//! `EventBus` wraps a `tokio::sync::broadcast::Sender<Arc<Event>>` so the
//! same event can be observed by an arbitrary number of consumers
//! (dispatcher, MCP notifier, file ring, future integrations) without
//! cloning the underlying value. Sending is non-blocking: when there are no
//! subscribers, send still succeeds (`broadcast::Sender::send` returns
//! `Err(SendError)` only if there are zero receivers and would otherwise
//! drop the message — we ignore that variant here).

use std::sync::Arc;

use tokio::sync::broadcast;

use crate::event::Event;
use spt_state::EventRing;

/// Configuration for [`EventBus`].
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    /// Broadcast channel buffer size — slow consumers exceeding this lag
    /// will receive `RecvError::Lagged`.
    pub capacity: usize,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self { capacity: 1024 }
    }
}

/// Broadcast event bus.
#[derive(Clone)]
pub struct EventBus {
    sender: broadcast::Sender<Arc<Event>>,
    /// Optional event ring — when set, every emitted event is also pushed
    /// onto the ring's daily JSONL file for persistence.
    ring: Option<Arc<EventRing>>,
}

impl EventBus {
    /// New bus with the given capacity.
    #[must_use]
    pub fn new(cfg: &EventBusConfig) -> Self {
        let (tx, _) = broadcast::channel(cfg.capacity);
        Self {
            sender: tx,
            ring: None,
        }
    }

    /// Attach an [`EventRing`] for persistence. Every subsequent emit also
    /// fans out to the ring (non-blocking, `Event::to_state_event()`).
    #[must_use]
    pub fn with_ring(mut self, ring: Arc<EventRing>) -> Self {
        self.ring = Some(ring);
        self
    }

    /// Emit an event to all current subscribers. Always succeeds (returns
    /// the number of receivers reached, or 0 if none).
    pub fn emit(&self, event: Event) -> usize {
        let arc = Arc::new(event);
        self.fan_out_ring(&arc);
        self.sender.send(arc).unwrap_or(0)
    }

    /// Emit an already-Arc'd event (avoids an extra clone for callers that
    /// already share ownership).
    pub fn emit_arc(&self, event: Arc<Event>) -> usize {
        self.fan_out_ring(&event);
        self.sender.send(event).unwrap_or(0)
    }

    fn fan_out_ring(&self, event: &Arc<Event>) {
        if let Some(ring) = &self.ring {
            ring.append(event.to_state_event());
        }
    }

    /// Subscribe to the bus. Each subscriber gets its own `Receiver`.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<Event>> {
        self.sender.subscribe()
    }

    /// Number of currently-subscribed receivers.
    #[must_use]
    pub fn receiver_count(&self) -> usize {
        self.sender.receiver_count()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new(&EventBusConfig::default())
    }
}

impl std::fmt::Debug for EventBus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventBus")
            .field("receivers", &self.receiver_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    #[tokio::test(flavor = "current_thread")]
    async fn emit_reaches_all_subscribers() {
        let bus = EventBus::new(&EventBusConfig { capacity: 16 });
        let mut a = bus.subscribe();
        let mut b = bus.subscribe();
        let n = bus.emit(Event::builder("k", Severity::Info).build());
        assert_eq!(n, 2);

        let ea = a.recv().await.unwrap();
        let eb = b.recv().await.unwrap();
        assert_eq!(ea.kind.as_str(), "k");
        assert_eq!(eb.kind.as_str(), "k");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_with_no_subscribers_returns_zero() {
        let bus = EventBus::new(&EventBusConfig::default());
        let n = bus.emit(Event::builder("k", Severity::Info).build());
        assert_eq!(n, 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn with_ring_persists_to_state_event_ring() {
        use spt_state::{EventRing, EventRingConfig};
        let tmp = tempfile::tempdir().unwrap();
        let ring = EventRing::spawn(
            tmp.path().to_path_buf(),
            EventRingConfig {
                channel_capacity: 16,
                retain_days: 7,
            },
        )
        .unwrap();
        let ring = Arc::new(ring);

        let bus = EventBus::new(&EventBusConfig::default()).with_ring(ring.clone());
        bus.emit(
            Event::builder("profile.connected", Severity::Info)
                .message("hello")
                .build(),
        );
        // Stop the ring writer so it flushes synchronously.
        if let Ok(r) = Arc::try_unwrap(ring) {
            r.stop().await;
        } else {
            // If still shared, give the writer a moment.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        // Find the events file for "today" and confirm the line is there.
        let events_dir = tmp.path().join("events");
        let mut found = false;
        if let Ok(rd) = std::fs::read_dir(&events_dir) {
            for entry in rd.flatten() {
                let body = std::fs::read_to_string(entry.path()).unwrap_or_default();
                if body.contains("profile.connected") {
                    found = true;
                    break;
                }
            }
        }
        assert!(
            found,
            "expected emitted event to land in the EventRing file"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emit_arc_avoids_extra_clone() {
        let bus = EventBus::new(&EventBusConfig::default());
        let mut rx = bus.subscribe();
        let arc = Arc::new(Event::builder("k", Severity::Info).build());
        let n = bus.emit_arc(arc.clone());
        assert_eq!(n, 1);
        let got = rx.recv().await.unwrap();
        assert_eq!(got.kind.as_str(), "k");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn receiver_count_tracks_subscribers() {
        let bus = EventBus::new(&EventBusConfig::default());
        assert_eq!(bus.receiver_count(), 0);
        let rx_a = bus.subscribe();
        let _rx_b = bus.subscribe();
        assert_eq!(bus.receiver_count(), 2);
        drop(rx_a);
        assert_eq!(bus.receiver_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn default_bus_has_documented_capacity() {
        let cfg = EventBusConfig::default();
        assert_eq!(cfg.capacity, 1024);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn default_constructor_constructs() {
        let bus = EventBus::default();
        assert_eq!(bus.receiver_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn debug_impl_reports_receiver_count() {
        let bus = EventBus::new(&EventBusConfig::default());
        let _r = bus.subscribe();
        let s = format!("{bus:?}");
        assert!(s.contains("EventBus"));
        assert!(s.contains("receivers"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn clone_shares_underlying_channel() {
        let bus = EventBus::new(&EventBusConfig::default());
        let bus2 = bus.clone();
        let mut rx = bus.subscribe();
        // Emit from the clone — receiver of the original should still see it.
        bus2.emit(Event::builder("k", Severity::Info).build());
        let got = rx.recv().await.unwrap();
        assert_eq!(got.kind.as_str(), "k");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn event_bus_config_is_clonable_and_debuggable() {
        let cfg = EventBusConfig { capacity: 32 };
        let _c = cfg.clone();
        let s = format!("{cfg:?}");
        assert!(s.contains("EventBusConfig"));
    }
}
