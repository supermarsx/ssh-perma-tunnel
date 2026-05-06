//! `ForwardHandle` — the actor-handle the supervisor holds for one open forward.
//!
//! Each backend, after successfully opening a forward, returns a `ForwardHandle`.
//! The handle owns:
//!
//! * A [`tokio::sync::watch::Receiver`] of [`ForwardState`] for state observation.
//! * A oneshot close-trigger consumed by [`ForwardHandle::close`].
//!
//! Internals are intentionally opaque — backends construct handles through
//! [`ForwardHandle::new`].

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use tokio::sync::{oneshot, watch};

use crate::forward::ForwardState;

/// Stable per-handle identifier — local to one process, monotonically increasing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ForwardId(pub u64);

impl ForwardId {
    /// Allocate a fresh forward id.
    #[must_use]
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        Self(NEXT.fetch_add(1, Ordering::Relaxed))
    }
}

impl Default for ForwardId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ForwardId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "fwd-{}", self.0)
    }
}

/// Handle for one open forward, returned by the protocol-session `open_*` calls.
#[derive(Debug)]
pub struct ForwardHandle {
    id: ForwardId,
    name: String,
    state_rx: watch::Receiver<ForwardState>,
    close_tx: Option<oneshot::Sender<()>>,
}

impl ForwardHandle {
    /// Construct a new handle. Backends call this after spawning their per-forward task.
    #[must_use]
    pub fn new(
        id: ForwardId,
        name: impl Into<String>,
        state_rx: watch::Receiver<ForwardState>,
        close_tx: oneshot::Sender<()>,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            state_rx,
            close_tx: Some(close_tx),
        }
    }

    /// Stable per-handle id.
    #[must_use]
    pub fn id(&self) -> ForwardId {
        self.id
    }

    /// Configured forward name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Snapshot of the current state.
    #[must_use]
    pub fn state(&self) -> ForwardState {
        *self.state_rx.borrow()
    }

    /// Subscribe to state changes — every forward state transition will appear here.
    #[must_use]
    pub fn watch_state(&self) -> watch::Receiver<ForwardState> {
        self.state_rx.clone()
    }

    /// Signal the per-forward task to shut down. The handle is consumed; the
    /// caller may continue to observe state through a previously cloned
    /// `watch::Receiver`.
    pub async fn close(mut self) {
        if let Some(tx) = self.close_tx.take() {
            let _ = tx.send(());
        }
        // wait for the producer side to mark a terminal state
        loop {
            if self.state().is_terminal() {
                break;
            }
            if self.state_rx.changed().await.is_err() {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn close_waits_for_terminal() {
        let (state_tx, state_rx) = watch::channel(ForwardState::Active);
        let (close_tx, close_rx) = oneshot::channel();
        let handle = ForwardHandle::new(ForwardId::new(), "t", state_rx, close_tx);

        let task = tokio::spawn(async move {
            close_rx.await.unwrap();
            state_tx.send(ForwardState::Stopped).unwrap();
        });

        handle.close().await;
        task.await.unwrap();
    }

    #[test]
    fn ids_are_unique() {
        let a = ForwardId::new();
        let b = ForwardId::new();
        assert_ne!(a, b);
    }
}
