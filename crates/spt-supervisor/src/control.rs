//! Control-channel commands sent to a [`crate::ProfileSupervisor`]'s task.
//!
//! The profile task originally listened on a single shutdown oneshot; for
//! richer external control surfaces (manual failover, drain, session close,
//! live-tunnel stream open) it now multiplexes all such requests through an
//! `mpsc::Sender<Control>`. Each variant carries an oneshot reply channel for
//! its caller — the variants without one (currently only `Shutdown`) are
//! fire-and-forget.

use std::time::Duration;

use spt_core::Result;
use tokio::sync::oneshot;

/// Endpoint identifier — currently `"host:port"`.
pub type EndpointKey = String;

/// Outcome of a [`Control::Drain`] cycle.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Forwards that drained cleanly within the grace window.
    pub drained: u32,
    /// Forwards force-closed at the grace boundary.
    pub force_closed: u32,
    /// Forwards already closed when drain started.
    pub already_closed: u32,
}

/// Control commands consumed by `ProfileTask`.
#[derive(Debug)]
pub enum Control {
    /// Shut the supervisor down (legacy `oneshot::Sender<()>` semantics).
    Shutdown,
    /// Request the next pick-loop iteration to switch endpoints. `override_to`
    /// pins the selector to a specific endpoint for one reconnect cycle.
    Failover {
        /// Optional manual override (`"host:port"`).
        override_to: Option<EndpointKey>,
        /// Reply: `Ok(())` on accepted, `Err` if the override is unknown.
        reply: oneshot::Sender<Result<()>>,
    },
    /// Tear the current session down without exhausting backoff. Reconnect
    /// logic still applies on the next loop iteration.
    CloseSession {
        /// Reply when the close has been signalled.
        reply: oneshot::Sender<Result<()>>,
    },
    /// Stop accepting new connections, wait `grace`, then force-close.
    Drain {
        /// Maximum time to wait for in-flight connections to finish.
        grace: Duration,
        /// Reply with the resulting [`DrainReport`].
        reply: oneshot::Sender<Result<DrainReport>>,
    },
}
