//! Tunnel protocol adapter traits shared by every backend (SSH2, SSH3, …).
//!
//! `spt-protocol` defines the seam between the supervisor (which owns the
//! reconnect, failover, and forward-orchestration state machines) and the
//! concrete protocol crates that talk to a remote peer. The traits mirror the
//! shape sketched in spec §17.3 with the additional structural detail required
//! to support local/remote TCP and UDP forwards uniformly.
//!
//! The crate intentionally contains **only types and traits** — no I/O. Each
//! backend (`spt-ssh2`, `spt-ssh3`) provides its own implementation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod capabilities;
pub mod endpoint;
pub mod forward;
pub mod handle;
pub mod session;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

use async_trait::async_trait;
use spt_auth::AuthConfig;
use spt_core::Result;

pub use capabilities::ProtocolCapabilities;
pub use endpoint::{Endpoint, TargetAddr};
pub use forward::{
    BindConflictPolicy, DynamicForwardSpec, ForwardDirection, ForwardRateLimits, ForwardState,
    ForwardTransport, LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec, UdsForwardSpec,
};
pub use handle::{ForwardHandle, ForwardId};
pub use session::{SessionInfo, TunnelSession};

/// A protocol adapter capable of opening a [`TunnelSession`] for one endpoint.
///
/// Implementations are stateless factories; per-connection state lives on the
/// returned session.
#[async_trait]
pub trait TunnelProtocol: Send + Sync {
    /// Establish a tunnel session to `endpoint` using `auth`.
    async fn connect(
        &self,
        endpoint: &Endpoint,
        auth: &AuthConfig,
    ) -> Result<Box<dyn TunnelSession>>;

    /// Static capability set advertised by this backend.
    fn capabilities(&self) -> ProtocolCapabilities;

    /// Stable backend name used in logs/diagnostics — `"ssh2"`, `"ssh3"`, …
    fn name(&self) -> &'static str;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Trait-object compile test: ensures `TunnelProtocol` and `TunnelSession`
    /// are object-safe and `Send + Sync`.
    #[allow(dead_code)]
    fn _object_safe() {
        fn assert_send_sync<T: Send + Sync + ?Sized>() {}
        assert_send_sync::<dyn TunnelProtocol>();
        assert_send_sync::<dyn TunnelSession>();
    }

    #[allow(dead_code)]
    fn _trait_bound<T: TunnelProtocol>() {}
}
