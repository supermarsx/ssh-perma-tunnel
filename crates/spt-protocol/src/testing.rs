//! Test facilities for downstream crates that mock or drive the protocol layer.
//!
//! Enabled with `--features testing` (or under `cfg(test)` inside this crate).
//! Helpers here are deterministic by default — endpoints use stable hostnames,
//! forward specs use sane defaults, and no I/O is performed.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use spt_core::BindAddr;
use tokio::sync::{oneshot, watch};

fn loopback_v4(port: u16) -> BindAddr {
    BindAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
}

fn any_v4(port: u16) -> BindAddr {
    BindAddr::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port))
}

use crate::endpoint::{AddressFamily, Endpoint};
use crate::forward::{
    ForwardDirection, ForwardState, LocalForwardSpec, RemoteForwardSpec, UdpForwardSpec,
};
use crate::handle::{ForwardHandle, ForwardId};
use crate::TargetAddr;

/// A representative set of [`Endpoint`] values suitable as test fixtures.
///
/// The list covers loopback, plain hostname, IPv4 literal, IPv6 literal, and a
/// hostname with an `address_family` hint set, in that order. Five entries.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use spt_protocol::testing::endpoint_fixtures;
/// let eps = endpoint_fixtures();
/// assert_eq!(eps.len(), 5);
/// assert_eq!(eps[0].host, "127.0.0.1");
/// # }
/// ```
#[must_use]
pub fn endpoint_fixtures() -> Vec<Endpoint> {
    vec![
        Endpoint {
            host: "127.0.0.1".to_owned(),
            port: 22,
            address_family: Some(AddressFamily::Ipv4),
            priority: 0,
            weight: 1,
        },
        Endpoint::new("ssh.example.com", 22),
        Endpoint {
            host: "192.0.2.10".to_owned(),
            port: 2222,
            address_family: Some(AddressFamily::Ipv4),
            priority: 10,
            weight: 1,
        },
        Endpoint {
            host: "2001:db8::1".to_owned(),
            port: 22,
            address_family: Some(AddressFamily::Ipv6),
            priority: 20,
            weight: 1,
        },
        Endpoint {
            host: "ssh-v6.example.com".to_owned(),
            port: 443,
            address_family: Some(AddressFamily::Ipv6),
            priority: 30,
            weight: 2,
        },
    ]
}

/// Build a [`LocalForwardSpec`] bound to `127.0.0.1:port` targeting `localhost:port`.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use spt_protocol::testing::local_forward_spec;
/// let s = local_forward_spec(8080);
/// assert_eq!(s.target.port, 8080);
/// # }
/// ```
#[must_use]
pub fn local_forward_spec(port: u16) -> LocalForwardSpec {
    LocalForwardSpec {
        name: format!("local-{port}"),
        listen: loopback_v4(port),
        target: TargetAddr::new("localhost", port),
        max_connections: None,
    }
}

/// Build a [`RemoteForwardSpec`] with the server bound on `0.0.0.0:port`
/// forwarding back to `127.0.0.1:port`.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use spt_protocol::testing::remote_forward_spec;
/// let s = remote_forward_spec(9090);
/// assert_eq!(s.target.port, 9090);
/// # }
/// ```
#[must_use]
pub fn remote_forward_spec(port: u16) -> RemoteForwardSpec {
    RemoteForwardSpec {
        name: format!("remote-{port}"),
        listen: any_v4(port),
        target: TargetAddr::new("127.0.0.1", port),
        max_connections: None,
    }
}

/// Build a [`UdpForwardSpec`] (local direction) on `127.0.0.1:port` with a
/// 60-second idle timeout.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use spt_protocol::testing::udp_forward_spec;
/// let s = udp_forward_spec(53);
/// assert_eq!(s.idle_timeout_secs, 60);
/// assert_eq!(s.target.port, 53);
/// # }
/// ```
#[must_use]
pub fn udp_forward_spec(port: u16) -> UdpForwardSpec {
    UdpForwardSpec {
        name: format!("udp-{port}"),
        direction: ForwardDirection::Local,
        listen: loopback_v4(port),
        target: TargetAddr::new("127.0.0.1", port),
        idle_timeout_secs: 60,
        max_flows: None,
    }
}

/// Test-only controller paired with a [`ForwardHandle`].
///
/// Returned by [`forward_handle_pair`]. Tests use the controller to drive state
/// transitions (via [`ForwardHandleController::set_state`]) and to observe the
/// close-trigger oneshot ([`ForwardHandleController::close_signal`]). Drop the
/// controller to detach.
#[derive(Debug)]
pub struct ForwardHandleController {
    state_tx: watch::Sender<ForwardState>,
    close_rx: Option<oneshot::Receiver<()>>,
}

impl ForwardHandleController {
    /// Set the forward state, notifying every observer.
    pub fn set_state(&self, state: ForwardState) {
        let _ = self.state_tx.send(state);
    }

    /// Take ownership of the close-signal receiver.
    ///
    /// Returns `None` if it was already consumed. After the [`ForwardHandle`]
    /// is dropped without calling `close()`, awaiting this receiver yields
    /// `Err(_)` rather than the close signal.
    pub fn close_signal(&mut self) -> Option<oneshot::Receiver<()>> {
        self.close_rx.take()
    }

    /// Borrow the underlying state-broadcast sender.
    #[must_use]
    pub fn state_sender(&self) -> &watch::Sender<ForwardState> {
        &self.state_tx
    }
}

/// Construct a [`ForwardHandle`] paired with a [`ForwardHandleController`].
///
/// The handle starts in [`ForwardState::Binding`]. Tests drive the state
/// machine through the controller and observe via [`ForwardHandle::watch_state`].
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use spt_protocol::forward::ForwardState;
/// use spt_protocol::testing::forward_handle_pair;
/// let (handle, controller) = forward_handle_pair();
/// controller.set_state(ForwardState::Active);
/// assert_eq!(handle.state(), ForwardState::Active);
/// # }
/// ```
#[must_use]
pub fn forward_handle_pair() -> (ForwardHandle, ForwardHandleController) {
    let (state_tx, state_rx) = watch::channel(ForwardState::Binding);
    let (close_tx, close_rx) = oneshot::channel();
    let handle = ForwardHandle::new(ForwardId::new(), "test-forward", state_rx, close_tx);
    let controller = ForwardHandleController {
        state_tx,
        close_rx: Some(close_rx),
    };
    (handle, controller)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_fixtures_are_distinct() {
        let eps = endpoint_fixtures();
        assert_eq!(eps.len(), 5);
        for i in 0..eps.len() {
            for j in (i + 1)..eps.len() {
                assert_ne!(eps[i], eps[j], "duplicate at {i},{j}");
            }
        }
    }

    #[test]
    fn forward_specs_carry_port() {
        assert_eq!(local_forward_spec(8080).target.port, 8080);
        assert_eq!(remote_forward_spec(9090).target.port, 9090);
        assert_eq!(udp_forward_spec(53).target.port, 53);
    }

    #[tokio::test]
    async fn forward_handle_round_trip() {
        let (handle, mut controller) = forward_handle_pair();
        assert_eq!(handle.state(), ForwardState::Binding);
        controller.set_state(ForwardState::Listening);
        controller.set_state(ForwardState::Active);
        // Allow the watch channel to propagate.
        let mut rx = handle.watch_state();
        // borrow now reads latest.
        assert_eq!(*rx.borrow_and_update(), ForwardState::Active);

        // observe close trigger
        let close_rx = controller.close_signal().expect("first take");
        let task = tokio::spawn(async move {
            let _ = close_rx.await;
            controller.set_state(ForwardState::Stopped);
        });
        handle.close().await;
        task.await.unwrap();
    }
}
