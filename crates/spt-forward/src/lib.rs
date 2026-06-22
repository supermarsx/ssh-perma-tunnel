//! Forwarding building blocks and the supervisor-facing [`ForwardRunner`].
//!
//! ## Layering
//!
//! `spt-protocol`'s `TunnelSession::open_local_forward(spec) -> ForwardHandle`
//! is **per-forward**: the returned handle represents the entire listener +
//! per-connection lifecycle. The protocol backend (spt-ssh2 / spt-ssh3) is
//! therefore the natural owner of the listener task and of the bidirectional
//! copy loops.
//!
//! `spt-forward` is **two things**:
//!
//! 1. **A toolkit crate of building blocks** that protocol backends consume
//!    inside their `open_*_forward` impls:
//!    - [`limits::TokenBucket`] for byte-rate throttling.
//!    - [`limits::ConnectionGate`] for max-connection caps.
//!    - [`acl::ForwardAcl`] for CIDR allow/deny enforcement (wraps
//!      [`spt_net::CidrAcl`]).
//!    - [`udp::UdpFlowTable`] for UDP NAT-style flow tracking with idle
//!      eviction and oversized-datagram drop counting.
//!    - [`bidir::copy_bidirectional_throttled`] — a backpressure-aware copy
//!      that respects per-direction token buckets.
//!    - [`local_tcp::AcceptLoop`] — a small accept-loop helper.
//!
//! 2. **The [`runner::ForwardRunner`] type** that the supervisor uses to take
//!    one config [`spt_config::Forward`] entry and drive a single
//!    [`spt_protocol::ForwardHandle`] through its lifecycle. The runner does
//!    *not* itself bind sockets — it asks the session to do so via
//!    `open_local_forward` / `open_remote_forward` / `open_dynamic_forward` /
//!    `open_udp_forward` and surfaces the resulting state.
//!
//! ## Why this layering
//!
//! The supervisor never reaches into per-connection internals; the backend
//! never duplicates the throttle/ACL/flow-table logic. Both sides agree on the
//! [`spt_protocol::ForwardHandle`] seam.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![allow(
    clippy::manual_let_else,
    clippy::doc_markdown,
    clippy::map_unwrap_or,
    clippy::cast_lossless,
    clippy::ignored_unit_patterns,
    clippy::missing_fields_in_debug
)]

pub mod acl;
pub mod bidir;
pub mod limits;
pub mod local_tcp;
pub mod remote_tcp;
pub mod runner;
pub mod udp;
pub mod udp_ssh2;
pub mod uds_listener;

// Test fixtures are gated behind the `testing` feature so other crates'
// tests (notably spt-supervisor) can reuse [`testing::MockTunnelProtocol`].
#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use acl::{AclDecision, ForwardAcl};
pub use bidir::{copy_bidirectional_throttled, copy_bidirectional_throttled_idle, CopyStats};
pub use limits::{ConnectionGate, ConnectionPermit, RateGate, TokenBucket};
pub use local_tcp::{bind_with_policy, AcceptLoop, BoundListener};
pub use runner::{ForwardRunner, ForwardRunnerConfig, ForwardRunnerError};
pub use udp::{UdpFlowKey, UdpFlowTable, UdpFlowTableConfig};
