//! SSH3 backend for spt built on QUIC, rustls, and HTTP/3.
//!
//! # Status: PARTIAL-REAL (spt↔spt channel framing live)
//!
//! This crate ships a real QUIC + TLS 1.3 + HTTP/3 Extended-CONNECT bootstrap
//! against the francoismichel/ssh3 reference. Per-forward channel framing
//! (direct-tcp, tcpip-forward, UDP datagram association) is live for spt↔spt
//! interop on a custom wire contract documented in [`forward`] and [`frame`].
//! Bit-compat with francoismichel/ssh3's reference framing is NOT claimed —
//! real-server interop is gated on the `SPT_SSH3_TEST_SERVER` integration test.
//!
//! Live today:
//!
//! * QUIC client via [`quinn`] with a [`rustls`] TLS config that honors
//!   system roots, optional CA file, optional SHA-256 SPKI pin
//!   ([`spt_trust::TlsPin`]), and `allow_self_signed`.
//! * HTTP/3 client via [`h3`] + [`h3-quinn`] performing **Extended CONNECT**
//!   with `:protocol = ssh3`, Bearer or Basic auth, and a configurable
//!   `:path`.
//! * The mandatory `tracing::warn!` experimental notice on every
//!   `connect()` call (and on `validate`/`doctor`/`tunnel run` startup),
//!   unless the operator sets `acknowledge_experimental = true` on the
//!   [`Ssh3Config`]. This satisfies the spec §4.2 requirement.
//!
//! See [`crates/spt-ssh3/readme.md`](https://github.com/Mariana/ssh-perma-tunnel/blob/main/crates/spt-ssh3/readme.md)
//! for the full rationale and the path to a non-stub implementation.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod auth_header;
pub mod config;
pub mod forward;
pub mod frame;
pub(crate) mod h3_raw;
pub mod jwt;
pub mod protocol;
pub mod session;
pub mod tls;
pub mod transport;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use auth_header::build_authorization_header;
pub use config::{Ssh3AuthExtras, Ssh3Config, Ssh3TlsConfig};
pub use frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3FrameKind, Ssh3Settings,
    Ssh3StreamKind, UdpAssociatePayload,
};
pub use protocol::{Ssh3Protocol, EXPERIMENTAL_WARNING, PARTIAL_REAL_REASON};
pub use session::Ssh3Session;
pub use transport::{
    accept_control_stream, bootstrap, build_connect_request, open_control_stream,
    BootstrappedSession,
};
