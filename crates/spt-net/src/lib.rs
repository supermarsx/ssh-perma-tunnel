//! Address parsing, interface enumeration, bind-policy resolution, socket
//! options, and Unix-domain-socket support for spt.
//!
//! Modules:
//! * [`interfaces`] — cross-platform network interface enumeration.
//! * [`cidr`] — allow/deny CIDR ACL with deny-wins semantics.
//! * [`bind`] — bind-mode resolver per spec §9.5 / §9.14.
//! * [`sockopts`] — `socket2`/Tokio TCP listener with per-platform options.
//! * [`uds`] — Unix domain socket listener helper (errors on Windows).
//! * [`privileged`] — best-effort privileged-port capability check.
//! * [`diag`] — t8-A2 network-error enrichment helpers (build
//!   [`spt_core::Error::NetworkUnreachableDiagnostic`] values that carry
//!   endpoint + retry advice via the A1 `Diagnostic` type).

// Most code is safe; the Windows privileged-port check uses FFI in
// `privileged::platform`. Allow unsafe at the crate root with a deny-by-default
// posture enforced via clippy's `undocumented_unsafe_blocks` (workspace lints).
#![warn(missing_docs)]
#![cfg_attr(not(windows), forbid(unsafe_code))]
// t8-D2: every unsafe operation inside an `unsafe fn` body must be wrapped
// in its own explicit `unsafe { … }` block. Promotes the workspace-level
// `warn` to a hard error for this crate, in line with the audit posture.
#![deny(unsafe_op_in_unsafe_fn)]

pub mod bind;
pub mod cidr;
pub mod diag;
pub mod interfaces;
pub mod privileged;
pub mod sockopts;
pub mod uds;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use bind::{resolve_bind, AutoPrefer, BindMode, Family};
pub use cidr::CidrAcl;
pub use diag::{
    classify_io_error, dns_failure, network_unreachable_from_io, network_unreachable_with,
    NetworkErrorKind,
};
pub use interfaces::{list as list_interfaces, Interface};
pub use privileged::can_bind_privileged_port;
pub use sockopts::{apply as apply_tcp_options, apply_v6_only, bind_tcp, TcpOptions};
pub use uds::bind_unix;
