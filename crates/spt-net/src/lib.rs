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

// Most code is safe; the Windows privileged-port check uses FFI in
// `privileged::platform`. Allow unsafe at the crate root with a deny-by-default
// posture enforced via clippy's `undocumented_unsafe_blocks` (workspace lints).
#![cfg_attr(not(windows), forbid(unsafe_code))]

pub mod bind;
pub mod cidr;
pub mod interfaces;
pub mod privileged;
pub mod sockopts;
pub mod uds;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use bind::{AutoPrefer, BindMode, Family, resolve_bind};
pub use cidr::CidrAcl;
pub use interfaces::{Interface, list as list_interfaces};
pub use privileged::can_bind_privileged_port;
pub use sockopts::{TcpOptions, apply as apply_tcp_options, apply_v6_only, bind_tcp};
pub use uds::bind_unix;
