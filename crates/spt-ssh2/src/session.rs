//! [`Ssh2Session`] — re-exported alias for the russh-backed
//! [`spt_protocol::TunnelSession`] implementation.
//!
//! Pre-t7 this module held a libssh2-generic `Ssh2Session<S>` wrapper. After
//! t7-Phase0 (libssh2 demolition), the russh-backed session in
//! [`crate::russh_backend`] is the only implementation. This module keeps
//! the public re-export point at `spt_ssh2::Ssh2Session` so downstream
//! callers do not have to update their `use` lines.

pub use crate::russh_backend::RusshSsh2Session as Ssh2Session;
