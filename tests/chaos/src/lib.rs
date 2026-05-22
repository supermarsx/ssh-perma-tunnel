//! Chaos / reconnect scenario harness for `spt`.
//!
//! C1 lays down the infrastructure: a [`harness::ChaosHarness`] that wires
//! a [`spt_chaos_proxy::ChaosProxy`] in front of a stub SSH server, plus a
//! [`MockAuditSink`] / [`ReconnectAttempt`] capture layer riding on
//! [`spt_supervisor::reconnect::install_test_hook`]. C2 will populate
//! `src/scenarios/` with the 12 reconnect scenarios that build on this
//! infrastructure.
//!
//! The harness is deliberately permissive — the `spt` binary subprocess
//! and the stub SSH server are both no-op stubs in C1 (see
//! [`harness::SshServer`] and [`harness::SptProcess`]). C2 replaces them
//! with real subprocess wiring once the scenario list is agreed.
//!
//! ## MSRV
//!
//! 1.85 (matches the workspace).

#![forbid(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod harness;
pub mod scenarios;

pub use harness::{
    AuditEvent, ChaosHarness, MockAuditSink, ReconnectAttempt, SshServer,
};
