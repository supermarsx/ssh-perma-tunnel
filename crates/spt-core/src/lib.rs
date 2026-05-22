//! Core types, error/exit codes, and parsers for `spt`.
//!
//! `spt-core` is the foundation crate every other crate in the workspace
//! depends on. It is intentionally pure logic with no I/O and no async — it
//! defines:
//!
//! * [`ExitCode`] — the 38 stable process exit codes from spec §7.4.
//! * [`Error`] / [`Result`] — the workspace-wide error type, which maps 1:1
//!   to [`ExitCode`].
//! * Strongly-typed [identifier newtypes][id] for sessions, connections,
//!   profiles, forwards, runs, and events.
//! * Spec-style parsers for [duration] (`"5m"`, `"1h30m"`),
//!   [size] (`"20MiB"`, `"1.5GB"`), and [bind addresses][address].
//! * [Path expansion][path] for `~`, `${VAR}`, `%VAR%`.
//! * [Redaction][redaction] primitives used before any log/event/MCP sink.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod address;
pub mod audit;
pub mod diagnostic;
pub mod duration;
pub mod error;
pub mod exit_code;
pub mod id;
pub mod path;
pub mod redacted_string;
pub mod redaction;
pub mod size;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use address::BindAddr;
pub use audit::{record_audit, register_audit_sink, AuditEvent, AuditSeverity, AuditSink};
pub use diagnostic::{Diagnostic, DiagnosticBuilder, RetryAdvice};
pub use error::{Error, Result};
pub use exit_code::ExitCode;
pub use id::{ConnectionId, EventId, ForwardId, ProfileId, RunId, SessionId};
pub use redacted_string::{RedactedString, REDACTED_DEBUG};
pub use redaction::{redact, RedactionMode};
