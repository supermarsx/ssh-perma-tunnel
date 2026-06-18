//! Runtime state directory, locks, and atomic writes for spt.
//!
//! This crate manages the on-disk state directory layout described in the spec
//! §13.5 / plan §3, including:
//!
//! * [`dir`] — per-OS resolution of the state directory.
//! * [`lock`] — exclusive process lock via `fs4`.
//! * [`atomic`] — atomic file replacement helpers.
//! * [`status`] — the status snapshot writer task.
//! * [`events`] — bounded JSONL event ring with daily rotation.
//! * [`spool`] — bounded on-disk spool for sinks.
//! * [`paths`] — single source of truth for state-file paths.
//! * [`portable`] — runtime context for `--portable` mode (gates every
//!   `BaseDirs` leakage site).

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// t8-E1: blanket allow — 93 missing-docs items across the
// StatusSnapshot type tree (per spec §13.5). Schema is documented in
// the spec itself and in `docs/observability.md`. Per-item docstrings
// deferred to v1.1.
#![allow(missing_docs)]

pub mod atomic;
pub mod clock;
pub mod dir;
pub mod events;
pub mod lock;
pub mod paths;
pub mod portable;
pub mod runtime;
pub mod spool;
pub mod status;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use atomic::{write_atomic, write_atomic_string};
pub use clock::{Clock, SystemClock};
pub use dir::resolve_state_dir;
pub use events::{Event, EventRing, EventRingConfig};
pub use lock::StateLock;
pub use portable::{ensure_writable, portable_context_for, PortableContext};
pub use runtime::{
    read_runtime, write_runtime, DnsStatus, EventsStatus, McpStatus, MetricsStatus,
    RemoteConfigPollerStatus, RuntimeStatus, StatusApiStatus, Subsystems,
};
pub use spool::{DiskSpool, SpoolConfig, SpoolEntry};
pub use status::{
    Counters, FailoverState, StatusSnapshot, StatusWriter, StatusWriterConfig, StatusWriterHandle,
};
