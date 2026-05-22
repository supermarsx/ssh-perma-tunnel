//! Rolling counters, sliding windows, and session/connection tables.
//!
//! # Modules
//! * [`counters`] — `RollingCounter` with bucketed time windows.
//! * [`windows`] — sliding-window aggregates (bytes / conns / errors).
//! * [`tables`] — `dashmap`-backed session and connection tables.
//! * [`ewma`] — exponentially-weighted moving averages for throughput.
//! * [`instability`] — instability detection trait for spt-supervisor.
//!
//! All time-aware structures take a `Clock` trait so tests can inject fake
//! clocks.

#![warn(missing_docs)]
#![forbid(unsafe_code)]

pub mod clock;
pub mod counters;
pub mod ewma;
pub mod instability;
#[allow(missing_docs)] // t7-CCI: deferred — 20 items in tables.rs to be documented in follow-up.
pub mod tables;
pub mod windows;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use clock::{Clock, SystemClock, TestClock};
pub use counters::RollingCounter;
pub use ewma::Ewma;
pub use instability::{InstabilityDetector, InstabilityVerdict, ThresholdInstability};
pub use tables::{ConnectionEntry, ConnectionTable, SessionEntry, SessionTable};
pub use windows::{SlidingWindow, WindowAggregates};
