//! Tracing subscriber stack, redaction, file rotation, and metrics for spt.
//!
//! # Modules
//!
//! * [`init()`] — `init(&LoggingConfig) -> TracingGuard` builds the
//!   `tracing-subscriber::Registry` with stacked layers per destination
//!   (stderr / file-with-rotation / journald-on-linux).
//! * [`redaction`] — byte-level redaction wrapper applied to every sink so
//!   secrets cannot leak past the formatter.
//! * [`metrics`] — Prometheus text-format exporter with periodic atomic
//!   write to `metrics.prom`.
//! * `otlp` — OTLP exporter setup (feature-gated `otlp`).
//! * [`config`] — local config types consumed by [`init()`]; mirrors a subset
//!   of `spt-config::Logging` so this crate can be tested in isolation.

#![forbid(unsafe_code)]

pub mod config;
pub mod https_jsonl;
pub mod init;
pub mod metrics;
pub mod redaction;
pub mod rotation;
pub mod syslog_common;
pub mod syslog_tcp;
pub mod syslog_tls;
pub mod syslog_udp;

#[cfg(feature = "otlp")]
pub mod otlp;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use config::{LoggingConfig, RemoteSink, RemoteSinkKind, RotationPolicy};
pub use init::{init, init_for_test, TracingGuard};
pub use metrics::{MetricsExporter, MetricsExporterConfig, MetricsExporterHandle};
pub use redaction::{RedactingMakeWriter, RedactingWriter};
