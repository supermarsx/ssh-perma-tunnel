//! Structured diagnostic checks and bundle builder for spt.
//!
//! Implements spec §13.12: each check has an id, severity, status, evidence
//! list, and optional remediation hint. Diagnostics never mutate system state
//! by default — callers explicitly opt into write-tests (e.g. Windows Event
//! Log probe).
//!
//! The crate ships:
//! - [`check`]           — `Check`, `Status`, `Severity` data model.
//! - [`framework`]       — `Diagnostic` trait + `DiagnosticRunner` aggregator.
//! - [`checks`]          — concrete `Diagnostic` implementations for the
//!                         toolsets §13.12 enumerates.
//! - [`port_autodetect`] — banner-read + safe-handshake port probes.
//! - [`bundle`]          — redacted tar.gz bundle builder.
//!
//! Every text written into the bundle is passed through
//! `spt_core::redact(.., RedactionMode::Strict)` — see spec §13.12
//! "Diagnostic bundles MUST be redacted by default."

#![deny(missing_docs)]

pub mod bundle;
pub mod check;
pub mod checks;
pub mod framework;
pub mod port_autodetect;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

pub use bundle::{build_bundle, BundleConfig, BundleInputs};
pub use check::{Check, Severity, Status};
pub use framework::{Diagnostic, DiagnosticContext, DiagnosticReport, DiagnosticRunner};
pub use port_autodetect::{
    autodetect, classify_banner, default_chain, AmqpDetector, BannerDetector, DetectedService,
    Detector, HttpDetector, LdapDetector, MqttDetector, PostgresDetector, RedisDetector,
    ServiceClass, TlsDetector,
};
