//! OTLP exporter setup (logs and metrics). Behind the `otlp` cargo feature.
//!
//! This is a thin glue layer — it exists so callers can opt-in to OTLP
//! without spt-observability pulling tonic/prost/OpenTelemetry into builds
//! that don't need them. The default workspace build does NOT enable this
//! feature.

#![cfg(feature = "otlp")]

use std::time::Duration;

use thiserror::Error;

/// Errors from the OTLP exporter setup.
#[derive(Debug, Error)]
pub enum OtlpError {
    /// The underlying OpenTelemetry crate rejected our config.
    #[error("OpenTelemetry: {0}")]
    Otel(String),
}

/// Configuration for the OTLP exporter.
#[derive(Debug, Clone)]
pub struct OtlpConfig {
    /// Endpoint URL (`https://otel-collector:4317`).
    pub endpoint: String,
    /// Per-export timeout.
    pub timeout: Duration,
}

/// Build a logs/metrics exporter using `opentelemetry-otlp`. The returned
/// `()` is a placeholder until callers wire spans/logs through; this stub
/// keeps the API surface stable when the feature is enabled in CI.
pub fn build(_config: &OtlpConfig) -> Result<(), OtlpError> {
    // The real implementation depends on opentelemetry / opentelemetry-otlp
    // version pinning; left as a documented hook for spt-bin (e18) to wire
    // with the rest of the runtime once MSRV survives the dep tree.
    Ok(())
}
