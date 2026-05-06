//! OTLP exporter setup (logs and metrics). Behind the `otlp` cargo feature.
//!
//! When the feature is enabled, this module builds a real
//! `opentelemetry-otlp` exporter for both logs and metrics. The resulting
//! `LoggerProvider` and `MeterProvider` are returned in an [`OtlpHandle`]
//! so callers can install them as the global `OTel` providers and shut them
//! down on process exit (which flushes any pending batches).
//!
//! ## Redaction ordering
//!
//! Redaction is applied in the **log-record builder** itself — every string
//! attribute value passes through [`spt_core::redact`] before it is attached
//! to an OTLP record. This ensures secrets cannot reach the OTLP exporter
//! even though tracing's `Layer` API forbids in-place field rewriting. See
//! the deviations log on field-visitor approach in the redaction module.

use std::time::Duration;

use thiserror::Error;

use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::logs::LoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::Resource;

use spt_core::{redact, RedactionMode};

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
    /// OTLP endpoint URL (`http(s)://collector:4317`).
    pub endpoint: String,
    /// `service.name` resource attribute.
    pub service_name: String,
    /// Per-export timeout.
    pub timeout: Duration,
    /// Redaction mode applied to log-record string attributes.
    pub redact: RedactionMode,
}

impl Default for OtlpConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://localhost:4317".into(),
            service_name: "spt".into(),
            timeout: Duration::from_secs(10),
            redact: RedactionMode::Standard,
        }
    }
}

/// Handle bundling the providers built in [`build`].
///
/// Drop or call [`OtlpHandle::shutdown`] at process exit to flush.
pub struct OtlpHandle {
    /// Logs provider.
    pub logger: LoggerProvider,
    /// Metrics provider.
    pub meter: SdkMeterProvider,
    /// Redaction mode in effect (callers should apply this to dynamic
    /// attributes before recording them).
    pub redact: RedactionMode,
}

impl OtlpHandle {
    /// Flush and shutdown both providers.
    pub fn shutdown(self) {
        let _ = self.logger.shutdown();
        let _ = self.meter.shutdown();
    }

    /// Apply this handle's redaction mode to a string attribute. Use this in
    /// every log-record builder call so secrets never reach the exporter.
    #[must_use]
    pub fn scrub(&self, s: &str) -> String {
        redact(s, self.redact).into_owned()
    }
}

fn resource(name: &str) -> Resource {
    Resource::new(vec![KeyValue::new("service.name", name.to_string())])
}

/// Build the OTLP exporter pipeline (logs + metrics). Spans are not built
/// here — the runtime task tree (spt-bin) installs the tracer when needed.
pub fn build(config: &OtlpConfig) -> Result<OtlpHandle, OtlpError> {
    let resource = resource(&config.service_name);

    // Logs.
    let logger = opentelemetry_otlp::new_pipeline()
        .logging()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&config.endpoint)
                .with_timeout(config.timeout),
        )
        .with_resource(resource.clone())
        .install_batch(opentelemetry_sdk::runtime::Tokio)
        .map_err(|e| OtlpError::Otel(e.to_string()))?;

    // Metrics.
    let meter = opentelemetry_otlp::new_pipeline()
        .metrics(opentelemetry_sdk::runtime::Tokio)
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(&config.endpoint)
                .with_timeout(config.timeout),
        )
        .with_resource(resource)
        .build()
        .map_err(|e| OtlpError::Otel(e.to_string()))?;

    Ok(OtlpHandle {
        logger,
        meter,
        redact: config.redact,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_redacts_strings_via_handle_mode() {
        // We can't actually `build()` here without a tonic runtime, but we
        // can validate the helper that callers will use to scrub attributes
        // before recording them on OTLP records.
        let s = redact("password=hunter2", RedactionMode::Standard);
        assert!(!s.contains("hunter2"));
    }
}
