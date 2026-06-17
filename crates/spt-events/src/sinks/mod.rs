//! Notification sink trait + concrete implementations.
//!
//! All sinks share the [`Sink`] trait. Concrete sinks accept their I/O
//! transport via trait objects so unit tests can substitute mocks; no real
//! network I/O happens during `cargo test`.

use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::event::Event;

pub mod build;
pub mod command;
pub mod email;
pub mod http;
pub mod mcp_notify;
pub mod push;
pub mod sms;

pub use build::{build_sink, resolve_secret, SinkDeps};

/// Errors a sink may return.
#[derive(Debug, Error)]
pub enum SinkError {
    /// Transient/retryable transport failure — dispatcher SHOULD enqueue
    /// on the disk spool for later retry.
    #[error("transient sink failure: {0}")]
    Transient(String),
    /// Permanent/non-retryable failure (e.g. malformed config).
    #[error("permanent sink failure: {0}")]
    Permanent(String),
    /// Configuration error — never retried.
    #[error("invalid sink configuration: {0}")]
    Config(String),
}

impl SinkError {
    /// True if the dispatcher should spool/retry this failure.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Transient(_))
    }
}

/// All sinks implement this trait. Implementations MUST be idempotent
/// where possible — the dispatcher may retry on transient failures.
#[async_trait]
pub trait Sink: Send + Sync {
    /// The unique sink name (matches `BindingMatch`'s `SinkRef`).
    fn name(&self) -> &str;
    /// Sink kind — used for log fields and disk spool subdirectories.
    fn kind(&self) -> &'static str;
    /// Deliver one event. Errors are classified per [`SinkError`].
    async fn deliver(&self, event: Arc<Event>) -> Result<(), SinkError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retryable_classification() {
        assert!(SinkError::Transient("x".into()).is_retryable());
        assert!(!SinkError::Permanent("x".into()).is_retryable());
        assert!(!SinkError::Config("x".into()).is_retryable());
    }
}
