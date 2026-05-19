//! Tracing-span construction with Authorization-header redaction.
//!
//! `tower_http::trace::TraceLayer` by default puts request headers into the
//! span. We don't want bearer tokens or basic-auth credentials in logs, so
//! [`redacted_span`] copies the request shape (method, URI, version) into
//! the span without the `Authorization` value.

use axum::extract::Request;
use tracing::Span;

/// Build a tracing span for a request, omitting the `Authorization` header
/// value. Used as the [`tower_http::trace::TraceLayer::make_span_with`]
/// callback.
#[must_use]
pub fn redacted_span(req: &Request) -> Span {
    let method = req.method();
    let uri = req.uri();
    let auth_present = req.headers().get(axum::http::header::AUTHORIZATION).is_some();
    tracing::info_span!(
        "status_api_request",
        method = %method,
        uri = %uri,
        // Note: we record only PRESENCE, never the value, so a leaked log
        // file never contains the bearer token or basic-auth password.
        auth_present = auth_present,
    )
}
