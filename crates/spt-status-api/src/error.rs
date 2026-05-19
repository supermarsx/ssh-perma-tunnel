//! Typed errors with HTTP status mapping for `spt-status-api`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;
use thiserror::Error;

/// Errors produced by status-api handlers / middleware.
///
/// Each variant maps to a specific HTTP status code via
/// [`StatusApiError::status_code`].
#[derive(Debug, Error)]
pub enum StatusApiError {
    /// Missing or malformed credentials (auth mode is `bearer` or `basic` and
    /// the request lacks a usable `Authorization` header).
    #[error("authentication required")]
    Unauthorized,

    /// Credentials provided but rejected — wrong token / wrong basic
    /// password / mTLS subject not in allow-list.
    #[error("forbidden")]
    Forbidden,

    /// Rate limit (per remote-IP token bucket) exhausted.
    #[error("rate limit exceeded")]
    RateLimited,

    /// State snapshot source unavailable (e.g. supervisor not yet started).
    #[error("status unavailable: {0}")]
    Unavailable(String),

    /// Catch-all for unexpected internal failures (logged, never echoed to
    /// the client beyond a generic message).
    #[error("internal error")]
    Internal,
}

impl StatusApiError {
    /// HTTP status code corresponding to this error.
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Short tag used in the JSON body (machine-friendly).
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::RateLimited => "rate_limited",
            Self::Unavailable(_) => "unavailable",
            Self::Internal => "internal",
        }
    }
}

impl IntoResponse for StatusApiError {
    fn into_response(self) -> Response {
        let body = json!({
            "error": self.tag(),
            "message": self.to_string(),
        });
        (self.status_code(), Json(body)).into_response()
    }
}
