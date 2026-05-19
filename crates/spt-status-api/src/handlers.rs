//! Route handlers.
//!
//! Each handler takes the shared [`AppState`] and a route-specific param,
//! reads from the [`crate::snapshot::StateSnapshotSource`] held inside the
//! state, and returns either a JSON value or a typed
//! [`crate::error::StatusApiError`].
//!
//! Handlers contain no I/O of their own beyond the snapshot source call —
//! all live data is funnelled through the trait, so unit tests substitute
//! [`crate::snapshot::InMemorySource`].

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::Utc;
use serde_json::{json, Value};
use spt_state::status::StatusSnapshot;

use crate::error::StatusApiError;
use crate::snapshot::StateSnapshotSource;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    /// Snapshot source. Boxed-trait so different supervisor impls plug in.
    pub source: Arc<dyn StateSnapshotSource>,
    /// `false` disables `/v1/metrics` (returns 404).
    pub expose_metrics: bool,
    /// Threshold (seconds) above which a `Failed` / `Reconnecting` profile
    /// pushes `/v1/health` to `503`.
    pub failed_threshold_secs: i64,
}

impl AppState {
    /// Construct a new [`AppState`].
    #[must_use]
    pub fn new(source: Arc<dyn StateSnapshotSource>, expose_metrics: bool) -> Self {
        Self {
            source,
            expose_metrics,
            failed_threshold_secs: 30,
        }
    }
}

/// `GET /v1/health` — liveness/readiness summary.
///
/// Returns `503` if any profile is in `Failed`/`Reconnecting` for longer
/// than `failed_threshold_secs` seconds (per the supervisor's own
/// timestamps in the snapshot).
pub async fn health(State(state): State<AppState>) -> Response {
    let snap = state.source.snapshot().await;
    let now = Utc::now();
    let mut degraded_reason: Option<String> = None;
    for p in &snap.profiles {
        let state_str = p.state.to_ascii_lowercase();
        if !matches!(state_str.as_str(), "failed" | "reconnecting") {
            continue;
        }
        let stale = p
            .last_successful_connection_at
            .map_or(true, |t| (now - t).num_seconds() > state.failed_threshold_secs);
        if stale {
            degraded_reason = Some(format!(
                "profile {} in state `{}`",
                p.id, p.state
            ));
            break;
        }
    }

    let (code, body) = if let Some(reason) = degraded_reason {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            json!({"status": "degraded", "reason": reason}),
        )
    } else {
        (StatusCode::OK, json!({"status": "ok"}))
    };
    (code, Json(body)).into_response()
}

/// `GET /v1/status` — full snapshot.
pub async fn status(State(state): State<AppState>) -> Result<Json<StatusSnapshot>, StatusApiError> {
    Ok(Json(state.source.snapshot().await))
}

/// `GET /v1/profiles`.
pub async fn list_profiles(
    State(state): State<AppState>,
) -> Result<Json<Value>, StatusApiError> {
    let snap = state.source.snapshot().await;
    Ok(Json(json!({ "profiles": snap.profiles })))
}

/// `GET /v1/profiles/:id`.
pub async fn get_profile(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<Value>, StatusApiError> {
    let snap = state.source.snapshot().await;
    let p = snap
        .profiles
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| StatusApiError::Unavailable(format!("no profile `{id}`")))?;
    Ok(Json(json!(p)))
}

/// `GET /v1/forwards`.
pub async fn list_forwards(
    State(state): State<AppState>,
) -> Result<Json<Value>, StatusApiError> {
    let snap = state.source.snapshot().await;
    Ok(Json(json!({ "forwards": snap.forwards })))
}

/// `GET /v1/forwards/:profile/:id`.
pub async fn get_forward(
    State(state): State<AppState>,
    Path((profile, id)): Path<(String, String)>,
) -> Result<Json<Value>, StatusApiError> {
    let snap = state.source.snapshot().await;
    let f = snap
        .forwards
        .into_iter()
        .find(|f| f.profile == profile && f.id == id)
        .ok_or_else(|| StatusApiError::Unavailable(format!("no forward `{profile}/{id}`")))?;
    Ok(Json(json!(f)))
}

/// `GET /v1/sessions`.
pub async fn list_sessions(
    State(state): State<AppState>,
) -> Result<Json<Value>, StatusApiError> {
    let snap = state.source.snapshot().await;
    Ok(Json(json!({ "sessions": snap.sessions })))
}

/// `GET /v1/metrics` — Prometheus text format. Returns 404 when
/// `expose_metrics = false`.
pub async fn metrics(State(state): State<AppState>) -> Response {
    if !state.expose_metrics {
        return (StatusCode::NOT_FOUND, "metrics disabled").into_response();
    }
    let body = state.source.metrics_prom().await;
    let mut resp = body.into_response();
    resp.headers_mut().insert(
        CONTENT_TYPE,
        "text/plain; version=0.0.4".parse().expect("valid header"),
    );
    resp
}

/// `GET /v1/version` — build identity.
pub async fn version() -> Json<Value> {
    Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "git_sha": option_env!("SPT_GIT_SHA").unwrap_or("unknown"),
        "msrv": "1.83",
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::InMemorySource;
    use spt_state::status::ProfileStatus;

    fn state_with(snap: StatusSnapshot) -> AppState {
        AppState::new(Arc::new(InMemorySource::with_snapshot(snap)), true)
    }

    #[tokio::test]
    async fn health_ok_when_no_profiles() {
        let s = state_with(StatusSnapshot::default());
        let resp = health(State(s)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn health_503_when_failed_profile_stale() {
        let mut snap = StatusSnapshot::default();
        snap.profiles.push(ProfileStatus {
            id: "p1".into(),
            state: "Failed".into(),
            last_successful_connection_at: None,
            ..Default::default()
        });
        let s = state_with(snap);
        let resp = health(State(s)).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn health_ok_when_failed_profile_recent() {
        let mut snap = StatusSnapshot::default();
        snap.profiles.push(ProfileStatus {
            id: "p1".into(),
            state: "Failed".into(),
            // Very recent — under the 30s threshold.
            last_successful_connection_at: Some(Utc::now()),
            ..Default::default()
        });
        let s = state_with(snap);
        let resp = health(State(s)).await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn version_returns_msrv() {
        let v = version().await;
        assert_eq!(v.0["msrv"], "1.83");
        assert!(v.0["version"].is_string());
    }
}
