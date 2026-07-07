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

use crate::crypto::NegotiatedCryptoRegistry;
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
    /// Additive negotiated-crypto side table, keyed by session id.
    ///
    /// The canonical `spt_state::status::SessionStatus` has no field for
    /// negotiated cryptographic parameters and `spt-state` is out of this
    /// crate's ownership, so we overlay the data here. `spt-bin` populates the
    /// shared registry at session establishment (see
    /// [`AppState::with_crypto_registry`]); the session-list handlers merge it
    /// into their JSON by session id. Defaults to empty, so all existing
    /// constructors/tests keep working unchanged.
    pub crypto_registry: NegotiatedCryptoRegistry,
}

impl AppState {
    /// Construct a new [`AppState`].
    ///
    /// The negotiated-crypto registry starts empty; attach a shared one with
    /// [`AppState::with_crypto_registry`].
    #[must_use]
    pub fn new(source: Arc<dyn StateSnapshotSource>, expose_metrics: bool) -> Self {
        Self {
            source,
            expose_metrics,
            failed_threshold_secs: 30,
            crypto_registry: NegotiatedCryptoRegistry::new(),
        }
    }

    /// Attach a shared [`NegotiatedCryptoRegistry`] (builder-style).
    ///
    /// `spt-bin` creates one registry, keeps a clone for the emission site
    /// where sessions are established, and passes another clone here so the
    /// `/v1/sessions` and `/v1/status` responses can be enriched with the
    /// negotiated crypto per session.
    #[must_use]
    pub fn with_crypto_registry(mut self, registry: NegotiatedCryptoRegistry) -> Self {
        self.crypto_registry = registry;
        self
    }
}

/// Overlay `negotiated_crypto` onto each session object in `sessions` whose
/// `id` has an entry in the registry snapshot.
///
/// This is an **additive overlay**: the canonical `spt_state::SessionStatus`
/// (serialized verbatim upstream) is out of this crate's ownership and has no
/// negotiated-crypto field, so we merge the side-table data into the already
/// serialized JSON here. Sessions with no registry entry are left unchanged.
fn enrich_sessions(sessions: &mut Value, registry: &NegotiatedCryptoRegistry) {
    let table = registry.snapshot();
    if table.is_empty() {
        return;
    }
    let Some(arr) = sessions.as_array_mut() else {
        return;
    };
    for session in arr {
        let Some(obj) = session.as_object_mut() else {
            continue;
        };
        // The session-id field in `spt_state::status::SessionStatus` is `id`.
        let Some(id) = obj.get("id").and_then(Value::as_str) else {
            continue;
        };
        if let Some(nc) = table.get(id) {
            if let Ok(nc_value) = serde_json::to_value(nc) {
                obj.insert("negotiated_crypto".to_string(), nc_value);
            }
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
            .is_none_or(|t| (now - t).num_seconds() > state.failed_threshold_secs);
        if stale {
            degraded_reason = Some(format!("profile {} in state `{}`", p.id, p.state));
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
///
/// The `sessions` array is enriched with an additive `negotiated_crypto`
/// object per session that has a registry entry (see [`enrich_sessions`]).
pub async fn status(State(state): State<AppState>) -> Result<Json<Value>, StatusApiError> {
    let snap = state.source.snapshot().await;
    let mut value = serde_json::to_value(&snap)
        .map_err(|e| StatusApiError::Unavailable(format!("serialize status snapshot: {e}")))?;
    if let Some(sessions) = value.get_mut("sessions") {
        enrich_sessions(sessions, &state.crypto_registry);
    }
    Ok(Json(value))
}

/// `GET /v1/profiles`.
pub async fn list_profiles(State(state): State<AppState>) -> Result<Json<Value>, StatusApiError> {
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
pub async fn list_forwards(State(state): State<AppState>) -> Result<Json<Value>, StatusApiError> {
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
///
/// Each session object is enriched with an additive `negotiated_crypto`
/// object when the registry holds an entry for that session id (see
/// [`enrich_sessions`]); sessions without an entry are returned unchanged.
pub async fn list_sessions(State(state): State<AppState>) -> Result<Json<Value>, StatusApiError> {
    let snap = state.source.snapshot().await;
    let mut sessions = serde_json::to_value(&snap.sessions)
        .map_err(|e| StatusApiError::Unavailable(format!("serialize sessions: {e}")))?;
    enrich_sessions(&mut sessions, &state.crypto_registry);
    Ok(Json(json!({ "sessions": sessions })))
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
    use crate::crypto::NegotiatedCrypto;
    use crate::snapshot::InMemorySource;
    use spt_state::status::{ProfileStatus, SessionStatus, StatusSnapshot};

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
    async fn list_sessions_overlays_negotiated_crypto_by_id() {
        let mut snap = StatusSnapshot::default();
        snap.sessions.push(SessionStatus {
            id: "sess-a".into(),
            ..Default::default()
        });
        snap.sessions.push(SessionStatus {
            id: "sess-b".into(),
            ..Default::default()
        });

        // Registry has an entry only for sess-a.
        let reg = NegotiatedCryptoRegistry::new();
        let nc = NegotiatedCrypto::parse(
            "transport=ssh2 kex=mlkem768x25519-sha256 hostkey=ssh-ed25519 pq_offered=true",
        )
        .expect("parses");
        reg.insert("sess-a", nc);

        let state = AppState::new(Arc::new(InMemorySource::with_snapshot(snap)), true)
            .with_crypto_registry(reg);

        let Json(body) = list_sessions(State(state)).await.expect("ok");
        let sessions = body["sessions"].as_array().expect("array");

        let a = sessions
            .iter()
            .find(|s| s["id"] == "sess-a")
            .expect("sess-a present");
        let nc = &a["negotiated_crypto"];
        assert_eq!(nc["transport"], "ssh2");
        assert_eq!(nc["host_key_algo"], "ssh-ed25519");
        assert_eq!(nc["pq_offered"], true);

        // sess-b has no registry entry -> no overlay key.
        let b = sessions
            .iter()
            .find(|s| s["id"] == "sess-b")
            .expect("sess-b present");
        assert!(
            b.get("negotiated_crypto").is_none(),
            "sess-b must not carry negotiated_crypto"
        );
    }

    #[tokio::test]
    async fn status_overlays_negotiated_crypto_in_session_array() {
        let mut snap = StatusSnapshot::default();
        snap.sessions.push(SessionStatus {
            id: "sess-x".into(),
            ..Default::default()
        });
        let reg = NegotiatedCryptoRegistry::new();
        reg.insert(
            "sess-x",
            NegotiatedCrypto::parse("transport=ssh3 tls_version=TLS1.3 alpn=h3").expect("parses"),
        );
        let state = AppState::new(Arc::new(InMemorySource::with_snapshot(snap)), true)
            .with_crypto_registry(reg);

        let Json(body) = status(State(state)).await.expect("ok");
        let sessions = body["sessions"].as_array().expect("array");
        let x = &sessions[0];
        assert_eq!(x["negotiated_crypto"]["transport"], "ssh3");
        assert_eq!(x["negotiated_crypto"]["alpn"], "h3");
    }

    #[tokio::test]
    async fn list_sessions_without_registry_is_unchanged() {
        let mut snap = StatusSnapshot::default();
        snap.sessions.push(SessionStatus {
            id: "sess-a".into(),
            ..Default::default()
        });
        // Default AppState -> empty registry.
        let state = AppState::new(Arc::new(InMemorySource::with_snapshot(snap)), true);
        let Json(body) = list_sessions(State(state)).await.expect("ok");
        let sessions = body["sessions"].as_array().expect("array");
        assert!(sessions[0].get("negotiated_crypto").is_none());
    }

    #[tokio::test]
    async fn version_returns_msrv() {
        let v = version().await;
        assert_eq!(v.0["msrv"], "1.83");
        assert!(v.0["version"].is_string());
    }
}
