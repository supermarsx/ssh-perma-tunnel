//! Router-level integration tests driven via `tower::ServiceExt::oneshot`
//! — no TCP listener needed.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::Engine;
use spt_state::status::{ProfileStatus, StatusSnapshot};
use spt_status_api::{
    AppState, AuthContext, InMemorySource, RateLimitConfig, RateLimiter, StatusApiServer,
};
use tower::ServiceExt;

fn router_with(auth: AuthContext, expose_metrics: bool, rps: f32) -> axum::Router {
    let mut snap = StatusSnapshot::default();
    snap.profiles.push(ProfileStatus {
        id: "p1".into(),
        state: "Running".into(),
        last_successful_connection_at: Some(chrono::Utc::now()),
        ..Default::default()
    });
    let source = Arc::new(InMemorySource::with_snapshot(snap));
    source.set_metrics("# HELP spt_up 1\nspt_up 1\n");
    let state = AppState::new(source, expose_metrics);
    let limiter = RateLimiter::new(RateLimitConfig {
        rps,
        burst: rps.max(1.0),
        idle_eviction: std::time::Duration::from_secs(600),
    });
    StatusApiServer::router(state, Arc::new(auth), limiter)
}

#[tokio::test]
async fn health_returns_200_on_running_profile() {
    let router = router_with(AuthContext::none(), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn health_503_when_profile_failed_long_ago() {
    let mut snap = StatusSnapshot::default();
    snap.profiles.push(ProfileStatus {
        id: "p1".into(),
        state: "Failed".into(),
        last_successful_connection_at: None,
        ..Default::default()
    });
    let source = Arc::new(InMemorySource::with_snapshot(snap));
    let state = AppState::new(source, true);
    let router = StatusApiServer::router(
        state,
        Arc::new(AuthContext::none()),
        RateLimiter::new(RateLimitConfig {
            rps: 1000.0,
            burst: 1000.0,
            idle_eviction: std::time::Duration::from_secs(600),
        }),
    );
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn bearer_missing_token_401() {
    let router = router_with(AuthContext::bearer("hunter2"), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bearer_valid_token_200() {
    let router = router_with(AuthContext::bearer("hunter2"), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/health")
        .header("Authorization", "Bearer hunter2")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn bearer_wrong_token_401() {
    let router = router_with(AuthContext::bearer("hunter2"), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/health")
        .header("Authorization", "Bearer wrong")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn basic_valid_creds_200() {
    let router = router_with(AuthContext::basic("monitoring", "s3cret"), true, 1000.0);
    let encoded = base64::engine::general_purpose::STANDARD.encode("monitoring:s3cret");
    let req = Request::builder()
        .uri("/v1/health")
        .header("Authorization", format!("Basic {encoded}"))
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn basic_missing_401() {
    let router = router_with(AuthContext::basic("u", "p"), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn version_endpoint_returns_msrv() {
    let router = router_with(AuthContext::none(), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/version")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["msrv"], "1.83");
}

#[tokio::test]
async fn metrics_endpoint_text_content_type() {
    let router = router_with(AuthContext::none(), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.starts_with("text/plain"), "got {ct}");
    let bytes = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
    assert!(!bytes.is_empty());
}

#[tokio::test]
async fn metrics_endpoint_404_when_disabled() {
    let router = router_with(AuthContext::none(), false, 1000.0);
    let req = Request::builder()
        .uri("/v1/metrics")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn profiles_list_returns_array() {
    let router = router_with(AuthContext::none(), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/profiles")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
    let v: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(v["profiles"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn profile_by_id_404() {
    let router = router_with(AuthContext::none(), true, 1000.0);
    let req = Request::builder()
        .uri("/v1/profiles/nonexistent")
        .body(Body::empty())
        .unwrap();
    let resp = router.oneshot(req).await.unwrap();
    // Maps to Unavailable -> 503.
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn rate_limit_70_requests_in_one_burst_rejects_majority() {
    // burst=5, rps=1 -> first 5 pass, rest 429.
    let router = router_with(AuthContext::none(), true, 1.0);
    let mut accepted = 0;
    let mut rejected = 0;
    for _ in 0..70 {
        let req = Request::builder()
            .uri("/v1/health")
            .body(Body::empty())
            .unwrap();
        let resp = router.clone().oneshot(req).await.unwrap();
        match resp.status() {
            StatusCode::OK => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => rejected += 1,
            other => panic!("unexpected status {other}"),
        }
    }
    assert!(
        rejected >= 10,
        "expected >=10 rate-limited, got {rejected} (accepted={accepted})"
    );
}
