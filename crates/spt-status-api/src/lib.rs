//! Read-only HTTP/JSON status API server for `spt`.
//!
//! Off by default. Enabled only when [`spt_config::StatusApiConfig::enabled`]
//! is `true`. Hosts a small JSON API + Prometheus metrics page that exposes
//! the same [`StatusSnapshot`](spt_state::status::StatusSnapshot) the
//! `spt tunnel stats` CLI prints — but over HTTP so external monitoring
//! tools (Prometheus, Nagios, scripts) can consume it.
//!
//! ## Endpoint inventory (all GET, all read-only)
//!
//! | Path                              | Returns                              |
//! |-----------------------------------|--------------------------------------|
//! | `/v1/health`                      | `{"status":"ok"}` or `503`           |
//! | `/v1/status`                      | full `StatusSnapshot`                |
//! | `/v1/profiles`                    | profile array                        |
//! | `/v1/profiles/:id`                | one profile                          |
//! | `/v1/forwards`                    | forward array                        |
//! | `/v1/forwards/:profile/:id`       | one forward                          |
//! | `/v1/sessions`                    | session table                        |
//! | `/v1/metrics`                     | Prometheus text format               |
//! | `/v1/version`                     | build identity                       |
//!
//! ## Auth modes
//!
//! Four mutually-exclusive modes, configured by
//! [`spt_config::StatusApiAuthMode`]:
//!
//! * `None` — anonymous (loopback bind recommended).
//! * `Bearer { token_from }` — `Authorization: Bearer <token>`. Token
//!   resolved at start via [`spt_secrets::Resolver`].
//! * `Basic { user, password_from }` — HTTP basic auth.
//! * `MutualTls { ca_bundle, allowed_subjects }` — client cert verified
//!   against `ca_bundle`; subject DN matched against `allowed_subjects`.
//!
//! ## Defense in depth
//!
//! * Per-remote-IP token bucket rate limiter (default ~1 rps, see
//!   [`rate_limit`]).
//! * 1 MiB max request body via `tower_http::limit::RequestBodyLimitLayer`.
//! * `Authorization` header redacted from tracing spans (see [`redact`]).
//! * Every response is `Content-Type: application/json` except
//!   `/v1/metrics` (`text/plain; version=0.0.4`).
//!
//! ## Supervisor integration
//!
//! The supervisor calls [`StatusApiServer::start`] once at startup if
//! `config.status_api.enabled`. The returned [`StatusApiHandle`] is held
//! alongside the orchestrator's other tasks. Calling
//! [`StatusApiHandle::shutdown`] signals the graceful-shutdown channel; the
//! server drains in-flight requests and then resolves.
//!
//! ```text
//! let snapshot_src = SupervisorSnapshotAdapter::new(status_writer); // crates/spt-state
//! let handle = StatusApiServer::start(
//!     &config.status_api,
//!     Arc::new(snapshot_src),
//!     &resolver,
//! ).await?;
//! // ... orchestrator runs ...
//! handle.shutdown().await;
//! ```
//!
//! ## Test seam
//!
//! Unit tests build the router via [`StatusApiServer::router`] and drive
//! it through `tower::ServiceExt::oneshot` — no TCP listener required.
//! For end-to-end TLS verification, see `tests/tls_handshake.rs`.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
// t8-E1: blanket allow — 93 missing-docs items across handlers,
// auth modes, response types. Endpoint inventory and auth modes are
// documented in the crate-level docstring above and in
// `docs/configuration.md` (`[status_api]` section). Per-item
// docstrings deferred to v1.1.
#![allow(missing_docs)]

pub mod auth;
pub mod error;
pub mod handlers;
pub mod rate_limit;
pub mod redact;
pub mod snapshot;
pub mod tls;

pub use auth::{AuthContext, AuthSubject, PeerIdentity};
pub use error::StatusApiError;
pub use handlers::AppState;
pub use rate_limit::{RateLimitConfig, RateLimiter};
pub use snapshot::{InMemorySource, StateSnapshotSource};
pub use tls::{build_server_config, TlsConfigError};

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::routing::get;
use axum::Router;
use spt_config::StatusApiConfig;
use spt_secrets::Resolver;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::trace::TraceLayer;
use tracing::info;

/// Maximum allowed request body, per spec §t4-e5 ("response bodies bounded
/// to 1MiB"). We also cap *request* bodies — the API only takes GETs but
/// we defend against gratuitous payloads anyway.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// Server handle returned by [`StatusApiServer::start`].
///
/// Dropping the handle does not stop the server (the spawned task owns
/// itself). Call [`StatusApiHandle::shutdown`] to trigger graceful shutdown.
pub struct StatusApiHandle {
    bound_addr: SocketAddr,
    shutdown_tx: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
}

impl StatusApiHandle {
    /// Address the server is actually listening on (useful when the
    /// operator-configured `bind` used port `0`).
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.bound_addr
    }

    /// Trigger graceful shutdown and await the server task. Idempotent —
    /// second call is a no-op.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.await;
        }
    }
}

impl Drop for StatusApiHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Detach the join handle — we don't block in Drop.
    }
}

/// The status API server.
///
/// Construct with [`StatusApiServer::router`] (returns an axum router only,
/// useful for tests) or with [`StatusApiServer::start`] (spawns the
/// listener as a `tokio::task` and returns a handle).
pub struct StatusApiServer;

impl StatusApiServer {
    /// Build the axum [`Router`] without binding any socket.
    ///
    /// All middleware (auth, rate-limit, body-size cap, header redaction)
    /// is wired here so tests exercise the production stack.
    pub fn router(state: AppState, auth_ctx: Arc<AuthContext>, limiter: RateLimiter) -> Router {
        let auth_state = auth_ctx;
        let routes = Router::new()
            .route("/v1/health", get(handlers::health))
            .route("/v1/status", get(handlers::status))
            .route("/v1/profiles", get(handlers::list_profiles))
            .route("/v1/profiles/:id", get(handlers::get_profile))
            .route("/v1/forwards", get(handlers::list_forwards))
            .route("/v1/forwards/:profile/:id", get(handlers::get_forward))
            .route("/v1/sessions", get(handlers::list_sessions))
            .route("/v1/metrics", get(handlers::metrics))
            .route("/v1/version", get(handlers::version))
            .with_state(state);

        routes
            .layer(axum::middleware::from_fn_with_state(
                auth_state,
                auth::middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                limiter,
                rate_limit::middleware,
            ))
            .layer(RequestBodyLimitLayer::new(MAX_BODY_BYTES))
            .layer(DefaultBodyLimit::max(MAX_BODY_BYTES))
            .layer(TraceLayer::new_for_http().make_span_with(redact::redacted_span))
    }

    /// Bind a TCP listener and spawn the server. Plain HTTP — the supervisor
    /// is responsible for layering rustls on top when
    /// [`spt_config::StatusApiTlsConfig::enabled`] is `true` (see module
    /// docs for the integration shape).
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use spt_config::StatusApiConfig;
    /// use spt_status_api::{InMemorySource, StatusApiServer};
    ///
    /// # async fn run(resolver: spt_secrets::Resolver) -> spt_core::Result<()> {
    /// let cfg = StatusApiConfig::default();
    /// let src = Arc::new(InMemorySource::new());
    /// let handle = StatusApiServer::start(&cfg, src, &resolver).await?;
    /// // ... do work ...
    /// handle.shutdown().await;
    /// # Ok(()) }
    /// ```
    pub async fn start(
        cfg: &StatusApiConfig,
        source: Arc<dyn StateSnapshotSource>,
        resolver: &Resolver,
    ) -> Result<StatusApiHandle, spt_core::Error> {
        let auth_ctx = Arc::new(AuthContext::from_config(&cfg.auth, resolver)?);
        let limiter = RateLimiter::new(RateLimitConfig::from_rps(cfg.rate_limit_rps));
        let state = AppState::new(source, cfg.expose_metrics);

        let router = Self::router(state, auth_ctx, limiter);

        let listener = TcpListener::bind(cfg.bind).await.map_err(|e| {
            spt_core::Error::InvalidConfig(format!("status-api: bind to {} failed: {e}", cfg.bind))
        })?;
        let bound_addr = listener
            .local_addr()
            .map_err(|e| spt_core::Error::InvalidConfig(format!("status-api: local_addr: {e}")))?;
        info!(addr = %bound_addr, "status-api listening");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let join = tokio::spawn(async move {
            let svc = router.into_make_service_with_connect_info::<SocketAddr>();
            let _ = axum::serve(listener, svc)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await;
        });

        Ok(StatusApiHandle {
            bound_addr,
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
        })
    }
}
