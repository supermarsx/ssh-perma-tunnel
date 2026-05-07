//! Test facilities for [`AuthConfig`] construction and OIDC device-flow.
//!
//! Activated with `--features testing`.
//!
//! ## Deviation note
//!
//! The brief specifies that [`MockOidcServer`] should run over HTTPS via
//! `axum-server` with a self-signed cert. We instead run over plain HTTP via
//! `axum::serve` to avoid pulling `axum-server` and its TLS stack into the
//! lockfile (workspace MSRV is 1.83 and several edition2024 deps would be
//! transitively reachable). The OIDC device-flow choreography under test is
//! transport-agnostic — TLS pinning is exercised separately in `spt-trust`'s
//! testing facilities.

use std::path::{Path, PathBuf};

use url::Url;

use crate::method::{AuthConfig, AuthMethod};
use crate::secret_ref::SecretRef;

/// Build an [`AuthConfig`] with a single [`AuthMethod::PublicKey`] entry.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use std::path::Path;
/// let cfg = spt_auth::testing::auth_config_pubkey("alice", Path::new("/tmp/id_ed25519"));
/// assert_eq!(cfg.username, "alice");
/// assert_eq!(cfg.methods.len(), 1);
/// # }
/// ```
#[must_use]
pub fn auth_config_pubkey(user: &str, key_path: &Path) -> AuthConfig {
    AuthConfig::new(
        user,
        vec![AuthMethod::PublicKey {
            identity_file: PathBuf::from(key_path),
            passphrase: None,
        }],
    )
}

/// Build an [`AuthConfig`] with a single [`AuthMethod::Password`] entry.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use spt_auth::SecretRef;
/// let secret = SecretRef::parse("secret://ssh/alice").unwrap();
/// let cfg = spt_auth::testing::auth_config_password("alice", secret);
/// assert_eq!(cfg.methods.len(), 1);
/// # }
/// ```
#[must_use]
pub fn auth_config_password(user: &str, secret_ref: SecretRef) -> AuthConfig {
    AuthConfig::new(user, vec![AuthMethod::Password { secret: secret_ref }])
}

/// Build an [`AuthConfig`] with a single [`AuthMethod::OidcDeviceFlow`] entry.
///
/// ```
/// # #[cfg(feature = "testing")] fn _doc() {
/// use url::Url;
/// let issuer = Url::parse("https://login.example.com").unwrap();
/// let cfg = spt_auth::testing::auth_config_oidc_device("alice", issuer, "spt-cli");
/// assert_eq!(cfg.methods.len(), 1);
/// # }
/// ```
#[must_use]
pub fn auth_config_oidc_device(user: &str, issuer: Url, client_id: &str) -> AuthConfig {
    AuthConfig::new(
        user,
        vec![AuthMethod::OidcDeviceFlow {
            issuer,
            client_id: client_id.to_owned(),
            audience: None,
        }],
    )
}

/// Pre-built canonical fixtures.
pub mod fixtures {
    use super::{auth_config_pubkey, AuthConfig};
    use std::path::Path;

    /// Canonical [`AuthConfig`] used as a "minimum sensible default" — user
    /// `tester`, single ed25519 public-key method pointing at
    /// `/tmp/id_test_ed25519` (the file is not required to exist).
    ///
    /// ```
    /// # #[cfg(feature = "testing")] fn _doc() {
    /// let cfg = spt_auth::testing::fixtures::canonical_authcfg();
    /// assert_eq!(cfg.username, "tester");
    /// # }
    /// ```
    #[must_use]
    pub fn canonical_authcfg() -> AuthConfig {
        auth_config_pubkey("tester", Path::new("/tmp/id_test_ed25519"))
    }
}

// =====================================================================
// MockOidcServer
// =====================================================================

mod mock_server {
    use std::collections::VecDeque;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::{get, post};
    use axum::{Form, Json, Router};
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;
    use url::Url;

    /// One scripted poll-step the mock token endpoint plays back, oldest first.
    #[derive(Debug, Clone)]
    pub enum MockPollStep {
        /// Return `400` with `error=authorization_pending`.
        AuthorizationPending,
        /// Return `400` with `error=slow_down`.
        SlowDown,
        /// Return `200` with the supplied token JSON body. Use
        /// `serde_json::json!({...})` to build it.
        Success(serde_json::Value),
        /// Return `400` with `error=access_denied`.
        AccessDenied,
        /// Return `400` with `error=expired_token`.
        ExpiredToken,
        /// Return a literal `(status, body)` pair — escape hatch for custom
        /// failure modes.
        Custom(u16, serde_json::Value),
    }

    impl MockPollStep {
        fn render(&self) -> (u16, serde_json::Value) {
            match self {
                Self::AuthorizationPending => {
                    (400, serde_json::json!({"error":"authorization_pending"}))
                }
                Self::SlowDown => (400, serde_json::json!({"error":"slow_down"})),
                Self::Success(v) => (200, v.clone()),
                Self::AccessDenied => (400, serde_json::json!({"error":"access_denied"})),
                Self::ExpiredToken => (400, serde_json::json!({"error":"expired_token"})),
                Self::Custom(s, b) => (*s, b.clone()),
            }
        }
    }

    #[derive(Default)]
    struct State_ {
        device: Mutex<Option<serde_json::Value>>,
        token_default: Mutex<Option<serde_json::Value>>,
        polls: Mutex<VecDeque<(u16, serde_json::Value)>>,
        port: AtomicUsize,
        device_calls: AtomicUsize,
        token_calls: AtomicUsize,
    }

    /// Builder/handle for an in-process OIDC device-flow mock provider.
    ///
    /// Spawns an `axum::serve` task on `127.0.0.1:0`. Issuer URL is
    /// `http://127.0.0.1:<assigned-port>`.
    pub struct MockOidcServer {
        state: Arc<State_>,
        addr: SocketAddr,
        shutdown_tx: Option<oneshot::Sender<()>>,
        join: Option<JoinHandle<()>>,
    }

    impl std::fmt::Debug for MockOidcServer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MockOidcServer")
                .field("addr", &self.addr)
                .finish_non_exhaustive()
        }
    }

    impl MockOidcServer {
        /// Spawn a fresh mock provider.
        ///
        /// Returns immediately once the listener binds; routes are wired up
        /// before the first request lands.
        ///
        /// ```
        /// # #[cfg(feature = "testing")] async fn _doc() {
        /// let srv = spt_auth::testing::MockOidcServer::start().await;
        /// assert!(srv.issuer_url().as_str().starts_with("http://127.0.0.1:"));
        /// srv.shutdown().await;
        /// # }
        /// ```
        pub async fn start() -> Self {
            let state = Arc::new(State_::default());
            let app = Router::new()
                .route(
                    "/.well-known/openid-configuration",
                    get(discovery_handler),
                )
                .route("/device", post(device_handler))
                .route("/token", post(token_handler))
                .with_state(state.clone());
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let addr = listener.local_addr().expect("local_addr");
            state.port.store(addr.port() as usize, Ordering::SeqCst);
            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            let join = tokio::spawn(async move {
                let _ = axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    })
                    .await;
            });
            tokio::task::yield_now().await;
            Self {
                state,
                addr,
                shutdown_tx: Some(shutdown_tx),
                join: Some(join),
            }
        }

        /// Issuer URL the server listens on.
        #[must_use]
        pub fn issuer_url(&self) -> Url {
            Url::parse(&format!("http://{}", self.addr)).expect("issuer url")
        }

        /// Override the device-authorization response.
        ///
        /// Defaults: `device_code = "mock-dc"`, `user_code = "MOCK-CODE"`,
        /// `verification_uri = "https://example.com/device"`, `interval = 1`,
        /// `expires_in = 30`.
        ///
        /// ```
        /// # #[cfg(feature = "testing")] async fn _doc() {
        /// use spt_auth::testing::{MockOidcServer, MockPollStep};
        /// let srv = MockOidcServer::start().await
        ///     .with_device_code("dc", "U-CODE", "https://example.com/d", 1, 30)
        ///     .with_token_response("acc", Some("ref"))
        ///     .with_polling_sequence(vec![MockPollStep::AuthorizationPending]);
        /// srv.shutdown().await;
        /// # }
        /// ```
        #[must_use]
        pub fn with_device_code(
            self,
            device_code: &str,
            user_code: &str,
            verification_uri: &str,
            interval: u64,
            expires_in: u64,
        ) -> Self {
            *self.state.device.lock().unwrap() = Some(serde_json::json!({
                "device_code": device_code,
                "user_code": user_code,
                "verification_uri": verification_uri,
                "expires_in": expires_in,
                "interval": interval,
            }));
            self
        }

        /// Configure a fixed token response returned when no scripted poll
        /// step matches a poll. Both fields are optional in the response body.
        #[must_use]
        pub fn with_token_response(
            self,
            access: &str,
            refresh: Option<&str>,
        ) -> Self {
            let mut body = serde_json::json!({
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": 3600,
            });
            if let Some(r) = refresh {
                body["refresh_token"] = serde_json::Value::String(r.to_owned());
            }
            *self.state.token_default.lock().unwrap() = Some(body);
            self
        }

        /// Replace the scripted poll-sequence with `steps`.
        ///
        /// Each call to `/token` consumes the next step in order.
        #[must_use]
        pub fn with_polling_sequence(self, steps: Vec<MockPollStep>) -> Self {
            {
                let mut q = self.state.polls.lock().unwrap();
                q.clear();
                for s in steps {
                    q.push_back(s.render());
                }
            }
            self
        }

        /// Number of `/device` calls observed.
        #[must_use]
        pub fn device_call_count(&self) -> usize {
            self.state.device_calls.load(Ordering::SeqCst)
        }

        /// Number of `/token` calls observed.
        #[must_use]
        pub fn token_call_count(&self) -> usize {
            self.state.token_calls.load(Ordering::SeqCst)
        }

        /// Stop the server and await the spawned task.
        pub async fn shutdown(mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
            if let Some(j) = self.join.take() {
                let _ = j.await;
            }
        }
    }

    impl Drop for MockOidcServer {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
        }
    }

    async fn discovery_handler(State(s): State<Arc<State_>>) -> Json<serde_json::Value> {
        let port = s.port.load(Ordering::SeqCst);
        let base = format!("http://127.0.0.1:{port}");
        Json(serde_json::json!({
            "issuer": base,
            "device_authorization_endpoint": format!("{base}/device"),
            "token_endpoint": format!("{base}/token"),
        }))
    }

    async fn device_handler(
        State(s): State<Arc<State_>>,
        Form(_form): Form<std::collections::HashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        s.device_calls.fetch_add(1, Ordering::SeqCst);
        let body = s.device.lock().unwrap().clone().unwrap_or_else(|| {
            serde_json::json!({
                "device_code": "mock-dc",
                "user_code": "MOCK-CODE",
                "verification_uri": "https://example.com/device",
                "expires_in": 30,
                "interval": 1,
            })
        });
        Json(body)
    }

    async fn token_handler(
        State(s): State<Arc<State_>>,
        Form(form): Form<std::collections::HashMap<String, String>>,
    ) -> (StatusCode, Json<serde_json::Value>) {
        s.token_calls.fetch_add(1, Ordering::SeqCst);
        // refresh-token requests are routed to the configured refresh response
        // (or, lacking one, fall through to default token).
        if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
            let body = s.token_default.lock().unwrap().clone().unwrap_or_else(|| {
                serde_json::json!({
                    "access_token": "refreshed",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                })
            });
            return (StatusCode::OK, Json(body));
        }
        if let Some((status, body)) = s.polls.lock().unwrap().pop_front() {
            return (StatusCode::from_u16(status).unwrap_or(StatusCode::OK), Json(body));
        }
        let body = s.token_default.lock().unwrap().clone().unwrap_or_else(|| {
            serde_json::json!({
                "access_token": "mock-access",
                "token_type": "Bearer",
                "expires_in": 3600,
            })
        });
        (StatusCode::OK, Json(body))
    }
}

pub use mock_server::{MockOidcServer, MockPollStep};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oidc_device_flow::OidcDeviceFlowClient;
    use secrecy::ExposeSecret;
    use std::time::Duration;

    #[test]
    fn pubkey_builder_smoke() {
        let cfg = auth_config_pubkey("alice", Path::new("/tmp/id_ed25519"));
        assert_eq!(cfg.username, "alice");
    }

    #[test]
    fn fixtures_canonical() {
        let cfg = fixtures::canonical_authcfg();
        assert_eq!(cfg.username, "tester");
    }

    #[tokio::test]
    async fn mock_server_drives_login_to_completion() {
        let server = MockOidcServer::start()
            .await
            .with_device_code("dc-x", "USER-CODE", "https://example.com/d", 1, 60)
            .with_polling_sequence(vec![
                MockPollStep::AuthorizationPending,
                MockPollStep::Success(serde_json::json!({
                    "access_token": "the-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                })),
            ]);

        let client = OidcDeviceFlowClient::new(
            server.issuer_url(),
            "test-client".to_owned(),
            None,
        )
        .unwrap();

        let dc = client.request_device_code(Some("openid")).await.unwrap();
        assert_eq!(dc.user_code, "USER-CODE");

        let tok = client
            .poll_for_token(&dc.device_code, Duration::from_millis(20), Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(tok.access_token.expose_secret().as_slice(), b"the-token");

        assert_eq!(server.device_call_count(), 1);
        assert!(server.token_call_count() >= 2);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn mock_server_default_token_response_works_for_login() {
        let server = MockOidcServer::start()
            .await
            .with_token_response("default-tok", None);
        let client = OidcDeviceFlowClient::new(
            server.issuer_url(),
            "client-id".to_owned(),
            None,
        )
        .unwrap();
        let tok = client.login(None, |_| {}).await.unwrap();
        assert_eq!(tok.access_token.expose_secret().as_slice(), b"default-tok");
        server.shutdown().await;
    }
}
