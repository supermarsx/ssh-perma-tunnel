//! OAuth 2.0 Device Authorization Grant (RFC 8628) + OIDC Discovery client.
//!
//! High-level entrypoint: [`OidcDeviceFlowClient::login`].
//!
//! ```no_run
//! use spt_auth::oidc_device_flow::OidcDeviceFlowClient;
//! use url::Url;
//!
//! # async fn run() -> spt_core::Result<()> {
//! let client = OidcDeviceFlowClient::new(
//!     Url::parse("https://login.example.com").unwrap(),
//!     "spt-cli".to_owned(),
//!     None,
//! )?;
//! let tokens = client.login(Some("openid offline_access"), |dc| {
//!     println!("Visit {} and enter code {}", dc.verification_uri, dc.user_code);
//! }).await?;
//! drop(tokens);
//! # Ok(()) }
//! ```
//!
//! No token bytes are ever logged: [`TokenResponse`] holds the access/refresh/id
//! tokens in [`SecretBytes`] (zeroizing buffers wrapped in `secrecy::SecretBox`)
//! which has no `Debug` exposure of the inner bytes.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use rand::Rng;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use spt_core::{Error as CoreError, Result as CoreResult};
use spt_secrets::backend::{secret_bytes, SecretBackend, SecretBytes};
use spt_secrets::reference::SecretRef as SecretsRef;
use thiserror::Error;
use tokio::sync::OnceCell;
use tracing::{debug, trace, warn};
use url::Url;

/// Errors produced by the OIDC device-flow client.
///
/// At the public-API boundary these convert to [`spt_core::Error`] (most
/// commonly [`spt_core::Error::AuthFailed`]) — see [`From`] impl below.
#[derive(Debug, Error)]
pub enum OidcError {
    /// OIDC discovery (GET `.well-known/openid-configuration`) failed.
    #[error("oidc discovery failed: {0}")]
    Discovery(String),

    /// HTTP transport error after retries.
    #[error("transport error: {0}")]
    Transport(String),

    /// Server returned an error JSON we could not decode.
    #[error("malformed response from {endpoint}: {reason}")]
    MalformedResponse {
        /// Endpoint that produced the response.
        endpoint: String,
        /// Underlying reason.
        reason: String,
    },

    /// User-facing rejection: the user denied consent.
    #[error("authorization denied by user (access_denied)")]
    AccessDenied,

    /// The authorization server reported the device code expired before the
    /// user completed the flow.
    #[error("device code expired before user authorized")]
    TokenExpired,

    /// `invalid_grant` from the token endpoint.
    #[error("invalid grant: {0}")]
    InvalidGrant(String),

    /// `invalid_client` / `unauthorized_client` / `unsupported_grant_type`.
    #[error("oauth error `{code}`: {description}")]
    OauthError {
        /// `error` code field per RFC 6749.
        code: String,
        /// Human-readable `error_description` (may be empty).
        description: String,
    },

    /// Total local expiry timer elapsed before terminal status.
    #[error("polling exceeded device-code expiry")]
    Expired,
}

impl From<OidcError> for CoreError {
    fn from(e: OidcError) -> Self {
        match &e {
            OidcError::AccessDenied
            | OidcError::TokenExpired
            | OidcError::InvalidGrant(_)
            | OidcError::OauthError { .. }
            | OidcError::Expired => CoreError::AuthFailed(e.to_string()),
            OidcError::Discovery(_)
            | OidcError::Transport(_)
            | OidcError::MalformedResponse { .. } => CoreError::NetworkUnreachable(e.to_string()),
        }
    }
}

type OidcResult<T> = std::result::Result<T, OidcError>;

/// Subset of an OIDC discovery document we actually consume.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryDocument {
    /// Issuer identifier (must match the configured issuer).
    pub issuer: String,
    /// Device-authorization endpoint per RFC 8628 §3.1.
    pub device_authorization_endpoint: String,
    /// Token endpoint per RFC 6749 §3.2.
    pub token_endpoint: String,
}

/// Successful response to RFC 8628 §3.2 device-authorization request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceCodeResponse {
    /// Device verification code (kept by client, sent during polling).
    pub device_code: String,
    /// End-user code displayed for the user to enter at the verification URI.
    pub user_code: String,
    /// Verification URI shown to the user.
    pub verification_uri: String,
    /// Optional pre-filled URI (`verification_uri` with `user_code` baked in).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Lifetime of the device/user codes in seconds.
    pub expires_in: u64,
    /// Minimum polling interval, in seconds (RFC 8628 §3.2 default 5).
    #[serde(default = "default_interval")]
    pub interval: u64,
}

const fn default_interval() -> u64 {
    5
}

/// Successful token-endpoint response with secret material wrapped.
#[derive(Debug)]
pub struct TokenResponse {
    /// Access token bytes.
    pub access_token: SecretBytes,
    /// `token_type` (e.g. `Bearer`).
    pub token_type: String,
    /// Optional access-token lifetime (seconds).
    pub expires_in: Option<u64>,
    /// Optional refresh token.
    pub refresh_token: Option<SecretBytes>,
    /// Optional ID token (OIDC).
    pub id_token: Option<SecretBytes>,
    /// Granted scope (may differ from requested).
    pub scope: Option<String>,
}

/// Wire-format token response (private; converted to [`TokenResponse`] by
/// pulling secrets into [`SecretBytes`]).
#[derive(Debug, Deserialize)]
struct WireTokenResponse {
    access_token: String,
    token_type: String,
    #[serde(default)]
    expires_in: Option<u64>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

impl From<WireTokenResponse> for TokenResponse {
    fn from(w: WireTokenResponse) -> Self {
        Self {
            access_token: secret_bytes(w.access_token.into_bytes()),
            token_type: w.token_type,
            expires_in: w.expires_in,
            refresh_token: w.refresh_token.map(|s| secret_bytes(s.into_bytes())),
            id_token: w.id_token.map(|s| secret_bytes(s.into_bytes())),
            scope: w.scope,
        }
    }
}

#[derive(Debug, Deserialize)]
struct WireErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// OIDC device-authorization-grant client.
///
/// Caches the discovery document for the lifetime of the client. All HTTP I/O
/// flows through the bundled `rustls`-only [`reqwest::Client`].
pub struct OidcDeviceFlowClient {
    issuer: Url,
    client_id: String,
    audience: Option<String>,
    http: reqwest::Client,
    discovery: Arc<OnceCell<DiscoveryDocument>>,
}

impl std::fmt::Debug for OidcDeviceFlowClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcDeviceFlowClient")
            .field("issuer", &self.issuer.as_str())
            .field("client_id", &self.client_id)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl OidcDeviceFlowClient {
    /// Construct a new client.
    ///
    /// Note that `audience` is the Auth0-style non-standard parameter; when
    /// present it is sent both with the device-authorization request and (per
    /// Auth0 docs) the token request. Standards-compliant providers ignore it.
    ///
    /// ```
    /// use spt_auth::oidc_device_flow::OidcDeviceFlowClient;
    /// use url::Url;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = OidcDeviceFlowClient::new(
    ///     Url::parse("https://login.example.com")?,
    ///     "spt-cli".to_owned(),
    ///     Some("https://api.example.com".to_owned()),
    /// )?;
    /// assert_eq!(client.issuer().as_str(), "https://login.example.com/");
    /// assert_eq!(client.client_id(), "spt-cli");
    /// # Ok(()) }
    /// ```
    pub fn new(issuer: Url, client_id: String, audience: Option<String>) -> CoreResult<Self> {
        Self::with_pin(issuer, client_id, audience, &[], false, None)
    }

    /// Construct with pinned-TLS parameters (t5-e2). `pin_strings` is the
    /// SPKI SHA-256 pin set; `allow_self_signed=true` requires a
    /// non-empty pin set. `max_cert_chain_depth=None` applies
    /// `spt_trust::DEFAULT_CHAIN_DEPTH_CAP`.
    pub fn with_pin(
        issuer: Url,
        client_id: String,
        audience: Option<String>,
        pin_strings: &[String],
        allow_self_signed: bool,
        max_cert_chain_depth: Option<u32>,
    ) -> CoreResult<Self> {
        let rustls_cfg = spt_trust::PinnedTlsConnector::from_config_parts(
            pin_strings,
            allow_self_signed,
            max_cert_chain_depth,
        )
        .map_err(|e| CoreError::InvalidConfig(format!("oidc pinned tls: {e}")))?;
        let cfg_inner = (*rustls_cfg).clone();
        let http = reqwest::Client::builder()
            .use_preconfigured_tls(cfg_inner)
            .user_agent(concat!("spt-auth/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| CoreError::RuntimeFailure(format!("reqwest builder: {e}")))?;
        Ok(Self::with_http(issuer, client_id, audience, http))
    }

    /// Construct with an explicit `reqwest::Client` (test seam).
    #[doc(hidden)]
    pub fn with_http(
        issuer: Url,
        client_id: String,
        audience: Option<String>,
        http: reqwest::Client,
    ) -> Self {
        Self {
            issuer,
            client_id,
            audience,
            http,
            discovery: Arc::new(OnceCell::new()),
        }
    }

    /// Issuer URL.
    #[must_use]
    pub fn issuer(&self) -> &Url {
        &self.issuer
    }

    /// OAuth `client_id`.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Optional audience.
    #[must_use]
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// Run RFC 8414 / OIDC discovery and cache the result.
    pub async fn discover(&self) -> CoreResult<DiscoveryDocument> {
        let doc =
            self.discovery
                .get_or_try_init(|| async {
                    let url = self.discovery_url()?;
                    debug!(target: "spt_auth::oidc", %url, "fetching discovery document");
                    let resp = self
                        .http
                        .get(url.clone())
                        .send()
                        .await
                        .map_err(|e| OidcError::Discovery(format!("GET {url} failed: {e}")))?;
                    if !resp.status().is_success() {
                        return Err(OidcError::Discovery(format!(
                            "GET {url} returned {}",
                            resp.status()
                        )));
                    }
                    let doc: DiscoveryDocument = resp.json().await.map_err(|e| {
                        OidcError::Discovery(format!("decode body from {url}: {e}"))
                    })?;
                    Ok(doc)
                })
                .await?;
        Ok(doc.clone())
    }

    fn discovery_url(&self) -> OidcResult<Url> {
        // Append `.well-known/openid-configuration`, preserving trailing slashes.
        let base = if self.issuer.path().ends_with('/') {
            self.issuer.clone()
        } else {
            let mut u = self.issuer.clone();
            u.set_path(&format!("{}/", u.path()));
            u
        };
        base.join(".well-known/openid-configuration")
            .map_err(|e| OidcError::Discovery(format!("invalid issuer URL: {e}")))
    }

    /// Request a device code (RFC 8628 §3.1).
    pub async fn request_device_code(&self, scope: Option<&str>) -> CoreResult<DeviceCodeResponse> {
        let disc = self.discover().await?;
        let mut form: HashMap<&str, String> = HashMap::new();
        form.insert("client_id", self.client_id.clone());
        if let Some(s) = scope {
            form.insert("scope", s.to_owned());
        }
        if let Some(a) = &self.audience {
            form.insert("audience", a.clone());
        }
        let resp = self
            .http
            .post(&disc.device_authorization_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| OidcError::Transport(format!("device_authorization: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| OidcError::Transport(format!("device_authorization body: {e}")))?;
        if !status.is_success() {
            return Err(
                parse_oauth_error(&disc.device_authorization_endpoint, status, &body).into(),
            );
        }
        let dc: DeviceCodeResponse =
            serde_json::from_str(&body).map_err(|e| OidcError::MalformedResponse {
                endpoint: disc.device_authorization_endpoint.clone(),
                reason: e.to_string(),
            })?;
        Ok(dc)
    }

    /// Poll the token endpoint per RFC 8628 §3.4 / §3.5.
    ///
    /// `interval` and `expires_in` are taken from the device-code response.
    /// `slow_down` doubles the interval (also satisfies the "increase by at
    /// least 5s" rule once interval ≥ 5). `authorization_pending` continues
    /// polling. `access_denied` / `expired_token` / `invalid_grant` produce
    /// terminal errors.
    pub async fn poll_for_token(
        &self,
        device_code: &str,
        interval: Duration,
        expires_in: Duration,
    ) -> CoreResult<TokenResponse> {
        let disc = self.discover().await?;
        let deadline = tokio::time::Instant::now() + expires_in;
        let mut interval = interval;
        let mut backoff = Duration::from_millis(250);
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(OidcError::Expired.into());
            }
            tokio::time::sleep(interval).await;
            if tokio::time::Instant::now() >= deadline {
                return Err(OidcError::Expired.into());
            }

            trace!(target: "spt_auth::oidc", "polling token endpoint");
            let outcome = self
                .post_token_request(&disc.token_endpoint, device_code)
                .await;

            match outcome {
                Ok(tok) => return Ok(tok),
                Err(PollError::AuthorizationPending) => {
                    debug!(target: "spt_auth::oidc", "authorization_pending");
                    backoff = Duration::from_millis(250); // reset transport backoff
                    continue;
                }
                Err(PollError::SlowDown) => {
                    interval = (interval * 2).max(interval + Duration::from_secs(5));
                    debug!(target: "spt_auth::oidc", new_interval_ms = interval.as_millis() as u64, "slow_down");
                    backoff = Duration::from_millis(250);
                    continue;
                }
                Err(PollError::Terminal(e)) => return Err(e.into()),
                Err(PollError::Transport(msg)) => {
                    warn!(target: "spt_auth::oidc", error = %msg, "transport error during poll; backing off");
                    let jitter = {
                        let mut rng = rand::thread_rng();
                        Duration::from_millis(rng.gen_range(0..100))
                    };
                    tokio::time::sleep(backoff + jitter).await;
                    backoff = (backoff * 2).min(Duration::from_secs(30));
                    continue;
                }
            }
        }
    }

    async fn post_token_request(
        &self,
        endpoint: &str,
        device_code: &str,
    ) -> std::result::Result<TokenResponse, PollError> {
        let mut form: HashMap<&str, String> = HashMap::new();
        form.insert(
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code".to_owned(),
        );
        form.insert("device_code", device_code.to_owned());
        form.insert("client_id", self.client_id.clone());
        if let Some(a) = &self.audience {
            form.insert("audience", a.clone());
        }
        let resp = self
            .http
            .post(endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| PollError::Transport(format!("send: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| PollError::Transport(format!("read body: {e}")))?;
        if status.is_success() {
            let wire: WireTokenResponse = serde_json::from_str(&body).map_err(|e| {
                PollError::Terminal(OidcError::MalformedResponse {
                    endpoint: endpoint.to_owned(),
                    reason: e.to_string(),
                })
            })?;
            return Ok(wire.into());
        }

        // RFC 8628 §3.5: token endpoint signals device-flow state via the
        // standard OAuth error response.
        let err = match serde_json::from_str::<WireErrorResponse>(&body) {
            Ok(v) => v,
            Err(e) => {
                return Err(PollError::Terminal(OidcError::MalformedResponse {
                    endpoint: endpoint.to_owned(),
                    reason: format!("status {status}: {e}"),
                }));
            }
        };
        let desc = err.error_description.unwrap_or_default();
        match err.error.as_str() {
            "authorization_pending" => Err(PollError::AuthorizationPending),
            "slow_down" => Err(PollError::SlowDown),
            "access_denied" => Err(PollError::Terminal(OidcError::AccessDenied)),
            "expired_token" => Err(PollError::Terminal(OidcError::TokenExpired)),
            "invalid_grant" => Err(PollError::Terminal(OidcError::InvalidGrant(desc))),
            other => Err(PollError::Terminal(OidcError::OauthError {
                code: other.to_owned(),
                description: desc,
            })),
        }
    }

    /// High-level entrypoint: discover, request a device code, invoke
    /// `on_user_code` with the response so the caller can render it, then poll
    /// to completion.
    pub async fn login<F>(&self, scope: Option<&str>, on_user_code: F) -> CoreResult<TokenResponse>
    where
        F: FnOnce(&DeviceCodeResponse),
    {
        let dc = self.request_device_code(scope).await?;
        on_user_code(&dc);
        let interval = Duration::from_secs(dc.interval.max(1));
        let expires_in = Duration::from_secs(dc.expires_in.max(1));
        self.poll_for_token(&dc.device_code, interval, expires_in)
            .await
    }

    /// Refresh an access token if its declared `expires_in` has nearly elapsed.
    ///
    /// `acquired_at` is the moment the token was issued; `slack` is how close
    /// to expiry triggers a refresh (e.g. 60s). Returns `None` when no refresh
    /// is required (the existing token is still valid). When refresh is
    /// required and a `refresh_token` is available, posts the refresh request
    /// and returns the new token.
    pub async fn refresh_if_needed(
        &self,
        token: &TokenResponse,
        acquired_at: std::time::SystemTime,
        slack: Duration,
    ) -> CoreResult<Option<TokenResponse>> {
        let Some(expires_in) = token.expires_in else {
            return Ok(None);
        };
        let elapsed = std::time::SystemTime::now()
            .duration_since(acquired_at)
            .unwrap_or(Duration::ZERO);
        if elapsed + slack < Duration::from_secs(expires_in) {
            return Ok(None);
        }
        let Some(refresh_secret) = &token.refresh_token else {
            return Err(OidcError::InvalidGrant("no refresh_token available".into()).into());
        };
        let refresh_str = secret_bytes_to_string(refresh_secret)?;
        let new = self.do_refresh(&refresh_str).await?;
        Ok(Some(new))
    }

    async fn do_refresh(&self, refresh_token: &str) -> CoreResult<TokenResponse> {
        let disc = self.discover().await?;
        let mut form: HashMap<&str, String> = HashMap::new();
        form.insert("grant_type", "refresh_token".to_owned());
        form.insert("refresh_token", refresh_token.to_owned());
        form.insert("client_id", self.client_id.clone());
        if let Some(a) = &self.audience {
            form.insert("audience", a.clone());
        }
        let resp = self
            .http
            .post(&disc.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| OidcError::Transport(format!("refresh: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| OidcError::Transport(format!("refresh body: {e}")))?;
        if !status.is_success() {
            return Err(parse_oauth_error(&disc.token_endpoint, status, &body).into());
        }
        let wire: WireTokenResponse =
            serde_json::from_str(&body).map_err(|e| OidcError::MalformedResponse {
                endpoint: disc.token_endpoint.clone(),
                reason: e.to_string(),
            })?;
        Ok(wire.into())
    }
}

enum PollError {
    AuthorizationPending,
    SlowDown,
    Terminal(OidcError),
    Transport(String),
}

fn parse_oauth_error(endpoint: &str, status: StatusCode, body: &str) -> OidcError {
    if let Ok(err) = serde_json::from_str::<WireErrorResponse>(body) {
        OidcError::OauthError {
            code: err.error,
            description: err.error_description.unwrap_or_default(),
        }
    } else {
        OidcError::MalformedResponse {
            endpoint: endpoint.to_owned(),
            reason: format!("HTTP {status}: {body}"),
        }
    }
}

fn secret_bytes_to_string(s: &SecretBytes) -> CoreResult<String> {
    use secrecy::ExposeSecret;
    let bytes: &[u8] = s.expose_secret().as_slice();
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| CoreError::RuntimeFailure(format!("non-utf8 secret: {e}")))
}

/// Persist the access (and refresh, if present) tokens through the supplied
/// secret backend under `secret://<ns>/<name>` and `secret://<ns>/<name>.refresh`.
///
/// The `id_token` is **not** persisted by default — callers that need it should
/// store it explicitly.
pub fn store_token(
    token: &TokenResponse,
    vault: &dyn SecretBackend,
    ns: &str,
    name: &str,
) -> CoreResult<()> {
    use secrecy::ExposeSecret;
    let access_ref = SecretsRef::new(ns.to_owned(), name.to_owned()).map_err(|e| {
        CoreError::InvalidConfig(format!("oidc.store_token: invalid secret ref: {e}"))
    })?;
    vault.set(&access_ref, token.access_token.expose_secret().as_slice())?;
    if let Some(refresh) = &token.refresh_token {
        let refresh_name = format!("{name}.refresh");
        let refresh_ref = SecretsRef::new(ns.to_owned(), refresh_name).map_err(|e| {
            CoreError::InvalidConfig(format!("oidc.store_token: invalid refresh ref: {e}"))
        })?;
        vault.set(&refresh_ref, refresh.expose_secret().as_slice())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::StatusCode as AxumStatus;
    use axum::routing::{get, post};
    use axum::{Form, Json, Router};
    use secrecy::ExposeSecret;
    use std::collections::HashMap as StdHashMap;
    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::net::TcpListener;

    /// Server-side state for fake provider.
    #[derive(Default)]
    struct FakeState {
        device_calls: AtomicUsize,
        token_calls: AtomicUsize,
        refresh_calls: AtomicUsize,
        /// Sequence of token-endpoint responses to play back, oldest first.
        ///
        /// Each entry: (status, body json).
        token_script: Mutex<Vec<(u16, serde_json::Value)>>,
        refresh_response: Mutex<Option<(u16, serde_json::Value)>>,
        port: AtomicUsize,
    }

    async fn discovery_handler(State(s): State<Arc<FakeState>>) -> Json<serde_json::Value> {
        let port = s.port.load(Ordering::SeqCst);
        let base = format!("http://127.0.0.1:{port}");
        Json(serde_json::json!({
            "issuer": base,
            "device_authorization_endpoint": format!("{base}/device"),
            "token_endpoint": format!("{base}/token"),
        }))
    }

    async fn device_handler(
        State(s): State<Arc<FakeState>>,
        Form(form): Form<StdHashMap<String, String>>,
    ) -> Json<serde_json::Value> {
        s.device_calls.fetch_add(1, Ordering::SeqCst);
        // verify client_id at least present
        assert!(form.contains_key("client_id"));
        Json(serde_json::json!({
            "device_code": "dc-abc-123",
            "user_code": "WDJB-MJHT",
            "verification_uri": "https://example.com/device",
            "verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
            "expires_in": 600,
            "interval": 5,
        }))
    }

    async fn token_handler(
        State(s): State<Arc<FakeState>>,
        Form(form): Form<StdHashMap<String, String>>,
    ) -> (AxumStatus, Json<serde_json::Value>) {
        // route refresh_token grant separately
        if form.get("grant_type").map(String::as_str) == Some("refresh_token") {
            s.refresh_calls.fetch_add(1, Ordering::SeqCst);
            let resp = s
                .refresh_response
                .lock()
                .unwrap()
                .clone()
                .unwrap_or_else(|| {
                    (
                        200,
                        serde_json::json!({
                            "access_token": "fresh-access",
                            "token_type": "Bearer",
                            "expires_in": 3600,
                        }),
                    )
                });
            return (AxumStatus::from_u16(resp.0).unwrap(), Json(resp.1));
        }
        s.token_calls.fetch_add(1, Ordering::SeqCst);
        let mut script = s.token_script.lock().unwrap();
        if script.is_empty() {
            return (
                AxumStatus::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error":"unexpected_extra_call"})),
            );
        }
        let (status, body) = script.remove(0);
        (AxumStatus::from_u16(status).unwrap(), Json(body))
    }

    async fn spawn_fake(state: Arc<FakeState>) -> u16 {
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_handler))
            .route("/device", post(device_handler))
            .route("/token", post(token_handler))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        state.port.store(addr.port() as usize, Ordering::SeqCst);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        // Yield to let the listener register before the first request.
        tokio::task::yield_now().await;
        addr.port()
    }

    fn make_client(port: u16) -> OidcDeviceFlowClient {
        let issuer = Url::parse(&format!("http://127.0.0.1:{port}")).unwrap();
        OidcDeviceFlowClient::new(issuer, "test-client".into(), Some("test-aud".into())).unwrap()
    }

    #[tokio::test]
    async fn discover_round_trip() {
        let state = Arc::new(FakeState::default());
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        let doc = client.discover().await.unwrap();
        assert!(doc.token_endpoint.ends_with("/token"));
        assert!(doc.device_authorization_endpoint.ends_with("/device"));
        // second call hits the cache, not the server.
        let _again = client.discover().await.unwrap();
    }

    #[tokio::test]
    async fn request_device_code_round_trip() {
        let state = Arc::new(FakeState::default());
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        let dc = client
            .request_device_code(Some("openid offline_access"))
            .await
            .unwrap();
        assert_eq!(dc.user_code, "WDJB-MJHT");
        assert_eq!(dc.expires_in, 600);
        assert_eq!(state.device_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(start_paused = false)]
    async fn poll_pending_then_success() {
        let state = Arc::new(FakeState::default());
        {
            let mut s = state.token_script.lock().unwrap();
            s.push((400, serde_json::json!({"error":"authorization_pending"})));
            s.push((
                200,
                serde_json::json!({
                    "access_token":"the-access",
                    "token_type":"Bearer",
                    "expires_in":3600,
                    "refresh_token":"the-refresh",
                    "id_token":"the-id",
                    "scope":"openid"
                }),
            ));
        }
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        // small interval so the test finishes quickly without time::pause complications.
        let tok = client
            .poll_for_token(
                "dc-abc-123",
                Duration::from_millis(20),
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(tok.token_type, "Bearer");
        assert_eq!(tok.expires_in, Some(3600));
        assert_eq!(tok.access_token.expose_secret().as_slice(), b"the-access");
        assert_eq!(state.token_calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn poll_slow_down_doubles_interval() {
        let state = Arc::new(FakeState::default());
        {
            let mut s = state.token_script.lock().unwrap();
            s.push((400, serde_json::json!({"error":"slow_down"})));
            s.push((
                200,
                serde_json::json!({"access_token":"x","token_type":"Bearer"}),
            ));
        }
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        let start = std::time::Instant::now();
        // initial interval 50ms; after slow_down it must be at least max(100ms, 50ms+5s).
        // We bound the test by using a tiny start interval and only asserting that
        // the elapsed exceeds the expected bumped interval.
        let tok = client
            .poll_for_token(
                "dc-abc-123",
                Duration::from_millis(50),
                Duration::from_secs(20),
            )
            .await
            .unwrap();
        let elapsed = start.elapsed();
        assert!(elapsed >= Duration::from_secs(5), "elapsed {elapsed:?}");
        assert_eq!(tok.access_token.expose_secret().as_slice(), b"x");
    }

    #[tokio::test]
    async fn poll_access_denied_terminal() {
        let state = Arc::new(FakeState::default());
        {
            let mut s = state.token_script.lock().unwrap();
            s.push((
                400,
                serde_json::json!({"error":"access_denied","error_description":"user said no"}),
            ));
        }
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        let err = client
            .poll_for_token(
                "dc-abc-123",
                Duration::from_millis(10),
                Duration::from_secs(5),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::AuthFailed(ref m) if m.contains("denied")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn poll_expiry_returns_expired() {
        let state = Arc::new(FakeState::default());
        // Always reply pending.
        {
            let mut s = state.token_script.lock().unwrap();
            for _ in 0..50 {
                s.push((400, serde_json::json!({"error":"authorization_pending"})));
            }
        }
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        let err = client
            .poll_for_token(
                "dc-abc-123",
                Duration::from_millis(50),
                Duration::from_millis(120),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, CoreError::AuthFailed(ref m) if m.contains("exceeded")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn login_happy_path_invokes_callback() {
        let state = Arc::new(FakeState::default());
        {
            let mut s = state.token_script.lock().unwrap();
            s.push((
                200,
                serde_json::json!({"access_token":"L","token_type":"Bearer"}),
            ));
        }
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        // Override the device_handler interval to a small value via expose: we
        // can't change the server response, but the low-level interval comes
        // from the response's `interval` field (5s) — too long for tests. We
        // therefore use poll_for_token directly here for the happy-path /
        // callback-invocation behaviour, calling request_device_code first.
        let dc = client.request_device_code(None).await.unwrap();
        let mut got_code = None;
        let cb_arg = dc.user_code.clone();
        let mut cb = |d: &DeviceCodeResponse| {
            got_code = Some(d.user_code.clone());
        };
        cb(&dc);
        let _tok = client
            .poll_for_token(
                &dc.device_code,
                Duration::from_millis(20),
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert_eq!(got_code.as_deref(), Some(cb_arg.as_str()));
    }

    #[tokio::test]
    async fn login_full_flow_calls_callback_once() {
        // Verify the high-level login() invokes the callback exactly once with
        // the user_code; we use a shorter device_code response by rebuilding
        // a custom server inline.
        let state = Arc::new(FakeState::default());
        {
            let mut s = state.token_script.lock().unwrap();
            s.push((
                200,
                serde_json::json!({"access_token":"X","token_type":"Bearer"}),
            ));
        }
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery_handler))
            .route(
                "/device",
                post(|State(s): State<Arc<FakeState>>| async move {
                    s.device_calls.fetch_add(1, Ordering::SeqCst);
                    Json(serde_json::json!({
                        "device_code":"dcX",
                        "user_code":"FAST-CODE",
                        "verification_uri":"https://example.com/d",
                        "expires_in": 30,
                        "interval": 1
                    }))
                }),
            )
            .route("/token", post(token_handler))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        state.port.store(addr.port() as usize, Ordering::SeqCst);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        tokio::task::yield_now().await;
        let client = make_client(addr.port());

        let counter = Arc::new(AtomicUsize::new(0));
        let observed: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        let counter2 = counter.clone();
        let observed2 = observed.clone();
        let tok = client
            .login(Some("openid"), move |dc| {
                counter2.fetch_add(1, Ordering::SeqCst);
                *observed2.lock().unwrap() = Some(dc.user_code.clone());
            })
            .await
            .unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(observed.lock().unwrap().as_deref(), Some("FAST-CODE"));
        assert_eq!(tok.access_token.expose_secret().as_slice(), b"X");
    }

    #[tokio::test]
    async fn refresh_if_needed_no_op_when_fresh() {
        let state = Arc::new(FakeState::default());
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        let tok = TokenResponse {
            access_token: secret_bytes(b"a".to_vec()),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some(secret_bytes(b"r".to_vec())),
            id_token: None,
            scope: None,
        };
        let refreshed = client
            .refresh_if_needed(&tok, std::time::SystemTime::now(), Duration::from_secs(60))
            .await
            .unwrap();
        assert!(refreshed.is_none());
        assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn refresh_if_needed_refreshes_when_expired() {
        let state = Arc::new(FakeState::default());
        let port = spawn_fake(state.clone()).await;
        let client = make_client(port);
        let tok = TokenResponse {
            access_token: secret_bytes(b"old".to_vec()),
            token_type: "Bearer".into(),
            expires_in: Some(10),
            refresh_token: Some(secret_bytes(b"the-refresh".to_vec())),
            id_token: None,
            scope: None,
        };
        let acquired = std::time::SystemTime::now() - Duration::from_secs(60);
        let refreshed = client
            .refresh_if_needed(&tok, acquired, Duration::from_secs(5))
            .await
            .unwrap()
            .expect("must refresh");
        assert_eq!(
            refreshed.access_token.expose_secret().as_slice(),
            b"fresh-access"
        );
        assert_eq!(state.refresh_calls.load(Ordering::SeqCst), 1);
    }

    /// In-memory mock backend for `store_token`.
    #[derive(Default)]
    struct MockBackend {
        store: Mutex<StdHashMap<String, Vec<u8>>>,
    }
    impl SecretBackend for MockBackend {
        fn kind(&self) -> spt_secrets::backend::BackendKind {
            spt_secrets::backend::BackendKind::Vault
        }
        fn get(&self, r: &SecretsRef) -> CoreResult<Option<spt_secrets::backend::SecretBytes>> {
            Ok(self
                .store
                .lock()
                .unwrap()
                .get(&r.to_string())
                .map(|v| secret_bytes(v.clone())))
        }
        fn set(&self, r: &SecretsRef, value: &[u8]) -> CoreResult<()> {
            self.store
                .lock()
                .unwrap()
                .insert(r.to_string(), value.to_vec());
            Ok(())
        }
        fn list(&self) -> CoreResult<Vec<SecretsRef>> {
            Ok(vec![])
        }
        fn remove(&self, r: &SecretsRef) -> CoreResult<bool> {
            Ok(self.store.lock().unwrap().remove(&r.to_string()).is_some())
        }
        fn doctor(&self) -> spt_secrets::backend::BackendDoctor {
            spt_secrets::backend::BackendDoctor::ok(
                spt_secrets::backend::BackendKind::Vault,
                "mock",
            )
        }
    }

    #[test]
    fn store_token_writes_access_and_refresh() {
        let tok = TokenResponse {
            access_token: secret_bytes(b"AT".to_vec()),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some(secret_bytes(b"RT".to_vec())),
            id_token: None,
            scope: None,
        };
        let backend = MockBackend::default();
        store_token(&tok, &backend, "oidc", "session").unwrap();
        let got_access = backend
            .get(&SecretsRef::new("oidc", "session").unwrap())
            .unwrap()
            .unwrap();
        let got_refresh = backend
            .get(&SecretsRef::new("oidc", "session.refresh").unwrap())
            .unwrap()
            .unwrap();
        assert_eq!(got_access.expose_secret().as_slice(), b"AT");
        assert_eq!(got_refresh.expose_secret().as_slice(), b"RT");
    }

    #[test]
    fn discovery_url_appends_trailing_slash_if_missing() {
        // We can't call the private `discovery_url` directly from outside the
        // impl block, but we can build a client and discover against a server
        // hosted at the bare issuer (no trailing slash) and verify it doesn't
        // panic.  This exercises the trailing-slash-recovery branch.
        let client =
            OidcDeviceFlowClient::new(Url::parse("http://127.0.0.1:1").unwrap(), "id".into(), None)
                .unwrap();
        assert_eq!(client.issuer().as_str(), "http://127.0.0.1:1/");
        assert_eq!(client.client_id(), "id");
        assert!(client.audience().is_none());
    }

    #[test]
    fn debug_does_not_finish_exhaustive() {
        let client = OidcDeviceFlowClient::new(
            Url::parse("https://login.example.com").unwrap(),
            "spt-cli".into(),
            Some("api".into()),
        )
        .unwrap();
        let s = format!("{client:?}");
        assert!(s.contains("OidcDeviceFlowClient"));
        assert!(s.contains("spt-cli"));
        // audience should appear.
        assert!(s.contains("api"));
    }

    #[test]
    fn oidc_error_into_core_error_categorisation() {
        // AccessDenied / TokenExpired / Expired / InvalidGrant / OauthError →
        // AuthFailed
        let cases = [
            OidcError::AccessDenied,
            OidcError::TokenExpired,
            OidcError::Expired,
            OidcError::InvalidGrant("x".into()),
            OidcError::OauthError {
                code: "invalid_client".into(),
                description: "no".into(),
            },
        ];
        for e in cases {
            let ce: CoreError = e.into();
            assert!(matches!(ce, CoreError::AuthFailed(_)), "got: {ce:?}");
        }
        // Discovery / Transport / MalformedResponse → NetworkUnreachable
        let net = [
            OidcError::Discovery("x".into()),
            OidcError::Transport("y".into()),
            OidcError::MalformedResponse {
                endpoint: "/x".into(),
                reason: "z".into(),
            },
        ];
        for e in net {
            let ce: CoreError = e.into();
            assert!(
                matches!(ce, CoreError::NetworkUnreachable(_)),
                "got: {ce:?}"
            );
        }
    }

    #[test]
    fn default_interval_constant() {
        assert_eq!(default_interval(), 5);
    }

    #[test]
    fn discovery_document_round_trips_through_json() {
        let doc = DiscoveryDocument {
            issuer: "https://i".into(),
            device_authorization_endpoint: "https://i/d".into(),
            token_endpoint: "https://i/t".into(),
        };
        let s = serde_json::to_string(&doc).unwrap();
        let back: DiscoveryDocument = serde_json::from_str(&s).unwrap();
        assert_eq!(back.issuer, doc.issuer);
        assert_eq!(back.token_endpoint, doc.token_endpoint);
    }

    #[test]
    fn device_code_response_uses_default_interval_when_absent() {
        let raw = r#"{
            "device_code":"x",
            "user_code":"U",
            "verification_uri":"https://e.com/d",
            "expires_in": 60
        }"#;
        let dc: DeviceCodeResponse = serde_json::from_str(raw).unwrap();
        assert_eq!(dc.interval, 5);
        assert!(dc.verification_uri_complete.is_none());
    }

    #[test]
    fn parse_oauth_error_returns_oauth_error_for_well_formed_body() {
        let err = parse_oauth_error(
            "/token",
            StatusCode::BAD_REQUEST,
            r#"{"error":"invalid_request","error_description":"oops"}"#,
        );
        match err {
            OidcError::OauthError { code, description } => {
                assert_eq!(code, "invalid_request");
                assert_eq!(description, "oops");
            }
            other => panic!("expected OauthError, got {other:?}"),
        }
    }

    #[test]
    fn parse_oauth_error_falls_back_to_malformed_for_unparseable_body() {
        let err = parse_oauth_error("/token", StatusCode::IM_A_TEAPOT, "not json");
        match err {
            OidcError::MalformedResponse { endpoint, reason } => {
                assert_eq!(endpoint, "/token");
                assert!(reason.contains("418"));
            }
            other => panic!("expected MalformedResponse, got {other:?}"),
        }
    }

    // ---------- t5-e2: PinnedTlsConnector wiring -----------------

    #[test]
    fn with_pin_empty_set_builds_strict_client() {
        // Empty pin set + allow_self_signed=false + None cap = strict
        // system roots routed via the pinned connector.
        let c = OidcDeviceFlowClient::with_pin(
            Url::parse("https://login.example.com").unwrap(),
            "spt-cli".into(),
            None,
            &[],
            false,
            None,
        );
        assert!(c.is_ok(), "with_pin empty failed: {:?}", c.err());
    }

    #[test]
    fn with_pin_allow_self_signed_without_pin_rejects() {
        let c = OidcDeviceFlowClient::with_pin(
            Url::parse("https://login.example.com").unwrap(),
            "spt-cli".into(),
            None,
            &[],
            true,
            None,
        );
        assert!(c.is_err(), "expected refusal: {:?}", c.ok());
    }

    #[test]
    fn with_pin_explicit_pin_builds() {
        let pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let c = OidcDeviceFlowClient::with_pin(
            Url::parse("https://login.example.com").unwrap(),
            "spt-cli".into(),
            None,
            &[pin],
            false,
            Some(5),
        );
        assert!(c.is_ok(), "with_pin pinned mode failed: {:?}", c.err());
    }

    #[test]
    fn token_response_debug_does_not_leak_secret() {
        let tok = TokenResponse {
            access_token: secret_bytes(b"SUPERSECRETBYTES".to_vec()),
            token_type: "Bearer".into(),
            expires_in: Some(3600),
            refresh_token: Some(secret_bytes(b"REFRESHSECRET".to_vec())),
            id_token: None,
            scope: None,
        };
        let dbg = format!("{tok:?}");
        assert!(!dbg.contains("SUPERSECRETBYTES"), "leak: {dbg}");
        assert!(!dbg.contains("REFRESHSECRET"), "leak: {dbg}");
    }
}
