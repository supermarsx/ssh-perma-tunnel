//! Authentication middleware: none / bearer / basic / mTLS.
//!
//! The compiled [`AuthContext`] is resolved once at server start (so bearer
//! tokens and basic-auth passwords are fetched from
//! [`spt_secrets::Resolver`] up-front and held as constant-time-comparable
//! bytes). Per-request the middleware walks the active mode and either
//! injects an [`AuthSubject`] extension or returns
//! [`crate::error::StatusApiError::Unauthorized`] /
//! [`StatusApiError::Forbidden`](crate::error::StatusApiError::Forbidden).
//!
//! ## mTLS subject extraction
//!
//! mTLS verification of the client certificate is performed inside the TLS
//! handshake layer ([`crate::tls`]); the verified subject DN is threaded
//! into the request as a [`PeerIdentity`] extension. The auth middleware
//! then matches that DN against `allowed_subjects`. When the server runs
//! over plain HTTP (or TLS without a client cert), there is no
//! `PeerIdentity` extension and the request is rejected with `403`.

use std::sync::Arc;

use axum::extract::Request;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use spt_config::{StatusApiAuthConfig, StatusApiAuthMode};
use spt_secrets::Resolver;
use subtle::ConstantTimeEq;

use crate::error::StatusApiError;

/// Per-request "who is calling" extension inserted by the auth middleware.
///
/// Currently informational only — handlers do not consume it, but the
/// tracing layer can include the identity in span fields.
#[derive(Debug, Clone)]
pub struct AuthSubject {
    /// Free-form identity string: `"anonymous"`, `"bearer"`, the basic-auth
    /// username, or the verified mTLS subject DN.
    pub label: String,
}

/// Verified mTLS peer identity, inserted by the TLS handshake layer.
///
/// The string is the RFC-4514 distinguished-name form of the verified
/// client certificate subject.
#[derive(Debug, Clone)]
pub struct PeerIdentity {
    /// RFC-4514 DN string, e.g. `"CN=prom.internal,O=Example,C=US"`.
    pub subject_dn: String,
}

/// Resolved authentication parameters held by the running server.
///
/// Build with [`AuthContext::from_config`]; clones are cheap (internal
/// `Arc` for the byte-vector secrets).
#[derive(Clone)]
pub struct AuthContext {
    mode: AuthMode,
}

#[derive(Clone)]
enum AuthMode {
    None,
    Bearer {
        token: Arc<Vec<u8>>,
    },
    Basic {
        user: String,
        password: Arc<Vec<u8>>,
    },
    MutualTls {
        allowed_subjects: Arc<Vec<String>>,
    },
}

impl AuthContext {
    /// Resolve the config-described mode into a runtime context.
    ///
    /// For bearer/basic modes this calls into the secret resolver — failure
    /// to resolve is fatal at server start (the operator misconfigured a
    /// `secret://` reference).
    pub fn from_config(
        cfg: &StatusApiAuthConfig,
        resolver: &Resolver,
    ) -> Result<Self, spt_core::Error> {
        let mode = match &cfg.mode {
            StatusApiAuthMode::None => AuthMode::None,
            StatusApiAuthMode::Bearer { token_from } => {
                let bytes = resolver.resolve(token_from)?;
                AuthMode::Bearer {
                    token: Arc::new(extract_bytes(&bytes)),
                }
            }
            StatusApiAuthMode::Basic {
                user,
                password_from,
            } => {
                let bytes = resolver.resolve(password_from)?;
                AuthMode::Basic {
                    user: user.clone(),
                    password: Arc::new(extract_bytes(&bytes)),
                }
            }
            StatusApiAuthMode::MutualTls {
                allowed_subjects, ..
            } => AuthMode::MutualTls {
                allowed_subjects: Arc::new(allowed_subjects.clone()),
            },
        };
        Ok(Self { mode })
    }

    /// Test-only constructor producing a no-auth context.
    #[doc(hidden)]
    #[must_use]
    pub fn none() -> Self {
        Self {
            mode: AuthMode::None,
        }
    }

    /// Test-only constructor producing a bearer-token context.
    #[doc(hidden)]
    #[must_use]
    pub fn bearer(token: impl Into<Vec<u8>>) -> Self {
        Self {
            mode: AuthMode::Bearer {
                token: Arc::new(token.into()),
            },
        }
    }

    /// Test-only constructor producing a basic-auth context.
    #[doc(hidden)]
    #[must_use]
    pub fn basic(user: impl Into<String>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            mode: AuthMode::Basic {
                user: user.into(),
                password: Arc::new(password.into()),
            },
        }
    }

    /// Test-only constructor producing an mTLS context.
    #[doc(hidden)]
    #[must_use]
    pub fn mtls(allowed: Vec<String>) -> Self {
        Self {
            mode: AuthMode::MutualTls {
                allowed_subjects: Arc::new(allowed),
            },
        }
    }

    /// Verify a request against this context.
    ///
    /// Returns the [`AuthSubject`] on success, or the appropriate error
    /// variant. Pure function (no I/O) — safe to call from middleware.
    ///
    /// `peer` is the optional mTLS-verified identity injected by the TLS
    /// handshake layer; `None` when no client cert was presented.
    pub fn verify<'h>(
        &self,
        authorization: Option<&'h str>,
        peer: Option<&'h PeerIdentity>,
    ) -> Result<AuthSubject, StatusApiError> {
        match &self.mode {
            AuthMode::None => Ok(AuthSubject {
                label: "anonymous".into(),
            }),
            AuthMode::Bearer { token } => {
                let header = authorization.ok_or(StatusApiError::Unauthorized)?;
                let presented = header
                    .strip_prefix("Bearer ")
                    .ok_or(StatusApiError::Unauthorized)?;
                if ct_eq(presented.as_bytes(), token) {
                    Ok(AuthSubject {
                        label: "bearer".into(),
                    })
                } else {
                    Err(StatusApiError::Unauthorized)
                }
            }
            AuthMode::Basic { user, password } => {
                let header = authorization.ok_or(StatusApiError::Unauthorized)?;
                let encoded = header
                    .strip_prefix("Basic ")
                    .ok_or(StatusApiError::Unauthorized)?;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(|_| StatusApiError::Unauthorized)?;
                let s = std::str::from_utf8(&decoded).map_err(|_| StatusApiError::Unauthorized)?;
                let (u, p) = s.split_once(':').ok_or(StatusApiError::Unauthorized)?;
                let user_ok = ct_eq(u.as_bytes(), user.as_bytes());
                let pw_ok = ct_eq(p.as_bytes(), password);
                if user_ok && pw_ok {
                    Ok(AuthSubject {
                        label: format!("basic:{u}"),
                    })
                } else {
                    Err(StatusApiError::Unauthorized)
                }
            }
            AuthMode::MutualTls { allowed_subjects } => {
                let id = peer.ok_or(StatusApiError::Forbidden)?;
                if allowed_subjects.iter().any(|s| s.as_str() == id.subject_dn) {
                    Ok(AuthSubject {
                        label: id.subject_dn.clone(),
                    })
                } else {
                    Err(StatusApiError::Forbidden)
                }
            }
        }
    }
}

/// Axum middleware: invoke [`AuthContext::verify`] and inject the
/// [`AuthSubject`] extension on success.
///
/// The `Authorization` header value is **redacted** from the request before
/// it reaches downstream tracing layers — see [`crate::redact`].
pub async fn middleware(
    axum::extract::State(ctx): axum::extract::State<Arc<AuthContext>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusApiError> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(std::string::ToString::to_string);
    let peer = request.extensions().get::<PeerIdentity>().cloned();
    let subject = ctx.verify(auth_header.as_deref(), peer.as_ref())?;
    request.extensions_mut().insert(subject);
    Ok(next.run(request).await)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Still do a constant-time pass over min(a,b) to discourage early
        // length-leaking, but the truthiness is dictated by length.
        let _ = a
            .iter()
            .zip(b.iter())
            .fold(0u8, |acc, (x, y)| acc | (*x ^ *y));
        return false;
    }
    a.ct_eq(b).into()
}

fn extract_bytes(secret: &spt_secrets::SecretBytes) -> Vec<u8> {
    use secrecy::ExposeSecret;
    secret.expose_secret().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_mode_accepts_anything() {
        let ctx = AuthContext::none();
        let r = ctx.verify(None, None).unwrap();
        assert_eq!(r.label, "anonymous");
    }

    #[test]
    fn bearer_missing_header_unauthorized() {
        let ctx = AuthContext::bearer("hunter2");
        assert!(matches!(
            ctx.verify(None, None),
            Err(StatusApiError::Unauthorized)
        ));
    }

    #[test]
    fn bearer_invalid_token_unauthorized() {
        let ctx = AuthContext::bearer("hunter2");
        assert!(matches!(
            ctx.verify(Some("Bearer wrong"), None),
            Err(StatusApiError::Unauthorized)
        ));
    }

    #[test]
    fn bearer_valid_token_ok() {
        let ctx = AuthContext::bearer("hunter2");
        assert!(ctx.verify(Some("Bearer hunter2"), None).is_ok());
    }

    #[test]
    fn basic_valid_creds_ok() {
        let ctx = AuthContext::basic("monitoring", "s3cret");
        let encoded = base64::engine::general_purpose::STANDARD.encode("monitoring:s3cret");
        let header = format!("Basic {encoded}");
        let r = ctx.verify(Some(&header), None).unwrap();
        assert_eq!(r.label, "basic:monitoring");
    }

    #[test]
    fn basic_missing_unauthorized() {
        let ctx = AuthContext::basic("u", "p");
        assert!(matches!(
            ctx.verify(None, None),
            Err(StatusApiError::Unauthorized)
        ));
    }

    #[test]
    fn basic_wrong_password_unauthorized() {
        let ctx = AuthContext::basic("u", "p");
        let encoded = base64::engine::general_purpose::STANDARD.encode("u:wrong");
        let header = format!("Basic {encoded}");
        assert!(matches!(
            ctx.verify(Some(&header), None),
            Err(StatusApiError::Unauthorized)
        ));
    }

    #[test]
    fn basic_malformed_b64_unauthorized() {
        let ctx = AuthContext::basic("u", "p");
        assert!(matches!(
            ctx.verify(Some("Basic !!!!"), None),
            Err(StatusApiError::Unauthorized)
        ));
    }

    #[test]
    fn mtls_no_peer_forbidden() {
        let ctx = AuthContext::mtls(vec!["CN=prom".into()]);
        assert!(matches!(
            ctx.verify(None, None),
            Err(StatusApiError::Forbidden)
        ));
    }

    #[test]
    fn mtls_unknown_subject_forbidden() {
        let ctx = AuthContext::mtls(vec!["CN=prom".into()]);
        let peer = PeerIdentity {
            subject_dn: "CN=other".into(),
        };
        assert!(matches!(
            ctx.verify(None, Some(&peer)),
            Err(StatusApiError::Forbidden)
        ));
    }

    #[test]
    fn mtls_allowed_subject_ok() {
        let ctx = AuthContext::mtls(vec!["CN=prom".into(), "CN=grafana".into()]);
        let peer = PeerIdentity {
            subject_dn: "CN=grafana".into(),
        };
        let r = ctx.verify(None, Some(&peer)).unwrap();
        assert_eq!(r.label, "CN=grafana");
    }
}
