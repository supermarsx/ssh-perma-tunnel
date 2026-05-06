//! HTTP `Authorization` header construction for the SSH3 Extended CONNECT
//! request.
//!
//! SSH3 uses HTTP-level authentication on the CONNECT that bootstraps the
//! session: `Authorization: Bearer <token>` (preferred) or `Basic <b64>`. The
//! OIDC device flow (`AuthMethod::OidcDeviceFlow`) is performed out-of-band by
//! `spt-bin` glue, which deposits the resulting access token into a `Bearer`
//! method's [`SecretRef`] before calling [`crate::Ssh3Protocol::connect`].

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_core::{Error, Result};

/// Resolve a [`SecretRef`] to its raw secret value.
///
/// Currently supports `env:NAME` and `file://` references natively.
/// `secret://` (vault) references require the spt-secrets resolver and are
/// rejected here with [`Error::InvalidConfig`] — operators should pre-resolve
/// vault refs at the spt-bin layer before invoking the SSH3 backend.
pub(crate) fn resolve_secret(s: &SecretRef) -> Result<String> {
    match s {
        SecretRef::Env(name) => std::env::var(name)
            .map_err(|_| Error::InvalidConfig(format!("env var `{name}` not set"))),
        SecretRef::File(path) => std::fs::read_to_string(path)
            .map(|s| s.trim_end_matches(['\r', '\n']).to_string())
            .map_err(|e| Error::InvalidConfig(format!("read {path}: {e}"))),
        SecretRef::Vault { .. } => Err(Error::InvalidConfig(
            "ssh3 backend cannot resolve `secret://` refs directly; \
             pre-resolve via spt-secrets and pass as env: or file://"
                .to_string(),
        )),
    }
}

/// Pick the first SSH3-applicable [`AuthMethod`] from `auth.methods` and
/// produce the corresponding `Authorization` header value.
///
/// Preference order: `Bearer` first, `Basic` second. `OidcDeviceFlow` is
/// handled out-of-band — by the time `connect()` runs, callers must have
/// already converted the OIDC result into a `Bearer { token }` entry.
pub fn build_authorization_header(auth: &AuthConfig) -> Result<String> {
    // Pick Bearer first.
    for m in &auth.methods {
        if let AuthMethod::Bearer { token } = m {
            let v = resolve_secret(token)?;
            return Ok(format!("Bearer {v}"));
        }
    }
    // Fall back to Basic.
    for m in &auth.methods {
        if let AuthMethod::Basic { username, password } = m {
            let pwd = resolve_secret(password)?;
            let raw = format!("{username}:{pwd}");
            return Ok(format!("Basic {}", B64.encode(raw.as_bytes())));
        }
    }
    Err(Error::AuthFailed(
        "ssh3 requires `Bearer` or `Basic` auth method (got none in profile)".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_from_env() {
        std::env::set_var("SPT_TEST_BEARER_1", "abc123");
        let cfg = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_TEST_BEARER_1").unwrap(),
            }],
        );
        let h = build_authorization_header(&cfg).unwrap();
        assert_eq!(h, "Bearer abc123");
        std::env::remove_var("SPT_TEST_BEARER_1");
    }

    #[test]
    fn basic_from_env() {
        std::env::set_var("SPT_TEST_BASIC_1", "s3cret");
        let cfg = AuthConfig::new(
            "u",
            vec![AuthMethod::Basic {
                username: "alice".into(),
                password: SecretRef::parse("env:SPT_TEST_BASIC_1").unwrap(),
            }],
        );
        let h = build_authorization_header(&cfg).unwrap();
        // base64("alice:s3cret") = "YWxpY2U6czNjcmV0"
        assert_eq!(h, "Basic YWxpY2U6czNjcmV0");
        std::env::remove_var("SPT_TEST_BASIC_1");
    }

    #[test]
    fn bearer_preferred_over_basic() {
        std::env::set_var("SPT_TEST_PREF_TOK", "tok");
        std::env::set_var("SPT_TEST_PREF_PWD", "pwd");
        let cfg = AuthConfig::new(
            "u",
            vec![
                AuthMethod::Basic {
                    username: "u".into(),
                    password: SecretRef::parse("env:SPT_TEST_PREF_PWD").unwrap(),
                },
                AuthMethod::Bearer {
                    token: SecretRef::parse("env:SPT_TEST_PREF_TOK").unwrap(),
                },
            ],
        );
        let h = build_authorization_header(&cfg).unwrap();
        assert!(h.starts_with("Bearer "));
        std::env::remove_var("SPT_TEST_PREF_TOK");
        std::env::remove_var("SPT_TEST_PREF_PWD");
    }

    #[test]
    fn no_method_errors() {
        let cfg = AuthConfig::new("u", vec![]);
        let err = build_authorization_header(&cfg).unwrap_err();
        assert!(matches!(err, Error::AuthFailed(_)));
    }

    #[test]
    fn vault_ref_rejected() {
        let cfg = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("secret://ns/name").unwrap(),
            }],
        );
        let err = build_authorization_header(&cfg).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}
