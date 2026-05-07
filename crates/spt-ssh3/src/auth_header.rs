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
use spt_key::io as key_io;

use crate::jwt::{build_jwt, fresh_claims, DEFAULT_JWT_LIFETIME_SECS};

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
/// Preference order:
///
/// 1. `Bearer` — the explicit token entry (also receives OIDC-deposited
///    access tokens from the device-flow preflight).
/// 2. `Basic` — HTTP Basic auth.
/// 3. `PublicKey` — SSH3 pubkey-style JWT bearer (Ed25519 / ECDSA P-256/P-384).
///
/// `OidcDeviceFlow` is handled out-of-band — by the time `connect()` runs,
/// callers must have already converted the OIDC result into a
/// `Bearer { token }` entry.
///
/// `host`, `port`, and `url_path` are required by the JWT branch only; they
/// are folded into the `aud` claim and must match exactly what the CONNECT
/// request later carries on the wire (see [`crate::jwt::canonical_audience`]).
/// Bearer/Basic ignore them, so `auth_header_simple` is provided for the
/// shorter call sites (and used by the existing tests).
pub fn build_authorization_header_for(
    auth: &AuthConfig,
    host: &str,
    port: u16,
    url_path: &str,
) -> Result<String> {
    // 1. Bearer
    for m in &auth.methods {
        if let AuthMethod::Bearer { token } = m {
            let v = resolve_secret(token)?;
            return Ok(format!("Bearer {v}"));
        }
    }
    // 2. Basic
    for m in &auth.methods {
        if let AuthMethod::Basic { username, password } = m {
            let pwd = resolve_secret(password)?;
            let raw = format!("{username}:{pwd}");
            return Ok(format!("Basic {}", B64.encode(raw.as_bytes())));
        }
    }
    // 3. PublicKey → SSH3 pubkey JWT.
    for m in &auth.methods {
        if let AuthMethod::PublicKey {
            identity_file,
            passphrase,
        } = m
        {
            let pass = passphrase.as_ref().map(resolve_secret).transpose()?;
            let kp = key_io::load(identity_file, pass.as_deref())?;
            let claims = fresh_claims(
                &kp,
                &auth.username,
                host,
                port,
                url_path,
                DEFAULT_JWT_LIFETIME_SECS,
            );
            let jwt = build_jwt(&kp, &claims)?;
            return Ok(format!("Bearer {jwt}"));
        }
    }
    Err(Error::AuthFailed(
        "ssh3 requires `Bearer`, `Basic`, or `PublicKey` auth method (got none in profile)"
            .to_string(),
    ))
}

/// Convenience wrapper for callers that don't need the JWT path (Bearer/Basic
/// only). Equivalent to [`build_authorization_header_for`] with placeholder
/// audience parameters; will return an error if the profile only has a
/// `PublicKey` method.
pub fn build_authorization_header(auth: &AuthConfig) -> Result<String> {
    // Use empty placeholders — only Bearer/Basic look at these. If the only
    // method is PublicKey we'll happily build a JWT with audience
    // `https://:0/` and the server will reject it; that's the caller's bug
    // for using this entry point on a pubkey profile.
    build_authorization_header_for(auth, "", 0, "/")
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
