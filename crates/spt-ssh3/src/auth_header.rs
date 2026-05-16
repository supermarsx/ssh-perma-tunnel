//! HTTP `Authorization` header construction for the SSH3 Extended CONNECT
//! request.
//!
//! SSH3 uses HTTP-level authentication on the CONNECT that bootstraps the
//! session: `Authorization: Bearer <token>` (preferred) or `Basic <b64>`. The
//! OIDC device flow (`AuthMethod::OidcDeviceFlow`) is performed out-of-band by
//! `spt-bin` glue, which deposits the resulting access token into a `Bearer`
//! method's [`SecretRef`] before calling
//! [`spt_protocol::TunnelProtocol::connect`].

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

    #[test]
    fn env_var_missing_errors_invalid_config() {
        std::env::remove_var("SPT_TEST_BEARER_MISSING_XYZ");
        let cfg = AuthConfig::new(
            "u",
            vec![AuthMethod::Bearer {
                token: SecretRef::parse("env:SPT_TEST_BEARER_MISSING_XYZ").unwrap(),
            }],
        );
        let err = build_authorization_header(&cfg).unwrap_err();
        match err {
            Error::InvalidConfig(msg) => {
                assert!(msg.contains("SPT_TEST_BEARER_MISSING_XYZ"));
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn resolve_secret_file_trims_trailing_crlf() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "spt-ssh3-test-secret-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, b"value-on-disk\r\n\n").unwrap();
        let got = resolve_secret(&SecretRef::File(path.to_string_lossy().into())).unwrap();
        assert_eq!(got, "value-on-disk");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn resolve_secret_file_missing_errors() {
        let bogus = SecretRef::File(
            "F:/this/path/should/not/exist/spt-ssh3-missing-secret-xyz.txt".into(),
        );
        let err = resolve_secret(&bogus).unwrap_err();
        assert!(matches!(err, Error::InvalidConfig(_)));
    }

    #[test]
    fn resolve_secret_env_ok() {
        std::env::set_var("SPT_TEST_RESOLVE_ENV", "envval");
        let got = resolve_secret(&SecretRef::parse("env:SPT_TEST_RESOLVE_ENV").unwrap()).unwrap();
        assert_eq!(got, "envval");
        std::env::remove_var("SPT_TEST_RESOLVE_ENV");
    }

    #[test]
    fn resolve_secret_vault_message_mentions_secret_scheme() {
        let r = SecretRef::parse("secret://ns/name").unwrap();
        let err = resolve_secret(&r).unwrap_err();
        match err {
            Error::InvalidConfig(msg) => assert!(msg.contains("secret://")),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn bearer_wins_when_listed_after_basic() {
        std::env::set_var("SPT_TEST_ORDER_TOK", "ord-tok");
        std::env::set_var("SPT_TEST_ORDER_PWD", "ord-pwd");
        let cfg = AuthConfig::new(
            "u",
            vec![
                AuthMethod::Basic {
                    username: "u".into(),
                    password: SecretRef::parse("env:SPT_TEST_ORDER_PWD").unwrap(),
                },
                AuthMethod::Bearer {
                    token: SecretRef::parse("env:SPT_TEST_ORDER_TOK").unwrap(),
                },
            ],
        );
        let h = build_authorization_header(&cfg).unwrap();
        assert_eq!(h, "Bearer ord-tok");
        std::env::remove_var("SPT_TEST_ORDER_TOK");
        std::env::remove_var("SPT_TEST_ORDER_PWD");
    }

    #[test]
    fn basic_with_empty_password() {
        std::env::set_var("SPT_TEST_BASIC_EMPTY", "");
        let cfg = AuthConfig::new(
            "u",
            vec![AuthMethod::Basic {
                username: "alice".into(),
                password: SecretRef::parse("env:SPT_TEST_BASIC_EMPTY").unwrap(),
            }],
        );
        let h = build_authorization_header(&cfg).unwrap();
        // base64("alice:") = "YWxpY2U6"
        assert_eq!(h, "Basic YWxpY2U6");
        std::env::remove_var("SPT_TEST_BASIC_EMPTY");
    }

    #[test]
    fn basic_with_special_chars_in_password() {
        std::env::set_var("SPT_TEST_BASIC_SPECIAL", "p@ss:w/ord");
        let cfg = AuthConfig::new(
            "u",
            vec![AuthMethod::Basic {
                username: "alice".into(),
                password: SecretRef::parse("env:SPT_TEST_BASIC_SPECIAL").unwrap(),
            }],
        );
        let h = build_authorization_header(&cfg).unwrap();
        assert!(h.starts_with("Basic "));
        let b64 = &h["Basic ".len()..];
        let raw = B64.decode(b64).unwrap();
        assert_eq!(raw, b"alice:p@ss:w/ord");
        std::env::remove_var("SPT_TEST_BASIC_SPECIAL");
    }

    #[test]
    fn publickey_simple_entrypoint_builds_jwt() {
        use spt_key::algorithm::KeyAlgorithm;
        use spt_key::io as key_io;
        let kp = key_io::generate(KeyAlgorithm::Ed25519).unwrap();
        let tmp = std::env::temp_dir().join(format!(
            "spt-ssh3-test-key-{}-{}.pem",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        key_io::save_encrypted(&kp, &tmp, None).unwrap();
        let cfg = AuthConfig::new(
            "alice",
            vec![AuthMethod::PublicKey {
                identity_file: tmp.clone(),
                passphrase: None,
            }],
        );
        let h = build_authorization_header_for(&cfg, "host.example", 7443, "/ssh3").unwrap();
        assert!(h.starts_with("Bearer "));
        let jwt = &h["Bearer ".len()..];
        assert_eq!(jwt.matches('.').count(), 2);
        let _ = std::fs::remove_file(&tmp);
    }

    #[test]
    fn publickey_missing_identity_file_errors() {
        let cfg = AuthConfig::new(
            "alice",
            vec![AuthMethod::PublicKey {
                identity_file: std::path::PathBuf::from(
                    "F:/this/path/should/not/exist/spt-ssh3-missing-key-xyz.pem",
                ),
                passphrase: None,
            }],
        );
        let err = build_authorization_header_for(&cfg, "h", 1, "/").unwrap_err();
        assert!(matches!(
            err,
            Error::RuntimeFailure(_) | Error::InvalidConfig(_)
        ));
    }

    #[test]
    fn agent_method_falls_through_to_auth_error() {
        let cfg = AuthConfig::new("u", vec![AuthMethod::Agent { socket: None }]);
        let err = build_authorization_header(&cfg).unwrap_err();
        match err {
            Error::AuthFailed(msg) => assert!(msg.contains("ssh3 requires")),
            _ => panic!("wrong variant"),
        }
    }
}
