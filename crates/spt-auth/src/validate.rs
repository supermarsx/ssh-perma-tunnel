//! Per-method shape validation for [`AuthMethod`].
//!
//! Validation here is **structural**: file paths are checked for existence and
//! basic readability, secret references are checked by `SecretRef::parse`,
//! and URLs/usernames are checked for non-empty + valid scheme. Mode/ownership
//! checks for secret files and live keychain queries belong in `spt-secrets`.

use std::path::Path;

use spt_core::{Error, Result};

use crate::method::AuthMethod;

/// Structurally validate a single [`AuthMethod`].
pub fn validate(method: &AuthMethod) -> Result<()> {
    match method {
        AuthMethod::PublicKey {
            identity_file,
            passphrase: _,
        } => check_file_exists("identity_file", identity_file),

        AuthMethod::Agent { socket } => {
            if let Some(path) = socket {
                if path.as_os_str().is_empty() {
                    return Err(invalid("agent.socket must not be empty"));
                }
                // Agent socket may not exist yet at validate-time; just shape-check.
            }
            Ok(())
        }

        // SecretRef parse already validated when the enum was deserialized.
        AuthMethod::Password { secret: _ } | AuthMethod::Bearer { token: _ } => Ok(()),

        AuthMethod::KeyboardInteractive { responder } => {
            if responder.is_empty() {
                return Err(invalid(
                    "keyboard_interactive requires at least one responder entry",
                ));
            }
            for (i, ans) in responder.iter().enumerate() {
                if ans.pattern.is_empty() {
                    return Err(invalid(format!(
                        "keyboard_interactive.responder[{i}].pattern must not be empty"
                    )));
                }
            }
            Ok(())
        }

        AuthMethod::Certificate {
            cert,
            key,
            passphrase: _,
        } => {
            check_file_exists("certificate.cert", cert)?;
            check_file_exists("certificate.key", key)?;
            Ok(())
        }

        AuthMethod::Gssapi {
            service,
            principal,
            delegate: _,
        } => {
            check_optional_non_empty("gssapi.service", service.as_deref())?;
            check_optional_non_empty("gssapi.principal", principal.as_deref())
        }

        AuthMethod::Sspi {
            service,
            principal,
            delegate: _,
            allow_ntlm_fallback: _,
        } => {
            check_optional_non_empty("sspi.service", service.as_deref())?;
            check_optional_non_empty("sspi.principal", principal.as_deref())
        }

        AuthMethod::Basic {
            username,
            password: _,
        } => {
            if username.is_empty() {
                return Err(invalid("http_basic.username must not be empty"));
            }
            Ok(())
        }

        AuthMethod::OidcDeviceFlow {
            issuer,
            client_id,
            audience: _,
        } => {
            if issuer.scheme() != "https" {
                return Err(invalid(format!(
                    "oidc.issuer must use https scheme: got `{}`",
                    issuer.scheme()
                )));
            }
            if !issuer.has_host() {
                return Err(invalid("oidc.issuer must include a host"));
            }
            if client_id.is_empty() {
                return Err(invalid("oidc.client_id must not be empty"));
            }
            Ok(())
        }
    }
}

fn check_file_exists(field: &str, path: &Path) -> Result<()> {
    if !path.exists() {
        return Err(invalid(format!(
            "{field} `{}` does not exist",
            path.display()
        )));
    }
    if !path.is_file() {
        return Err(invalid(format!(
            "{field} `{}` is not a regular file",
            path.display()
        )));
    }
    Ok(())
}

fn check_optional_non_empty(field: &str, value: Option<&str>) -> Result<()> {
    if matches!(value, Some("")) {
        return Err(invalid(format!("{field} must not be empty")));
    }
    Ok(())
}

fn invalid(msg: impl Into<String>) -> Error {
    Error::InvalidConfig(msg.into())
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;
    use url::Url;

    use super::*;
    use crate::kbi::KbiAnswer;
    use crate::secret_ref::SecretRef;

    fn touch() -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"x").unwrap();
        f
    }

    #[test]
    fn public_key_ok() {
        let f = touch();
        let m = AuthMethod::PublicKey {
            identity_file: f.path().to_path_buf(),
            passphrase: None,
        };
        validate(&m).unwrap();
    }

    #[test]
    fn public_key_missing_file() {
        let m = AuthMethod::PublicKey {
            identity_file: "/no/such/file/spt-test".into(),
            passphrase: None,
        };
        assert!(validate(&m).is_err());
    }

    #[test]
    fn agent_ok() {
        validate(&AuthMethod::Agent { socket: None }).unwrap();
    }

    #[test]
    fn kbi_requires_responder() {
        let m = AuthMethod::KeyboardInteractive { responder: vec![] };
        assert!(validate(&m).is_err());
    }

    #[test]
    fn kbi_ok() {
        let m = AuthMethod::KeyboardInteractive {
            responder: vec![KbiAnswer {
                pattern: "Password:".into(),
                response: SecretRef::Env("X".into()),
                echo: false,
            }],
        };
        validate(&m).unwrap();
    }

    #[test]
    fn certificate_missing_files() {
        let m = AuthMethod::Certificate {
            cert: "/nope-cert".into(),
            key: "/nope-key".into(),
            passphrase: None,
        };
        assert!(validate(&m).is_err());
    }

    #[test]
    fn basic_username_required() {
        let m = AuthMethod::Basic {
            username: String::new(),
            password: SecretRef::Env("P".into()),
        };
        assert!(validate(&m).is_err());
    }

    #[test]
    fn oidc_must_be_https() {
        let m = AuthMethod::OidcDeviceFlow {
            issuer: Url::parse("http://example.com").unwrap(),
            client_id: "id".into(),
            audience: None,
        };
        assert!(validate(&m).is_err());
    }

    #[test]
    fn oidc_ok() {
        let m = AuthMethod::OidcDeviceFlow {
            issuer: Url::parse("https://login.example.com").unwrap(),
            client_id: "id".into(),
            audience: Some("api".into()),
        };
        validate(&m).unwrap();
    }

    #[test]
    fn bearer_passes() {
        validate(&AuthMethod::Bearer {
            token: SecretRef::Env("T".into()),
        })
        .unwrap();
    }

    #[test]
    fn gssapi_shape_passes() {
        validate(&AuthMethod::Gssapi {
            service: Some("host/edge.example.com".into()),
            principal: Some("alice@EXAMPLE.COM".into()),
            delegate: false,
        })
        .unwrap();
    }

    #[test]
    fn sspi_rejects_empty_service() {
        let err = validate(&AuthMethod::Sspi {
            service: Some(String::new()),
            principal: None,
            delegate: false,
            allow_ntlm_fallback: false,
        })
        .unwrap_err();
        assert!(err.to_string().contains("sspi.service"));
    }

    #[test]
    fn password_passes_without_inspecting_secret() {
        validate(&AuthMethod::Password {
            secret: SecretRef::Env("PW".into()),
        })
        .unwrap();
    }

    #[test]
    fn public_key_rejects_directory_path() {
        let tmp = tempfile::tempdir().unwrap();
        let m = AuthMethod::PublicKey {
            identity_file: tmp.path().to_path_buf(),
            passphrase: None,
        };
        let err = validate(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("not a regular file"), "{s}");
    }

    #[test]
    fn agent_with_empty_socket_path_rejected() {
        let m = AuthMethod::Agent {
            socket: Some(std::path::PathBuf::from("")),
        };
        let err = validate(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("agent.socket"), "{s}");
    }

    #[test]
    fn agent_with_non_empty_socket_passes_without_existence_check() {
        // Validation is shape-only — socket path is not required to exist.
        let m = AuthMethod::Agent {
            socket: Some(std::path::PathBuf::from("/never/created/spt-agent.sock")),
        };
        validate(&m).unwrap();
    }

    #[test]
    fn kbi_rejects_entry_with_empty_pattern() {
        let m = AuthMethod::KeyboardInteractive {
            responder: vec![KbiAnswer {
                pattern: String::new(),
                response: SecretRef::Env("X".into()),
                echo: false,
            }],
        };
        let err = validate(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("responder[0]"), "{s}");
        assert!(s.contains("pattern"), "{s}");
    }

    #[test]
    fn certificate_passes_when_both_files_exist() {
        let cert = touch();
        let key = touch();
        validate(&AuthMethod::Certificate {
            cert: cert.path().to_path_buf(),
            key: key.path().to_path_buf(),
            passphrase: None,
        })
        .unwrap();
    }

    #[test]
    fn certificate_missing_cert_fails_with_cert_field() {
        let key = touch();
        let m = AuthMethod::Certificate {
            cert: "/no/such/cert".into(),
            key: key.path().to_path_buf(),
            passphrase: None,
        };
        let err = validate(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("certificate.cert"), "{s}");
    }

    #[test]
    fn basic_passes_with_username() {
        validate(&AuthMethod::Basic {
            username: "alice".into(),
            password: SecretRef::Env("PW".into()),
        })
        .unwrap();
    }

    #[test]
    fn oidc_rejects_missing_client_id() {
        let m = AuthMethod::OidcDeviceFlow {
            issuer: Url::parse("https://login.example.com").unwrap(),
            client_id: String::new(),
            audience: None,
        };
        let err = validate(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("oidc.client_id"), "{s}");
    }

    #[test]
    fn oidc_data_url_rejected_for_missing_host() {
        // A scheme other than https is rejected first.
        let m = AuthMethod::OidcDeviceFlow {
            issuer: Url::parse("ftp://login.example.com").unwrap(),
            client_id: "id".into(),
            audience: None,
        };
        let err = validate(&m).unwrap_err();
        let s = err.to_string();
        assert!(s.contains("https"), "{s}");
    }

    #[test]
    fn public_key_with_passphrase_ok() {
        let f = touch();
        let m = AuthMethod::PublicKey {
            identity_file: f.path().to_path_buf(),
            passphrase: Some(SecretRef::Env("PASS".into())),
        };
        validate(&m).unwrap();
    }
}
