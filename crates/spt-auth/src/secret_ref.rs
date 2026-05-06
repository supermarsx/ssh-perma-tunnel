//! [`SecretRef`] — the *reference* (not the secret) used by every secret-bearing field.
//!
//! Accepted forms (spec §15):
//!
//! | Form                  | Resolution location                  |
//! |-----------------------|--------------------------------------|
//! | `secret://ns/name`    | OS keychain → vault → env → file     |
//! | `env:NAME`            | Environment variable `NAME`          |
//! | `file:///path/to/foo` | File contents (mode-checked by spt-secrets) |
//!
//! This type only checks *shape*. It does **not** read environment, files,
//! or the keychain — that is `spt-secrets`' job.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A typed reference to a secret value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub enum SecretRef {
    /// `secret://<namespace>/<name>` — primary form, resolved through the
    /// keychain/vault/env/file chain in `spt-secrets`.
    Vault {
        /// Namespace.
        namespace: String,
        /// Name within the namespace.
        name: String,
    },
    /// `env:NAME` — read from environment variable `NAME`.
    Env(String),
    /// `file:///absolute/path` — secret value lives in a file with mode checks.
    File(String),
}

/// Errors raised when [`SecretRef::parse`] rejects a string.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SecretRefError {
    /// The input did not begin with one of the supported scheme prefixes.
    #[error(
        "secret reference must start with `secret://`, `env:`, or `file:///`; got `{0}`"
    )]
    UnknownScheme(String),
    /// `secret://` form did not have a `/` separating namespace from name.
    #[error("secret://<ns>/<name>: missing `/` between namespace and name in `{0}`")]
    MissingNameSeparator(String),
    /// Namespace or name component was empty.
    #[error("secret reference has empty {field} in `{input}`")]
    Empty {
        /// Which component was empty.
        field: &'static str,
        /// Offending input.
        input: String,
    },
    /// `env:` form had an empty variable name.
    #[error("env: reference has empty variable name in `{0}`")]
    EmptyEnvName(String),
    /// `file://` form was malformed (missing the `//` or path).
    #[error("file:// reference is malformed: `{0}`")]
    BadFileUri(String),
}

impl SecretRef {
    /// Parse a secret reference string per the table above.
    pub fn parse(s: &str) -> Result<Self, SecretRefError> {
        let s = s.trim();
        if let Some(rest) = s.strip_prefix("secret://") {
            let (ns, name) = rest
                .split_once('/')
                .ok_or_else(|| SecretRefError::MissingNameSeparator(s.to_owned()))?;
            if ns.is_empty() {
                return Err(SecretRefError::Empty {
                    field: "namespace",
                    input: s.to_owned(),
                });
            }
            if name.is_empty() {
                return Err(SecretRefError::Empty {
                    field: "name",
                    input: s.to_owned(),
                });
            }
            return Ok(Self::Vault {
                namespace: ns.to_owned(),
                name: name.to_owned(),
            });
        }
        if let Some(name) = s.strip_prefix("env:") {
            if name.is_empty() {
                return Err(SecretRefError::EmptyEnvName(s.to_owned()));
            }
            return Ok(Self::Env(name.to_owned()));
        }
        if let Some(rest) = s.strip_prefix("file://") {
            // Accept either `file://` (host-relative) or `file:///abs`.
            let path = rest.strip_prefix('/').unwrap_or(rest);
            if path.is_empty() {
                return Err(SecretRefError::BadFileUri(s.to_owned()));
            }
            // Re-prepend a single leading slash on Unix-like inputs while leaving
            // Windows-style `C:/...` untouched.
            let normalized = if path.chars().nth(1) == Some(':') {
                path.to_owned()
            } else {
                format!("/{path}")
            };
            return Ok(Self::File(normalized));
        }
        Err(SecretRefError::UnknownScheme(s.to_owned()))
    }
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault { namespace, name } => write!(f, "secret://{namespace}/{name}"),
            Self::Env(n) => write!(f, "env:{n}"),
            Self::File(p) => {
                if p.starts_with('/') {
                    write!(f, "file://{p}")
                } else {
                    write!(f, "file:///{p}")
                }
            }
        }
    }
}

impl From<SecretRef> for String {
    fn from(value: SecretRef) -> Self {
        value.to_string()
    }
}

impl TryFrom<String> for SecretRef {
    type Error = SecretRefError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl std::str::FromStr for SecretRef {
    type Err = SecretRefError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_form() {
        let r = SecretRef::parse("secret://ssh/profile/passphrase").unwrap();
        match r {
            SecretRef::Vault { namespace, name } => {
                assert_eq!(namespace, "ssh");
                assert_eq!(name, "profile/passphrase");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn env_form() {
        assert_eq!(
            SecretRef::parse("env:SPT_TOKEN").unwrap(),
            SecretRef::Env("SPT_TOKEN".into())
        );
    }

    #[test]
    fn file_form_unix() {
        assert_eq!(
            SecretRef::parse("file:///etc/spt/passphrase").unwrap(),
            SecretRef::File("/etc/spt/passphrase".into())
        );
    }

    #[test]
    fn file_form_windows() {
        let r = SecretRef::parse("file://C:/Secrets/x.txt").unwrap();
        assert_eq!(r, SecretRef::File("C:/Secrets/x.txt".into()));
    }

    #[test]
    fn rejects_unknown_scheme() {
        assert!(matches!(
            SecretRef::parse("plain-text"),
            Err(SecretRefError::UnknownScheme(_))
        ));
    }

    #[test]
    fn rejects_empty_components() {
        assert!(matches!(
            SecretRef::parse("secret:///name"),
            Err(SecretRefError::Empty { field: "namespace", .. })
        ));
        assert!(matches!(
            SecretRef::parse("secret://ns/"),
            Err(SecretRefError::Empty { field: "name", .. })
        ));
        assert!(matches!(
            SecretRef::parse("env:"),
            Err(SecretRefError::EmptyEnvName(_))
        ));
    }

    #[test]
    fn missing_separator() {
        assert!(matches!(
            SecretRef::parse("secret://justaname"),
            Err(SecretRefError::MissingNameSeparator(_))
        ));
    }

    #[test]
    fn roundtrip_display() {
        for s in [
            "secret://ns/name",
            "env:FOO",
            "file:///abs/path",
        ] {
            let r = SecretRef::parse(s).unwrap();
            assert_eq!(r.to_string(), s);
        }
    }
}
