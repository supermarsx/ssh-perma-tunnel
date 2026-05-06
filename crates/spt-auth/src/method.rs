//! [`AuthMethod`] enum and [`AuthConfig`] container.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::Url;

use crate::kbi::KbiAnswer;
use crate::secret_ref::SecretRef;

/// One authentication method modeled by spec §9.12.
///
/// Methods are specified as a serde-tagged enum (`method = "public_key"`)
/// matching the TOML examples in the spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "snake_case")]
pub enum AuthMethod {
    /// SSH2 public-key auth — optional certificate, optional passphrase.
    PublicKey {
        /// Path to private key (OpenSSH PEM).
        identity_file: PathBuf,
        /// Optional passphrase reference for an encrypted key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<SecretRef>,
    },

    /// SSH2 agent auth — uses `SSH_AUTH_SOCK` (or Pageant on Windows) when
    /// `socket` is `None`.
    Agent {
        /// Optional explicit agent socket path.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        socket: Option<PathBuf>,
    },

    /// SSH2 password auth.
    Password {
        /// Reference to the password.
        secret: SecretRef,
    },

    /// SSH2 keyboard-interactive auth — typically password-equivalent.
    KeyboardInteractive {
        /// Scripted answers; tried in order against each prompt batch.
        responder: Vec<KbiAnswer>,
    },

    /// SSH2 OpenSSH user certificate auth.
    Certificate {
        /// Path to certificate file (`*-cert.pub`).
        cert: PathBuf,
        /// Path to the underlying private key.
        key: PathBuf,
        /// Optional passphrase reference for an encrypted private key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        passphrase: Option<SecretRef>,
    },

    /// SSH3 bearer-token auth (`Authorization: Bearer …`).
    Bearer {
        /// Reference to the bearer token.
        token: SecretRef,
    },

    /// SSH3 HTTP Basic auth.
    Basic {
        /// Username portion sent in the `Authorization: Basic …` header.
        username: String,
        /// Password reference.
        password: SecretRef,
    },

    /// SSH3 OIDC device-flow login — preflight command writes resulting tokens
    /// to a configured secret.
    OidcDeviceFlow {
        /// Issuer URL (e.g. `https://login.example.com`).
        issuer: Url,
        /// OAuth client identifier.
        client_id: String,
        /// Optional `audience` parameter.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        audience: Option<String>,
    },
}

/// Aggregate auth configuration for one profile — username plus an ordered
/// list of methods. Methods are tried in order; the first to succeed wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Login username sent to the remote peer.
    pub username: String,
    /// Ordered list of auth methods to attempt.
    pub methods: Vec<AuthMethod>,
}

impl AuthConfig {
    /// Convenience constructor.
    pub fn new(username: impl Into<String>, methods: Vec<AuthMethod>) -> Self {
        Self {
            username: username.into(),
            methods,
        }
    }
}
