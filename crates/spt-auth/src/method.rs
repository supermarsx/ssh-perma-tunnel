//! [`AuthMethod`] enum and [`AuthConfig`] container.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use spt_core::{Error, Result};
use url::Url;

use crate::kbi::KbiResponder;
use crate::secret_ref::SecretRef;

/// Algorithm-policy gate for incoming public-key auth offers.
///
/// `algorithm` is the SSH signature-algorithm name negotiated for the
/// authentication exchange — for example `ssh-ed25519`, `rsa-sha2-256`,
/// `rsa-sha2-512`, `ecdsa-sha2-nistp256` etc. Legacy `ssh-rsa` (SHA-1, RFC
/// 4253) is rejected unless `allow_ssh_rsa_sha1` is `true`; the escape hatch
/// exists for connecting to servers that have not been upgraded to RFC 8332
/// (`rsa-sha2-256` / `rsa-sha2-512`).
///
/// Returns `Ok(())` on accepted algorithms; an [`Error::AuthFailed`] with a
/// stable message prefix `algorithm policy:` on rejected ones.
pub fn check_pubkey_algorithm_allowed(algorithm: &str, allow_ssh_rsa_sha1: bool) -> Result<()> {
    if algorithm == "ssh-rsa" && !allow_ssh_rsa_sha1 {
        return Err(Error::AuthFailed(format!(
            "algorithm policy: refusing legacy `{algorithm}` (SHA-1); \
             enable `allow_ssh_rsa_sha1 = true` to permit"
        )));
    }
    Ok(())
}

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
        /// Permit legacy `ssh-rsa` (SHA-1) public-key auth (RFC 4253).
        ///
        /// SHA-1 is collision-broken; ssh-rsa SHA-1 is rejected by default.
        /// Newer servers negotiate `rsa-sha2-256` / `rsa-sha2-512` (RFC 8332)
        /// from the same key bytes, so this escape hatch is only needed when
        /// connecting to legacy OpenSSH (<7.2) or proprietary servers that
        /// have not been updated. See `docs/auth.md` for the policy rationale.
        #[serde(default)]
        allow_ssh_rsa_sha1: bool,
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
        /// Scripted prompt/answer bindings; tried in order. First-match wins.
        responder: Vec<KbiResponder>,
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

    /// SSH2 GSSAPI/Kerberos auth.
    Gssapi {
        /// Optional service principal, for example `host/edge.example.com`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
        /// Optional client principal hint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<String>,
        /// Permit credential delegation.
        #[serde(default)]
        delegate: bool,
    },

    /// Windows SSPI/Negotiate auth for SSH2.
    Sspi {
        /// Optional service principal name.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        service: Option<String>,
        /// Optional client principal hint.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        principal: Option<String>,
        /// Permit credential delegation.
        #[serde(default)]
        delegate: bool,
        /// Permit NTLM fallback when Kerberos cannot be negotiated.
        #[serde(default)]
        allow_ntlm_fallback: bool,
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

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn ssh_rsa_sha1_rejected_by_default() {
        let err = check_pubkey_algorithm_allowed("ssh-rsa", false).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("algorithm policy"), "{msg}");
        assert!(msg.contains("ssh-rsa"), "{msg}");
    }

    #[test]
    fn ssh_rsa_sha1_accepted_with_escape_hatch() {
        check_pubkey_algorithm_allowed("ssh-rsa", true).unwrap();
    }

    #[test]
    fn rsa_sha2_variants_always_accepted() {
        check_pubkey_algorithm_allowed("rsa-sha2-256", false).unwrap();
        check_pubkey_algorithm_allowed("rsa-sha2-512", false).unwrap();
        // Even with the legacy escape hatch on, the SHA-2 variants pass.
        check_pubkey_algorithm_allowed("rsa-sha2-256", true).unwrap();
    }

    #[test]
    fn ed25519_and_ecdsa_always_accepted() {
        for algo in [
            "ssh-ed25519",
            "ecdsa-sha2-nistp256",
            "ecdsa-sha2-nistp384",
            "ecdsa-sha2-nistp521",
        ] {
            check_pubkey_algorithm_allowed(algo, false).unwrap();
        }
    }
}
