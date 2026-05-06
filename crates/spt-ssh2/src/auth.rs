//! Authentication flow — tries each method in `AuthConfig.methods` order.
//!
//! Secret resolution is delegated to a slice of `&dyn SecretBackend`s — the
//! caller (typically `spt-bin`) configures the resolver chain externally.

use std::io::Write as _;

use async_ssh2_lite::session_stream::AsyncSessionStream;
use async_ssh2_lite::AsyncSession;
use secrecy::ExposeSecret;
use spt_auth::secret_ref::SecretRef as AuthSecretRef;
use spt_auth::{AuthConfig, AuthMethod};
use spt_core::{Error, Result};
use spt_secrets::reference::SecretRef as SecretsSecretRef;
use spt_secrets::{SecretBackend, SecretBytes};
use tempfile::NamedTempFile;
use tracing::{debug, warn};

use crate::errors::from_async_ssh;
use crate::kbi_bridge::ScriptedPrompter;

/// Attempt every method in `auth.methods` in order until one succeeds. Returns
/// `Ok(())` on first success, the last `AuthFailed` otherwise.
pub async fn run<S>(
    session: &AsyncSession<S>,
    auth: &AuthConfig,
    backends: &[&dyn SecretBackend],
) -> Result<()>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    if auth.methods.is_empty() {
        return Err(Error::AuthFailed("no auth methods configured".into()));
    }
    let mut last_err: Option<Error> = None;
    for method in &auth.methods {
        debug!(target: "spt_ssh2::auth", method = ?method_name(method), "attempting");
        match try_one(session, &auth.username, method, backends).await {
            Ok(()) if session.authenticated() => return Ok(()),
            Ok(()) => {
                last_err = Some(Error::AuthFailed(format!(
                    "method `{}` returned success but session is not authenticated",
                    method_name(method)
                )));
            }
            Err(e) => {
                warn!(target: "spt_ssh2::auth", method = method_name(method), error = %e, "auth method failed");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| Error::AuthFailed("all auth methods failed".into())))
}

async fn try_one<S>(
    session: &AsyncSession<S>,
    username: &str,
    method: &AuthMethod,
    backends: &[&dyn SecretBackend],
) -> Result<()>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    match method {
        AuthMethod::Password { secret } => {
            let bytes = resolve_secret(backends, secret)?;
            let pw = std::str::from_utf8(bytes.expose_secret())
                .map_err(|_| Error::AuthFailed("password secret is not utf-8".into()))?;
            session
                .userauth_password(username, pw)
                .await
                .map_err(|e| from_async_ssh("userauth_password", e))
        }
        AuthMethod::Agent { socket } => {
            if socket.is_some() {
                warn!(target: "spt_ssh2::auth", "explicit agent socket override is not supported by libssh2; relying on SSH_AUTH_SOCK");
            }
            session
                .userauth_agent(username)
                .await
                .map_err(|e| from_async_ssh("userauth_agent", e))
        }
        AuthMethod::PublicKey {
            identity_file,
            passphrase,
        } => {
            let pw_string = resolve_passphrase(backends, passphrase.as_ref())?;
            try_pubkey(session, username, identity_file, None, pw_string.as_deref()).await
        }
        AuthMethod::Certificate {
            cert,
            key,
            passphrase,
        } => {
            let pw_string = resolve_passphrase(backends, passphrase.as_ref())?;
            try_pubkey(session, username, key, Some(cert), pw_string.as_deref()).await
        }
        AuthMethod::KeyboardInteractive { responder } => {
            let mut prompter = ScriptedPrompter::new(responder, backends);
            session
                .userauth_keyboard_interactive(username, &mut prompter)
                .await
                .map_err(|e| from_async_ssh("userauth_keyboard_interactive", e))
        }
        AuthMethod::Bearer { .. } | AuthMethod::Basic { .. } | AuthMethod::OidcDeviceFlow { .. } => {
            Err(Error::InvalidConfig(format!(
                "auth method `{}` is SSH3-only; not supported by SSH2 backend",
                method_name(method)
            )))
        }
    }
}

/// Try public-key auth: prefer `userauth_pubkey_memory` when available, else
/// fall back to writing the key to a 0600-mode tempfile and using
/// `userauth_pubkey_file`.
async fn try_pubkey<S>(
    session: &AsyncSession<S>,
    username: &str,
    privkey_path: &std::path::Path,
    cert_path: Option<&std::path::Path>,
    passphrase: Option<&str>,
) -> Result<()>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    // The on-disk key is the canonical form here; both the in-memory and the
    // file-based libssh2 entry points read the same OpenSSH PEM bytes.
    let key_bytes = std::fs::read_to_string(privkey_path).map_err(|e| {
        Error::KeyFailure(format!(
            "read private key `{}`: {e}",
            privkey_path.display()
        ))
    })?;
    let pub_bytes = if let Some(p) = cert_path {
        Some(std::fs::read_to_string(p).map_err(|e| {
            Error::KeyFailure(format!("read cert/pubkey `{}`: {e}", p.display()))
        })?)
    } else {
        None
    };

    // libssh2 `userauth_pubkey_memory` is only compiled in async-ssh2-lite
    // when one of `unix`, `vendored-openssl`, or `openssl-on-win32` is on.
    // The workspace builds without vendored-openssl on Windows (libssh2 uses
    // WinCNG, which lacks the in-memory entry point), so on Windows we skip
    // straight to the tempfile fallback below.
    #[cfg(unix)]
    {
        match session
            .userauth_pubkey_memory(
                username,
                pub_bytes.as_deref(),
                &key_bytes,
                passphrase,
            )
            .await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                debug!(target: "spt_ssh2::auth", "pubkey_memory failed, falling back to file: {e}");
            }
        }
    }

    // Tempfile fallback (Windows non-vendored builds, or pubkey_memory unavail).
    let mut priv_tmp = NamedTempFile::new()
        .map_err(|e| Error::KeyFailure(format!("create temp key file: {e}")))?;
    set_tempfile_mode(priv_tmp.path())?;
    priv_tmp
        .write_all(key_bytes.as_bytes())
        .map_err(|e| Error::KeyFailure(format!("write temp key: {e}")))?;
    priv_tmp
        .flush()
        .map_err(|e| Error::KeyFailure(format!("flush temp key: {e}")))?;
    let priv_path = priv_tmp.path().to_path_buf();

    let pub_tmp_holder;
    let pub_path_opt = if let Some(pb) = pub_bytes {
        let mut pub_tmp = NamedTempFile::new()
            .map_err(|e| Error::KeyFailure(format!("create temp pubkey file: {e}")))?;
        set_tempfile_mode(pub_tmp.path())?;
        pub_tmp
            .write_all(pb.as_bytes())
            .map_err(|e| Error::KeyFailure(format!("write temp pubkey: {e}")))?;
        pub_tmp
            .flush()
            .map_err(|e| Error::KeyFailure(format!("flush temp pubkey: {e}")))?;
        let p = pub_tmp.path().to_path_buf();
        pub_tmp_holder = Some(pub_tmp);
        Some(p)
    } else {
        pub_tmp_holder = None;
        None
    };

    let res = session
        .userauth_pubkey_file(
            username,
            pub_path_opt.as_deref(),
            &priv_path,
            passphrase,
        )
        .await
        .map_err(|e| from_async_ssh("userauth_pubkey_file", e));

    drop(pub_tmp_holder);
    drop(priv_tmp);
    res
}

#[cfg(unix)]
fn set_tempfile_mode(p: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| Error::KeyFailure(format!("chmod temp key: {e}")))
}

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps)]
fn set_tempfile_mode(_p: &std::path::Path) -> Result<()> {
    // Windows: NamedTempFile already creates with restrictive ACL inheritance.
    Ok(())
}

/// Resolve a passphrase reference into an owned `String`. Returns `Ok(None)`
/// when there is no passphrase configured. The owned string is held by the
/// caller for the duration of the libssh2 call; `zeroize` would be ideal but
/// libssh2 expects `&str` so we cannot avoid an owned plaintext copy here.
fn resolve_passphrase(
    backends: &[&dyn SecretBackend],
    r: Option<&AuthSecretRef>,
) -> Result<Option<String>> {
    match r {
        None => Ok(None),
        Some(rf) => {
            let bytes = resolve_secret(backends, rf)?;
            let s = std::str::from_utf8(bytes.expose_secret())
                .map_err(|_| Error::AuthFailed("passphrase secret is not utf-8".into()))?;
            Ok(Some(s.to_owned()))
        }
    }
}

/// Resolve a `SecretRef` from spt-auth via the secrets backends provided.
///
/// Tries each backend in order — the first to return `Ok(Some(_))` wins.
/// `env:` and `file://` references are short-circuited locally because spt-auth's
/// `SecretRef` already carries those variants.
pub fn resolve_secret(
    backends: &[&dyn SecretBackend],
    r: &AuthSecretRef,
) -> Result<SecretBytes> {
    use spt_secrets::backend::secret_bytes;
    match r {
        AuthSecretRef::Vault { namespace, name } => {
            let secrets_ref = SecretsSecretRef::new(namespace, name).map_err(|e| {
                Error::SecretUnavailable {
                    reference: format!("secret://{namespace}/{name}"),
                    reason: format!("invalid reference: {e}"),
                }
            })?;
            for b in backends {
                match b.get(&secrets_ref)? {
                    Some(v) => return Ok(v),
                    None => continue,
                }
            }
            Err(Error::SecretUnavailable {
                reference: secrets_ref.to_string(),
                reason: "no backend resolved the reference".into(),
            })
        }
        AuthSecretRef::Env(name) => {
            let v = std::env::var_os(name).ok_or_else(|| Error::SecretUnavailable {
                reference: format!("env:{name}"),
                reason: format!("environment variable `{name}` not set"),
            })?;
            Ok(secret_bytes(v.to_string_lossy().into_owned().into_bytes()))
        }
        AuthSecretRef::File(path) => {
            let bytes = std::fs::read(path).map_err(|e| Error::SecretUnavailable {
                reference: format!("file://{path}"),
                reason: format!("read `{path}`: {e}"),
            })?;
            Ok(secret_bytes(bytes))
        }
    }
}

fn method_name(m: &AuthMethod) -> &'static str {
    match m {
        AuthMethod::PublicKey { .. } => "public_key",
        AuthMethod::Agent { .. } => "agent",
        AuthMethod::Password { .. } => "password",
        AuthMethod::KeyboardInteractive { .. } => "keyboard_interactive",
        AuthMethod::Certificate { .. } => "certificate",
        AuthMethod::Bearer { .. } => "bearer",
        AuthMethod::Basic { .. } => "basic",
        AuthMethod::OidcDeviceFlow { .. } => "oidc_device_flow",
    }
}
