//! Authentication flow — tries each method in `AuthConfig.methods` order.
//!
//! Secret resolution is delegated to a slice of `&dyn SecretBackend`s — the
//! caller (typically `spt-bin`) configures the resolver chain externally.

use std::io::Write as _;

use async_ssh2_lite::session_stream::AsyncSessionStream;
use async_ssh2_lite::AsyncSession;
use ed25519_dalek::pkcs8::EncodePrivateKey as EncodeEd25519PrivateKey;
use rsa::pkcs1::{EncodeRsaPrivateKey, LineEnding as Pkcs1LineEnding};
use rsa::pkcs8::LineEnding as Pkcs8LineEnding;
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
        AuthMethod::Bearer { .. }
        | AuthMethod::Basic { .. }
        | AuthMethod::OidcDeviceFlow { .. } => Err(Error::InvalidConfig(format!(
            "auth method `{}` is SSH3-only; not supported by SSH2 backend",
            method_name(method)
        ))),
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
    let original_key_bytes = std::fs::read_to_string(privkey_path).map_err(|e| {
        Error::KeyFailure(format!(
            "read private key `{}`: {e}",
            privkey_path.display()
        ))
    })?;
    let key_bytes = normalize_private_key_for_libssh2(&original_key_bytes)?;
    let pub_bytes = public_key_material(privkey_path, cert_path)?;

    // The memory API is available on Unix and when the optional vendored
    // OpenSSL backend is enabled on Windows. Otherwise, fall back to file auth.
    #[cfg(any(unix, feature = "vendored-openssl"))]
    match session
        .userauth_pubkey_memory(username, pub_bytes.as_deref(), &key_bytes, passphrase)
        .await
    {
        Ok(()) => return Ok(()),
        Err(e) => {
            debug!(target: "spt_ssh2::auth", "pubkey_memory failed, falling back to file: {e}");
        }
    }

    // Tempfile fallback (Windows non-vendored builds, or pubkey_memory unavail).
    let res = try_pubkey_file_with_material(
        session,
        username,
        &key_bytes,
        pub_bytes.as_deref(),
        passphrase,
    )
    .await;
    if res.is_err() && original_key_bytes != key_bytes {
        debug!(
            target: "spt_ssh2::auth",
            "normalized pubkey_file failed, retrying with original OpenSSH key material"
        );
        return try_pubkey_file_with_material(
            session,
            username,
            &original_key_bytes,
            pub_bytes.as_deref(),
            passphrase,
        )
        .await;
    }
    res
}

async fn try_pubkey_file_with_material<S>(
    session: &AsyncSession<S>,
    username: &str,
    private_key: &str,
    pubkey: Option<&str>,
    passphrase: Option<&str>,
) -> Result<()>
where
    S: AsyncSessionStream + Send + Sync + 'static,
{
    let mut priv_tmp = NamedTempFile::new()
        .map_err(|e| Error::KeyFailure(format!("create temp key file: {e}")))?;
    set_tempfile_mode(priv_tmp.path())?;
    priv_tmp
        .write_all(private_key.as_bytes())
        .map_err(|e| Error::KeyFailure(format!("write temp key: {e}")))?;
    priv_tmp
        .flush()
        .map_err(|e| Error::KeyFailure(format!("flush temp key: {e}")))?;
    let priv_path = priv_tmp.path().to_path_buf();

    let pub_tmp_holder;
    let pub_path_opt = if let Some(pb) = pubkey {
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
        .userauth_pubkey_file(username, pub_path_opt.as_deref(), &priv_path, passphrase)
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

fn public_key_material(
    privkey_path: &std::path::Path,
    cert_path: Option<&std::path::Path>,
) -> Result<Option<String>> {
    let discovered;
    let path = if let Some(path) = cert_path {
        Some(path)
    } else {
        discovered = discover_public_key_path(privkey_path);
        discovered.as_deref()
    };
    let Some(path) = path else { return Ok(None) };
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|e| Error::KeyFailure(format!("read cert/pubkey `{}`: {e}", path.display())))
}

fn discover_public_key_path(privkey_path: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut path = privkey_path.as_os_str().to_os_string();
    path.push(".pub");
    let path = std::path::PathBuf::from(path);
    path.exists().then_some(path)
}

fn normalize_private_key_for_libssh2(key_bytes: &str) -> Result<String> {
    if !key_bytes.contains("BEGIN OPENSSH PRIVATE KEY") {
        return Ok(key_bytes.to_owned());
    }

    let key = ssh_key::PrivateKey::from_openssh(key_bytes.as_bytes())
        .map_err(|e| Error::KeyFailure(format!("parse OpenSSH private key for libssh2: {e}")))?;

    match key.key_data() {
        ssh_key::private::KeypairData::Rsa(keypair) => {
            let key = rsa::RsaPrivateKey::from_components(
                mpint_to_biguint(&keypair.public.n),
                mpint_to_biguint(&keypair.public.e),
                mpint_to_biguint(&keypair.private.d),
                vec![
                    mpint_to_biguint(&keypair.private.p),
                    mpint_to_biguint(&keypair.private.q),
                ],
            )
            .map_err(|e| Error::KeyFailure(format!("convert OpenSSH RSA key: {e}")))?;
            key.to_pkcs1_pem(Pkcs1LineEnding::LF)
                .map(|pem| pem.to_string())
                .map_err(|e| Error::KeyFailure(format!("encode RSA key as PEM: {e}")))
        }
        ssh_key::private::KeypairData::Ed25519(keypair) => {
            let key = ed25519_dalek::SigningKey::from_bytes(keypair.private.as_ref());
            key.to_pkcs8_pem(Pkcs8LineEnding::LF)
                .map(|pem| pem.to_string())
                .map_err(|e| Error::KeyFailure(format!("encode ED25519 key as PKCS#8 PEM: {e}")))
        }
        _ => Ok(key_bytes.to_owned()),
    }
}

fn mpint_to_biguint(value: &ssh_key::Mpint) -> rsa::BigUint {
    rsa::BigUint::from_bytes_be(
        value
            .as_positive_bytes()
            .unwrap_or_else(|| value.as_bytes()),
    )
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
pub fn resolve_secret(backends: &[&dyn SecretBackend], r: &AuthSecretRef) -> Result<SecretBytes> {
    use spt_secrets::backend::secret_bytes;
    match r {
        AuthSecretRef::Vault { namespace, name } => {
            let secrets_ref =
                SecretsSecretRef::new(namespace, name).map_err(|e| Error::SecretUnavailable {
                    reference: format!("secret://{namespace}/{name}"),
                    reason: format!("invalid reference: {e}"),
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

#[cfg(test)]
mod tests {
    use ssh_key::{Algorithm, LineEnding, PrivateKey};
    use std::path::PathBuf;

    use spt_auth::SecretRef as AuthSecretRef;

    use super::*;

    #[test]
    fn normalizes_openssh_ed25519_private_key_to_pkcs8_pem() {
        let mut rng = ssh_key::rand_core::OsRng;
        let key = PrivateKey::random(&mut rng, Algorithm::Ed25519).unwrap();
        let openssh = key.to_openssh(LineEnding::LF).unwrap();

        let normalized = normalize_private_key_for_libssh2(&openssh).unwrap();

        assert!(normalized.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(normalized.ends_with("-----END PRIVATE KEY-----\n"));
    }

    #[test]
    fn normalizes_openssh_rsa_private_key_to_pkcs1_pem() {
        let mut rng = ssh_key::rand_core::OsRng;
        let key = PrivateKey::random(&mut rng, Algorithm::Rsa { hash: None }).unwrap();
        let openssh = key.to_openssh(LineEnding::LF).unwrap();

        let normalized = normalize_private_key_for_libssh2(&openssh).unwrap();

        assert!(normalized.starts_with("-----BEGIN RSA PRIVATE KEY-----"));
        assert!(normalized.ends_with("-----END RSA PRIVATE KEY-----\n"));
    }

    #[test]
    fn normalize_passthrough_when_not_openssh() {
        let pem = "-----BEGIN RSA PRIVATE KEY-----\nblob\n-----END RSA PRIVATE KEY-----\n";
        let out = normalize_private_key_for_libssh2(pem).unwrap();
        assert_eq!(out, pem);
    }

    #[test]
    fn normalize_rejects_malformed_openssh_blob() {
        let bad = "-----BEGIN OPENSSH PRIVATE KEY-----\nnot base64!\n-----END OPENSSH PRIVATE KEY-----\n";
        assert!(normalize_private_key_for_libssh2(bad).is_err());
    }

    #[test]
    fn method_name_covers_every_variant() {
        // PublicKey / Agent / Password / KeyboardInteractive / Certificate /
        // Bearer / Basic / OidcDeviceFlow.
        let pk = AuthMethod::PublicKey {
            identity_file: PathBuf::from("/tmp/id_test"),
            passphrase: None,
        };
        assert_eq!(method_name(&pk), "public_key");
        let agent = AuthMethod::Agent { socket: None };
        assert_eq!(method_name(&agent), "agent");
        let pw = AuthMethod::Password {
            secret: AuthSecretRef::Env("X".into()),
        };
        assert_eq!(method_name(&pw), "password");
        let kbi = AuthMethod::KeyboardInteractive { responder: vec![] };
        assert_eq!(method_name(&kbi), "keyboard_interactive");
        let cert = AuthMethod::Certificate {
            cert: PathBuf::from("/tmp/c"),
            key: PathBuf::from("/tmp/k"),
            passphrase: None,
        };
        assert_eq!(method_name(&cert), "certificate");
        let bearer = AuthMethod::Bearer {
            token: AuthSecretRef::Env("X".into()),
        };
        assert_eq!(method_name(&bearer), "bearer");
        let basic = AuthMethod::Basic {
            username: "u".into(),
            password: AuthSecretRef::Env("X".into()),
        };
        assert_eq!(method_name(&basic), "basic");
        let oidc = AuthMethod::OidcDeviceFlow {
            issuer: "https://i".parse().unwrap(),
            client_id: "c".into(),
            audience: None,
        };
        assert_eq!(method_name(&oidc), "oidc_device_flow");
    }

    #[test]
    fn discover_public_key_path_finds_dotpub() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("id_ed25519");
        let pub_path = dir.path().join("id_ed25519.pub");
        std::fs::write(&priv_path, b"priv").unwrap();
        std::fs::write(&pub_path, b"pub").unwrap();
        let got = discover_public_key_path(&priv_path).expect("found");
        assert_eq!(got, pub_path);
    }

    #[test]
    fn discover_public_key_path_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("id_x");
        std::fs::write(&priv_path, b"priv").unwrap();
        assert!(discover_public_key_path(&priv_path).is_none());
    }

    #[test]
    fn public_key_material_uses_explicit_cert_path_when_provided() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("k");
        let cert_path = dir.path().join("k-cert.pub");
        std::fs::write(&priv_path, b"priv").unwrap();
        std::fs::write(&cert_path, "CERTBODY").unwrap();
        let got = public_key_material(&priv_path, Some(&cert_path)).unwrap();
        assert_eq!(got.as_deref(), Some("CERTBODY"));
    }

    #[test]
    fn public_key_material_falls_back_to_dotpub() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("id_e");
        let pub_path = dir.path().join("id_e.pub");
        std::fs::write(&priv_path, b"priv").unwrap();
        std::fs::write(&pub_path, "PUBBODY").unwrap();
        let got = public_key_material(&priv_path, None).unwrap();
        assert_eq!(got.as_deref(), Some("PUBBODY"));
    }

    #[test]
    fn public_key_material_none_when_no_cert_and_no_dotpub() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("k");
        std::fs::write(&priv_path, b"priv").unwrap();
        let got = public_key_material(&priv_path, None).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn public_key_material_errors_when_explicit_cert_missing() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("k");
        let cert_path = dir.path().join("does-not-exist");
        std::fs::write(&priv_path, b"priv").unwrap();
        let err = public_key_material(&priv_path, Some(&cert_path)).unwrap_err();
        assert!(matches!(err, Error::KeyFailure(_)));
    }

    #[test]
    fn resolve_secret_env_variant() {
        std::env::set_var("SPT_TEST_AUTH_E", "value");
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::Env("SPT_TEST_AUTH_E".into());
        let got = resolve_secret(&backends, &rf).unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"value");
        std::env::remove_var("SPT_TEST_AUTH_E");
    }

    #[test]
    fn resolve_secret_env_variant_missing_returns_unavailable() {
        std::env::remove_var("SPT_TEST_AUTH_MISSING");
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::Env("SPT_TEST_AUTH_MISSING".into());
        let err = resolve_secret(&backends, &rf).unwrap_err();
        match err {
            Error::SecretUnavailable { reference, .. } => {
                assert!(reference.contains("SPT_TEST_AUTH_MISSING"));
            }
            other => panic!("expected SecretUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn resolve_secret_file_variant() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.txt");
        std::fs::write(&p, b"filebody").unwrap();
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::File(p.to_string_lossy().into_owned());
        let got = resolve_secret(&backends, &rf).unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"filebody");
    }

    #[test]
    fn resolve_secret_file_variant_missing() {
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::File("/no/such/path/here".into());
        let err = resolve_secret(&backends, &rf).unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
    }

    /// In-memory `SecretBackend` always returning a fixed value.
    struct CannedBackend(&'static [u8]);
    impl SecretBackend for CannedBackend {
        fn kind(&self) -> spt_secrets::BackendKind {
            spt_secrets::BackendKind::Env
        }
        fn get(
            &self,
            _r: &spt_secrets::SecretRef,
        ) -> Result<Option<spt_secrets::SecretBytes>> {
            Ok(Some(spt_secrets::backend::secret_bytes(self.0.to_vec())))
        }
        fn set(&self, _r: &spt_secrets::SecretRef, _value: &[u8]) -> Result<()> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<spt_secrets::SecretRef>> {
            Ok(vec![])
        }
        fn remove(&self, _r: &spt_secrets::SecretRef) -> Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> spt_secrets::BackendDoctor {
            spt_secrets::BackendDoctor::ok(spt_secrets::BackendKind::Env, "test")
        }
    }

    /// Backend that always returns `Ok(None)`.
    struct EmptyBackend;
    impl SecretBackend for EmptyBackend {
        fn kind(&self) -> spt_secrets::BackendKind {
            spt_secrets::BackendKind::Env
        }
        fn get(
            &self,
            _r: &spt_secrets::SecretRef,
        ) -> Result<Option<spt_secrets::SecretBytes>> {
            Ok(None)
        }
        fn set(&self, _r: &spt_secrets::SecretRef, _value: &[u8]) -> Result<()> {
            Ok(())
        }
        fn list(&self) -> Result<Vec<spt_secrets::SecretRef>> {
            Ok(vec![])
        }
        fn remove(&self, _r: &spt_secrets::SecretRef) -> Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> spt_secrets::BackendDoctor {
            spt_secrets::BackendDoctor::ok(spt_secrets::BackendKind::Env, "test")
        }
    }

    #[test]
    fn resolve_secret_vault_variant_returns_first_hit() {
        let b1 = EmptyBackend;
        let b2 = CannedBackend(b"hello");
        let backends: Vec<&dyn SecretBackend> = vec![&b1, &b2];
        let rf = AuthSecretRef::Vault {
            namespace: "ns".into(),
            name: "n".into(),
        };
        let got = resolve_secret(&backends, &rf).unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"hello");
    }

    #[test]
    fn resolve_secret_vault_variant_none_yields_unavailable() {
        let b1 = EmptyBackend;
        let backends: Vec<&dyn SecretBackend> = vec![&b1];
        let rf = AuthSecretRef::Vault {
            namespace: "ns".into(),
            name: "n".into(),
        };
        let err = resolve_secret(&backends, &rf).unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
    }

    #[test]
    fn resolve_passphrase_none_yields_none() {
        let backends: Vec<&dyn SecretBackend> = vec![];
        let got = resolve_passphrase(&backends, None).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn resolve_passphrase_some_resolves_to_string() {
        std::env::set_var("SPT_TEST_PASSPHRASE", "secretpw");
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::Env("SPT_TEST_PASSPHRASE".into());
        let got = resolve_passphrase(&backends, Some(&rf)).unwrap();
        assert_eq!(got.as_deref(), Some("secretpw"));
        std::env::remove_var("SPT_TEST_PASSPHRASE");
    }

    #[test]
    fn resolve_passphrase_non_utf8_errors() {
        // Write 0xFF (invalid UTF-8) into a file and resolve through File variant.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("badutf8.bin");
        std::fs::write(&p, [0xFFu8, 0xFE]).unwrap();
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::File(p.to_string_lossy().into_owned());
        let err = resolve_passphrase(&backends, Some(&rf)).unwrap_err();
        assert!(matches!(err, Error::AuthFailed(_)));
    }

    #[test]
    fn mpint_to_biguint_roundtrip() {
        let raw: &[u8] = &[0x01, 0x00, 0x00];
        let mp = ssh_key::Mpint::from_bytes(raw).unwrap();
        let bi = mpint_to_biguint(&mp);
        // The mpint should round-trip to a positive integer equal to 0x010000.
        assert_eq!(bi, rsa::BigUint::from(0x0001_0000u64));
    }
}
