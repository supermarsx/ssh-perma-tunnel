//! Secret resolution + keyboard-interactive answer evaluation shared by the
//! russh auth dispatch.
//!
//! - [`resolve_secret`] translates a [`spt_auth::SecretRef`] into bytes via
//!   the configured resolver chain. Local short-circuits for `env:` and
//!   `file://` references mirror the auth-config shape and avoid a backend
//!   lookup for those variants.
//! - [`resolve_passphrase`] is a thin convenience wrapper that decodes the
//!   resolved bytes as UTF-8.
//! - [`evaluate_kbi_answer`] turns a `KbiAnswer` (`Static` / `SecretRef` /
//!   `TOTP` / `YubiKey` OATH) into the response string sent on the wire.

use std::time::{SystemTime, UNIX_EPOCH};

use secrecy::ExposeSecret as _;
use spt_auth::secret_ref::SecretRef as AuthSecretRef;
use spt_auth::KbiAnswer;
use spt_core::{Error, Result};
use spt_secrets::reference::SecretRef as SecretsSecretRef;
use spt_secrets::{SecretBackend, SecretBytes};

/// Resolve a `SecretRef` from spt-auth via the supplied secrets backends.
///
/// Tries each backend in order — the first to return `Ok(Some(_))` wins.
/// `env:` and `file://` references are short-circuited locally because
/// spt-auth's `SecretRef` already carries those variants.
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
            // Enforce the same 0400/0600 (Unix) / DACL-audit (Windows) check
            // the spt-secrets file backend applies, instead of a bare read.
            // E2-F2: previously this path skipped the mode check entirely.
            spt_secrets::file::check_mode(std::path::Path::new(path))?;
            let bytes = std::fs::read(path).map_err(|e| Error::SecretUnavailable {
                reference: format!("file://{path}"),
                reason: format!("read `{path}`: {e}"),
            })?;
            Ok(secret_bytes(bytes))
        }
    }
}

/// Resolve an optional passphrase reference. Returns `None` for `None`,
/// otherwise resolves the reference and decodes the bytes as UTF-8.
pub fn resolve_passphrase(
    backends: &[std::sync::Arc<dyn SecretBackend>],
    passphrase: Option<&AuthSecretRef>,
) -> Result<Option<String>> {
    match passphrase {
        None => Ok(None),
        Some(reference) => {
            let refs: Vec<&dyn SecretBackend> =
                backends.iter().map(std::convert::AsRef::as_ref).collect();
            let bytes = resolve_secret(&refs, reference)?;
            let value = std::str::from_utf8(bytes.expose_secret())
                .map_err(|_| Error::AuthFailed("passphrase secret is not utf-8".into()))?;
            Ok(Some(value.to_owned()))
        }
    }
}

/// Evaluate one [`KbiAnswer`] to the UTF-8 string sent back to the server.
///
/// `Static` returns the literal. `SecretRef` resolves through the supplied
/// backends. `Totp` and `YubikeyOath` propagate typed errors so the auth
/// layer can surface them — credential-equivalent variants must never fail
/// silently.
pub fn evaluate_kbi_answer(answer: &KbiAnswer, backends: &[&dyn SecretBackend]) -> Result<String> {
    match answer {
        KbiAnswer::Static(s) => Ok(s.clone()),
        KbiAnswer::SecretRef(r) => {
            let bytes = resolve_secret(backends, r)?;
            String::from_utf8(bytes.expose_secret().to_vec())
                .map_err(|_| Error::AuthFailed("keyboard-interactive secret is not utf-8".into()))
        }
        KbiAnswer::Totp {
            secret_ref,
            digits,
            period,
            algo,
        } => {
            let bytes = resolve_secret(backends, secret_ref)?;
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| Error::RuntimeFailure(format!("system clock: {e}")))?
                .as_secs();
            spt_auth::totp::generate(
                bytes.expose_secret(),
                u64::from(*period),
                *digits,
                *algo,
                now,
            )
        }
        KbiAnswer::YubikeyOath { serial, oath_name } => {
            spt_auth::yubikey_oath::fetch_code(serial.as_deref(), oath_name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_auth::SecretRef as AuthSecretRef;

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

    /// Tighten a file to owner-only so the mode check accepts it. No-op on
    /// non-Unix (the Windows check is best-effort and never rejects).
    #[allow(unused_variables)]
    fn make_owner_only(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    #[test]
    fn resolve_secret_file_variant() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.txt");
        std::fs::write(&p, b"filebody").unwrap();
        make_owner_only(&p);
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::File(p.to_string_lossy().into_owned());
        let got = resolve_secret(&backends, &rf).unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"filebody");
    }

    #[cfg(unix)]
    #[test]
    fn resolve_secret_file_variant_rejects_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("loose.txt");
        std::fs::write(&p, b"filebody").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        let backends: Vec<&dyn SecretBackend> = vec![];
        let rf = AuthSecretRef::File(p.to_string_lossy().into_owned());
        let err = resolve_secret(&backends, &rf).unwrap_err();
        assert!(matches!(err, Error::PermissionDenied(_)), "got {err:?}");
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
        fn get(&self, _r: &spt_secrets::SecretRef) -> Result<Option<spt_secrets::SecretBytes>> {
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

    struct EmptyBackend;
    impl SecretBackend for EmptyBackend {
        fn kind(&self) -> spt_secrets::BackendKind {
            spt_secrets::BackendKind::Env
        }
        fn get(&self, _r: &spt_secrets::SecretRef) -> Result<Option<spt_secrets::SecretBytes>> {
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
        let backends: Vec<std::sync::Arc<dyn SecretBackend>> = vec![];
        let got = resolve_passphrase(&backends, None).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn resolve_passphrase_some_resolves_to_string() {
        std::env::set_var("SPT_TEST_PASSPHRASE_S", "secretpw");
        let backends: Vec<std::sync::Arc<dyn SecretBackend>> = vec![];
        let rf = AuthSecretRef::Env("SPT_TEST_PASSPHRASE_S".into());
        let got = resolve_passphrase(&backends, Some(&rf)).unwrap();
        assert_eq!(got.as_deref(), Some("secretpw"));
        std::env::remove_var("SPT_TEST_PASSPHRASE_S");
    }

    #[test]
    fn resolve_passphrase_non_utf8_errors() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("badutf8.bin");
        std::fs::write(&p, [0xFFu8, 0xFE]).unwrap();
        make_owner_only(&p);
        let backends: Vec<std::sync::Arc<dyn SecretBackend>> = vec![];
        let rf = AuthSecretRef::File(p.to_string_lossy().into_owned());
        let err = resolve_passphrase(&backends, Some(&rf)).unwrap_err();
        assert!(matches!(err, Error::AuthFailed(_)));
    }
}
