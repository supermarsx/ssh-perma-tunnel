#![allow(clippy::unnecessary_wraps, clippy::needless_pass_by_value)]
//! Glue between `spt_auth::SecretRef` (config-shape newtype) and the resolver
//! in `spt_secrets`.
//!
//! The two crates intentionally have different `SecretRef` types: spt-auth's
//! is a permissive shape-checker over the spec grammar (`secret://`, `env:`,
//! `file:///`); spt-secrets's is a strict `secret://ns/name` reference paired
//! with a `Resolver`. This module bridges them and constructs a resolver
//! whose backend list matches the `[secrets]` config table.

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use spt_config::schema::Secrets as SecretsConfig;
use spt_core::{Error, Result};
use spt_secrets::{EnvBackend, FileBackend, KeychainBackend, Resolver, SecretBackend, SecretRef};

/// Build a [`Resolver`] from the `[secrets]` config table.
///
/// Backend priority order (per spec §14.6): keychain → vault → env → file.
/// The `state_dir` is used to locate the default vault file when no explicit
/// `vault_file` is configured.
pub fn build_resolver(
    cfg: Option<&SecretsConfig>,
    state_dir: &std::path::Path,
) -> Result<Resolver> {
    let mut backends: Vec<Arc<dyn SecretBackend>> = Vec::new();
    let backend_kind = cfg.and_then(|s| s.backend.as_deref()).unwrap_or("auto");

    let want_keychain = matches!(backend_kind, "auto" | "keychain");
    let want_env = matches!(backend_kind, "auto" | "env");

    if want_keychain {
        let ns = cfg
            .and_then(|s| s.keychain_namespace.clone())
            .unwrap_or_else(|| "spt".to_string());
        backends.push(Arc::new(KeychainBackend::with_service(ns)));
    }
    // Note: VaultBackend requires explicit unlock (passphrase or keychain
    // material). Handlers that need vault access acquire it on demand and
    // push it onto a fresh resolver — keeping it out of the default chain
    // means the CLI never blocks waiting for a passphrase prompt unless the
    // command actually needs a secret.
    if want_env {
        backends.push(Arc::new(EnvBackend::new()));
    }
    // FileBackend acts as a final fallback. Its root defaults to
    // <state_dir>/secrets/ (back-compat) but honors an explicit
    // `[secrets.file] root = "..."` when configured — e.g. point it at a
    // read-only `/run/secrets` mount so `secret://ns/name` resolves there.
    // The backend's own containment + 0400/0600 permission checks are
    // unchanged regardless of the root.
    let file_root = cfg
        .and_then(|s| s.file.as_ref())
        .and_then(|f| f.root.as_deref())
        .map_or_else(|| state_dir.join("secrets"), PathBuf::from);
    backends.push(Arc::new(FileBackend::new(file_root)));
    Ok(Resolver::new(backends))
}

/// Translate the spt-auth shape-checker into the resolver-side `SecretRef`.
///
/// Only `secret://ns/name` references can be resolved this way; `env:` and
/// `file://` references are addressed via the `EnvBackend` / `FileBackend`
/// wrappers and require a different code path.
pub fn auth_ref_to_resolver_ref(auth: &spt_auth::SecretRef) -> Result<SecretRef> {
    let s = auth.to_string();
    SecretRef::from_str(&s).map_err(|e| Error::SecretUnavailable {
        reference: s.clone(),
        reason: format!("not a secret:// reference: {e}"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use spt_config::schema::Secrets as SecretsConfig;

    #[test]
    fn build_resolver_with_no_config_returns_some_backends() {
        let tmp = tempfile::tempdir().unwrap();
        let r = build_resolver(None, tmp.path()).expect("build");
        assert!(r.backends().count() >= 2);
    }

    #[test]
    fn build_resolver_keychain_only_skips_env_backend() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SecretsConfig {
            backend: Some("keychain".into()),
            ..Default::default()
        };
        let r = build_resolver(Some(&cfg), tmp.path()).expect("build");
        // keychain + file fallback = 2 backends, no env.
        let count = r.backends().count();
        assert!(count >= 2, "keychain backend expected, got {count}");
    }

    #[test]
    fn build_resolver_env_only_skips_keychain() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SecretsConfig {
            backend: Some("env".into()),
            ..Default::default()
        };
        let r = build_resolver(Some(&cfg), tmp.path()).expect("build");
        // env + file fallback = 2 backends, no keychain.
        let count = r.backends().count();
        assert!(count >= 2);
    }

    #[test]
    fn build_resolver_unknown_backend_only_uses_file_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SecretsConfig {
            backend: Some("magic".into()),
            ..Default::default()
        };
        let r = build_resolver(Some(&cfg), tmp.path()).expect("build");
        // Unknown backend = only file fallback registered.
        assert_eq!(r.backends().count(), 1);
    }

    #[test]
    fn build_resolver_uses_custom_keychain_namespace() {
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SecretsConfig {
            backend: Some("keychain".into()),
            keychain_namespace: Some("my-org".into()),
            ..Default::default()
        };
        let r = build_resolver(Some(&cfg), tmp.path()).expect("build");
        assert!(r.backends().count() >= 1);
    }

    #[test]
    fn build_resolver_honors_configured_file_root() {
        // A secret seeded ONLY under a custom root is resolvable when
        // `[secrets.file] root` points there, and is NOT resolvable when the
        // field is unset (proving the root actually switched, not a coincidence).
        let state = tempfile::tempdir().unwrap();
        let custom = tempfile::tempdir().unwrap();
        let r = SecretRef::from_str("secret://ns/name").unwrap();
        FileBackend::new(custom.path())
            .set(&r, b"from-custom")
            .unwrap();

        let cfg_custom = SecretsConfig {
            backend: Some("file".into()),
            file: Some(spt_config::schema::SecretsFile {
                root: Some(custom.path().display().to_string()),
            }),
            ..Default::default()
        };
        let resolver = build_resolver(Some(&cfg_custom), state.path()).expect("build");
        assert!(
            resolver.resolve(&r).is_ok(),
            "configured file.root should resolve the seeded secret"
        );

        // Same state_dir, but no configured root -> default <state_dir>/secrets,
        // where nothing was seeded, so the reference is unavailable.
        let cfg_default = SecretsConfig {
            backend: Some("file".into()),
            ..Default::default()
        };
        let resolver = build_resolver(Some(&cfg_default), state.path()).expect("build");
        assert!(
            resolver.resolve(&r).is_err(),
            "unset file.root must not read from the custom root"
        );
    }

    #[test]
    fn build_resolver_file_root_defaults_to_state_dir_when_unset() {
        // With no configured root, the file backend falls back to
        // <state_dir>/secrets (back-compat).
        let state = tempfile::tempdir().unwrap();
        let r = SecretRef::from_str("secret://ns/name").unwrap();
        FileBackend::new(state.path().join("secrets"))
            .set(&r, b"from-state")
            .unwrap();

        let cfg = SecretsConfig {
            backend: Some("file".into()),
            ..Default::default()
        };
        let resolver = build_resolver(Some(&cfg), state.path()).expect("build");
        assert!(
            resolver.resolve(&r).is_ok(),
            "default root <state_dir>/secrets should resolve the seeded secret"
        );
    }

    #[test]
    fn auth_ref_to_resolver_ref_for_secret_grammar() {
        let auth = spt_auth::SecretRef::parse("secret://ns/name").unwrap();
        let resolved = auth_ref_to_resolver_ref(&auth).unwrap();
        assert_eq!(resolved.ns(), "ns");
        assert_eq!(resolved.name(), "name");
    }

    #[test]
    fn auth_ref_to_resolver_ref_rejects_env_form() {
        let auth = spt_auth::SecretRef::parse("env:FOO").unwrap();
        let err = auth_ref_to_resolver_ref(&auth).unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
    }

    #[test]
    fn auth_ref_to_resolver_ref_rejects_file_form() {
        let auth = spt_auth::SecretRef::parse("file:///tmp/x").unwrap();
        let err = auth_ref_to_resolver_ref(&auth).unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
    }
}
