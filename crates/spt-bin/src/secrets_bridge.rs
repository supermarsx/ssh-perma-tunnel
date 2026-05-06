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
use spt_secrets::{
    EnvBackend, FileBackend, KeychainBackend, Resolver, SecretBackend, SecretRef,
};

/// Build a [`Resolver`] from the `[secrets]` config table.
///
/// Backend priority order (per spec §14.6): keychain → vault → env → file.
/// The `state_dir` is used to locate the default vault file when no explicit
/// `vault_file` is configured.
pub fn build_resolver(cfg: Option<&SecretsConfig>, state_dir: &std::path::Path) -> Result<Resolver> {
    let mut backends: Vec<Arc<dyn SecretBackend>> = Vec::new();
    let backend_kind = cfg
        .and_then(|s| s.backend.as_deref())
        .unwrap_or("auto");

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
    // FileBackend rooted at <state_dir>/secrets/ acts as a final fallback.
    backends.push(Arc::new(FileBackend::new(state_dir.join("secrets"))));
    let _ = (state_dir, PathBuf::new());
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

    #[test]
    fn build_resolver_with_no_config_returns_some_backends() {
        let tmp = tempfile::tempdir().unwrap();
        let r = build_resolver(None, tmp.path()).expect("build");
        assert!(r.backends().count() >= 2);
    }
}
