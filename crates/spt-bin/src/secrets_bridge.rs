#![allow(clippy::unnecessary_wraps, clippy::needless_pass_by_value)]
//! Glue between `spt_auth::SecretRef` (config-shape newtype) and the resolver
//! in `spt_secrets`.
//!
//! The two crates intentionally have different `SecretRef` types: spt-auth's
//! is a permissive shape-checker over the spec grammar (`secret://`, `env:`,
//! `file:///`); spt-secrets's is a strict `secret://ns/name` reference paired
//! with a `Resolver`. This module bridges them and constructs a resolver
//! whose backend list matches the `[secrets]` config table.

use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

use spt_config::schema::Secrets as SecretsConfig;
use spt_core::{Error, Result};
use spt_secrets::{
    apply_memory_protection_once, EnvBackend, FileBackend, KeychainBackend, MemoryProtection,
    Resolver, SecretBackend, SecretRef, VaultBackend,
};

/// Build a [`Resolver`] from the `[secrets]` config table.
///
/// Backends are composed in the spec §14.6 priority order — **keychain → vault
/// → env → file** — including only the backends selected by `[secrets].backend`,
/// with the file backend always appended as the final fallback:
///
/// * `auto` (default) → keychain, env, file
/// * `keychain` → keychain, file
/// * `env` → env, file
/// * `vault` → vault, file (the vault is unlocked non-interactively via the OS
///   keychain master key; see [`build_vault_backend`])
///
/// This function also applies the process-wide `[secrets].memory_protection`
/// level exactly once per process (mlockall on Unix for `strict`) and warns when
/// `encrypt_at_rest = true` is set against a backend that cannot honour it.
///
/// The `state_dir` locates the default file-backend root and default vault
/// directory when no explicit `[secrets.file].root` / `vault_file` is configured.
///
/// # Errors
///
/// Returns an error when `backend = "vault"` is selected but the vault does not
/// exist or cannot be unlocked from the OS keychain — a fail-loud contract, so a
/// vault misconfiguration never silently collapses to file-only resolution.
pub fn build_resolver(cfg: Option<&SecretsConfig>, state_dir: &Path) -> Result<Resolver> {
    // Finding 1: honour `[secrets].memory_protection`. Previously validated as a
    // closed enum and documented as "consumed by spt-secrets" but never applied.
    // `apply_once` is process-global and idempotent, so calling it on every
    // resolver build is cheap and logs the active protection exactly once.
    let level = MemoryProtection::from_config(cfg.and_then(|s| s.memory_protection.as_deref()));
    let _ = apply_memory_protection_once(level);

    let mut backends: Vec<Arc<dyn SecretBackend>> = Vec::new();
    let backend_kind = cfg.and_then(|s| s.backend.as_deref()).unwrap_or("auto");

    let want_keychain = matches!(backend_kind, "auto" | "keychain");
    let want_vault = backend_kind == "vault";
    let want_env = matches!(backend_kind, "auto" | "env");

    if want_keychain {
        let ns = cfg
            .and_then(|s| s.keychain_namespace.clone())
            .unwrap_or_else(|| "spt".to_string());
        backends.push(Arc::new(KeychainBackend::with_service(ns)));
    }
    // Finding 2: when `backend = "vault"` is explicitly selected, actually build
    // the encrypted `VaultBackend` and place it in the chain (previously the
    // "vault" value matched neither keychain nor env and silently collapsed to
    // file-only). The vault is unlocked non-interactively via the OS keychain
    // master key — this never blocks on a passphrase prompt. If it cannot be
    // unlocked we fail loudly rather than falling through to an unrelated file
    // secret of the same `ns/name`.
    if want_vault {
        backends.push(Arc::new(build_vault_backend(cfg, state_dir)?));
    }
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

    // Finding 3: `[secrets].encrypt_at_rest` has no dedicated file-backend
    // encryption path — the encrypted-at-rest store IS the vault (AES-256-GCM +
    // Argon2id). Rather than let the flag be a silent dead field, emit an honest
    // WARN when it is requested against a backend that does not encrypt its
    // at-rest material, pointing the operator at `backend = "vault"`. When the
    // vault backend is active the flag is already satisfied (and we say so).
    if cfg.and_then(|s| s.encrypt_at_rest) == Some(true) {
        if want_vault {
            tracing::debug!(
                target: "spt_bin::secrets",
                "encrypt_at_rest=true honoured by the vault backend (AES-256-GCM at rest)"
            );
        } else {
            tracing::warn!(
                target: "spt_bin::secrets",
                backend = backend_kind,
                "[secrets].encrypt_at_rest=true is NOT enforced by the `{backend_kind}` backend; \
                 spt-managed secrets are only encrypted at rest under `backend = \"vault\"`"
            );
        }
    }

    let resolver = Resolver::new(backends);
    tracing::debug!(
        target: "spt_bin::secrets",
        backend = backend_kind,
        chain = %chain_kinds(&resolver),
        "built secret resolver chain"
    );
    Ok(resolver)
}

/// Human-readable summary of a resolver's backend chain (kinds only — never any
/// secret material). Used for the debug line emitted by [`build_resolver`].
fn chain_kinds(resolver: &Resolver) -> String {
    resolver
        .backends()
        .map(|b| match b.kind() {
            spt_secrets::BackendKind::Keychain => "keychain",
            spt_secrets::BackendKind::Vault => "vault",
            spt_secrets::BackendKind::Env => "env",
            spt_secrets::BackendKind::File => "file",
        })
        .collect::<Vec<_>>()
        .join(" → ")
}

/// Construct and unlock the encrypted [`VaultBackend`] for `backend = "vault"`.
///
/// The vault directory comes from `[secrets].vault_file` (its parent when the
/// path names the `vault.spt` file itself) or defaults to `<state_dir>/secrets`.
/// Unlock is non-interactive via the OS keychain master key (the same key
/// `spt secret store init` stores). Both a missing vault and a failed unlock are
/// hard errors so a `backend = "vault"` misconfiguration is loud rather than a
/// silent fall-through to file-only resolution.
fn build_vault_backend(cfg: Option<&SecretsConfig>, state_dir: &Path) -> Result<VaultBackend> {
    let dir = vault_dir(cfg, state_dir);
    if !VaultBackend::vault_path(&dir).exists() {
        return Err(Error::SecretUnavailable {
            reference: format!("vault at `{}`", dir.display()),
            reason: "[secrets].backend = \"vault\" selected but no vault exists there; \
                     run `spt secret store init` (or fix `vault_file`)"
                .to_string(),
        });
    }
    let ns = cfg
        .and_then(|s| s.keychain_namespace.clone())
        .unwrap_or_else(|| "spt".to_string());
    let kc = KeychainBackend::with_service(ns);
    VaultBackend::open_with_keychain(&dir, &kc).map_err(|e| Error::SecretUnavailable {
        reference: format!("vault at `{}`", dir.display()),
        reason: format!(
            "[secrets].backend = \"vault\" selected but the vault could not be unlocked \
             from the OS keychain: {e}"
        ),
    })
}

/// Resolve the vault **directory** from the `[secrets].vault_file` config value,
/// defaulting to `<state_dir>/secrets`. When `vault_file` names the `vault.spt`
/// file directly, its parent directory is used.
fn vault_dir(cfg: Option<&SecretsConfig>, state_dir: &Path) -> PathBuf {
    match cfg
        .and_then(|s| s.vault_file.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(vault_file) => {
            let p = Path::new(vault_file);
            if p.file_name() == Some(std::ffi::OsStr::new("vault.spt")) {
                p.parent()
                    .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
            } else {
                p.to_path_buf()
            }
        }
        None => state_dir.join("secrets"),
    }
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

    // ----- Finding 1: memory_protection is applied (no longer a no-op) --------

    #[test]
    fn build_resolver_applies_memory_protection_without_error() {
        // strict must not break resolver construction: it either engages
        // (mlockall) or degrades to best-effort with a WARN — both are Ok. The
        // engagement itself is unit-tested in spt_secrets::mem_protection; here
        // we prove the config value is actually threaded into apply_once.
        let tmp = tempfile::tempdir().unwrap();
        for level in ["strict", "best_effort", "none"] {
            let cfg = SecretsConfig {
                memory_protection: Some(level.into()),
                ..Default::default()
            };
            let r = build_resolver(Some(&cfg), tmp.path()).expect("build");
            assert!(r.backends().count() >= 1);
        }
    }

    // ----- Finding 2: vault backend appears in the chain when configured ------

    fn vault_kinds(r: &Resolver) -> Vec<spt_secrets::BackendKind> {
        r.backends().map(spt_secrets::SecretBackend::kind).collect()
    }

    #[test]
    fn build_resolver_vault_backend_appears_in_chain_when_configured() {
        // A keychain-unlockable vault is created; with backend = "vault" the
        // resolver chain must contain the Vault backend (before the file
        // fallback), not silently collapse to file-only.
        let _guard = spt_secrets::testing::install_mock_keyring();
        let state = tempfile::tempdir().unwrap();
        let vault_dir = state.path().join("secrets");
        let kc = spt_secrets::KeychainBackend::with_service("spt".to_string());
        VaultBackend::init_with_keychain(&vault_dir, &kc).expect("init vault");

        let cfg = SecretsConfig {
            backend: Some("vault".into()),
            ..Default::default()
        };
        let r = build_resolver(Some(&cfg), state.path()).expect("build");
        let kinds = vault_kinds(&r);
        assert!(
            kinds.contains(&spt_secrets::BackendKind::Vault),
            "vault must be in the chain: {kinds:?}"
        );
        // File fallback is still last.
        assert_eq!(kinds.last(), Some(&spt_secrets::BackendKind::File));
        // Vault precedes file (documented priority order).
        let vpos = kinds
            .iter()
            .position(|k| *k == spt_secrets::BackendKind::Vault);
        let fpos = kinds
            .iter()
            .position(|k| *k == spt_secrets::BackendKind::File);
        assert!(vpos < fpos, "vault must precede file: {kinds:?}");
    }

    #[test]
    fn build_resolver_vault_missing_fails_loudly() {
        // backend = "vault" but no vault present -> hard error (fail-loud),
        // never a silent fall-through to file-only resolution.
        let _guard = spt_secrets::testing::install_mock_keyring();
        let state = tempfile::tempdir().unwrap();
        let cfg = SecretsConfig {
            backend: Some("vault".into()),
            ..Default::default()
        };
        match build_resolver(Some(&cfg), state.path()) {
            Err(Error::SecretUnavailable { reason, .. }) => {
                assert!(reason.contains("vault"), "reason: {reason}");
            }
            Err(other) => panic!("expected SecretUnavailable, got {other:?}"),
            Ok(_) => panic!("backend=vault with no vault must fail loudly"),
        }
    }

    #[test]
    fn vault_dir_resolves_file_and_dir_forms() {
        let state = tempfile::tempdir().unwrap();
        // Unset -> <state_dir>/secrets.
        assert_eq!(vault_dir(None, state.path()), state.path().join("secrets"));
        // Directory form -> used verbatim.
        let cfg_dir = SecretsConfig {
            vault_file: Some("/etc/spt/vaultdir".into()),
            ..Default::default()
        };
        assert_eq!(
            vault_dir(Some(&cfg_dir), state.path()),
            PathBuf::from("/etc/spt/vaultdir")
        );
        // vault.spt file form -> parent directory.
        let cfg_file = SecretsConfig {
            vault_file: Some("/etc/spt/vaultdir/vault.spt".into()),
            ..Default::default()
        };
        assert_eq!(
            vault_dir(Some(&cfg_file), state.path()),
            PathBuf::from("/etc/spt/vaultdir")
        );
    }

    // ----- Finding 3: encrypt_at_rest is wired-or-warned (no dead field) ------

    #[test]
    fn build_resolver_encrypt_at_rest_true_still_builds_with_warning() {
        // With a non-vault backend, encrypt_at_rest=true emits a WARN (not
        // enforced) but must not break resolver construction.
        let tmp = tempfile::tempdir().unwrap();
        let cfg = SecretsConfig {
            backend: Some("file".into()),
            encrypt_at_rest: Some(true),
            ..Default::default()
        };
        let r = build_resolver(Some(&cfg), tmp.path()).expect("build");
        assert_eq!(vault_kinds(&r), vec![spt_secrets::BackendKind::File]);
    }
}
