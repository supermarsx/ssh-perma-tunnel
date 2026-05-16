//! End-to-end lifecycle test for [`spt_secrets::VaultBackend`].
//!
//! These tests drive the vault entirely through its public passphrase API
//! so they do not depend on the in-process keyring mock and therefore do
//! not need the `testing` feature enabled. They exercise:
//!
//! * `init_with_passphrase` → `set` → drop → `open_with_passphrase` → `get`
//! * Multi-namespace `list` and `list_refs(Some(ns))`
//! * `remove` and re-`list`
//! * Persistence of `VaultMeta` across opens
//! * Resolver integration: `Resolver::new(vec![VaultBackend])` resolves
//!   stored references and returns `SecretUnavailable` for missing ones.

use std::sync::Arc;

use secrecy::ExposeSecret;
use spt_core::Error;
use spt_secrets::{FileBackend, Resolver, SecretBackend, SecretBytes, SecretRef, VaultBackend};
use tempfile::tempdir;

fn unwrap_bytes(b: &SecretBytes) -> Vec<u8> {
    b.expose_secret().to_vec()
}

#[test]
fn full_passphrase_lifecycle() {
    let dir = tempdir().unwrap();
    let passphrase: &[u8] = b"correct horse battery staple";

    // Initialize a brand-new vault.
    let v = VaultBackend::init_with_passphrase(dir.path(), passphrase).unwrap();

    // Populate two namespaces.
    let r_a = SecretRef::new("alpha", "token").unwrap();
    let r_b = SecretRef::new("alpha", "session").unwrap();
    let r_c = SecretRef::new("beta", "key").unwrap();
    v.set(&r_a, b"a-value").unwrap();
    v.set(&r_b, b"b-value").unwrap();
    v.set(&r_c, b"c-value").unwrap();

    // Verify list contents.
    let mut listed = v.list().unwrap();
    listed.sort_by_key(ToString::to_string);
    assert_eq!(listed, vec![r_b.clone(), r_a.clone(), r_c.clone()]);

    // Filter by namespace.
    let mut alpha = v.list_refs(Some("alpha")).unwrap();
    alpha.sort_by_key(ToString::to_string);
    assert_eq!(alpha, vec![r_b.clone(), r_a.clone()]);

    let beta = v.list_refs(Some("beta")).unwrap();
    assert_eq!(beta, vec![r_c.clone()]);

    // None-filter returns every entry.
    let all = v.list_refs(None).unwrap();
    assert_eq!(all.len(), 3);

    // Drop the vault handle and reopen with the same passphrase.
    drop(v);
    let v2 = VaultBackend::open_with_passphrase(dir.path(), passphrase).unwrap();
    assert_eq!(
        unwrap_bytes(&v2.get(&r_a).unwrap().unwrap()),
        b"a-value".to_vec()
    );

    // Remove one record and confirm.
    assert!(v2.remove(&r_b).unwrap());
    assert!(!v2.remove(&r_b).unwrap());
    assert!(v2.get(&r_b).unwrap().is_none());

    let mut after_remove = v2.list().unwrap();
    after_remove.sort_by_key(ToString::to_string);
    assert_eq!(after_remove, vec![r_a, r_c]);
}

#[test]
fn vault_resolves_through_resolver_chain() {
    let dir = tempdir().unwrap();
    let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
    let r = SecretRef::new("auth", "bearer").unwrap();
    v.set(&r, b"deadbeef").unwrap();

    // Place the vault in a resolver chain alongside an empty file backend
    // to ensure fall-through semantics: the file backend has nothing and
    // returns `Ok(None)`, so the vault is consulted next and wins.
    let empty_root = tempdir().unwrap();
    let file: Arc<dyn SecretBackend> = Arc::new(FileBackend::new(empty_root.path()));
    let vault: Arc<dyn SecretBackend> = Arc::new(v);
    let resolver = Resolver::new(vec![file, vault]);

    let got = resolver.resolve(&r).unwrap();
    assert_eq!(got.expose_secret().as_slice(), b"deadbeef");

    let missing = SecretRef::new("auth", "absent").unwrap();
    let err = resolver.resolve(&missing).unwrap_err();
    match err {
        Error::SecretUnavailable { reference, reason } => {
            assert_eq!(reference, "secret://auth/absent");
            // The chain description names both backends.
            assert!(reason.contains("file"));
            assert!(reason.contains("vault"));
        }
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn wrong_passphrase_decrypts_to_authentication_failure() {
    let dir = tempdir().unwrap();
    let v = VaultBackend::init_with_passphrase(dir.path(), b"correct").unwrap();
    let r = SecretRef::new("ns", "n").unwrap();
    v.set(&r, b"payload").unwrap();
    drop(v);

    // Opening with a different passphrase derives a different AES key, so
    // any subsequent `get` must surface `SecretCryptoFailed`.
    let v2 = VaultBackend::open_with_passphrase(dir.path(), b"wrong").unwrap();
    let err = v2.get(&r).unwrap_err();
    assert!(matches!(err, Error::SecretCryptoFailed(_)));
}

#[test]
fn vault_meta_persists_across_opens() {
    let dir = tempdir().unwrap();
    let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
    let meta_path = VaultBackend::meta_path(dir.path());
    assert!(meta_path.exists());

    // Reopen and verify meta is readable.
    drop(v);
    let _v2 = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap();
    assert!(meta_path.exists());
}

#[test]
fn vault_path_helpers_compute_layout() {
    let base = std::path::Path::new("/spt/state/secrets");
    let vp = VaultBackend::vault_path(base);
    let mp = VaultBackend::meta_path(base);
    assert!(vp.ends_with("vault.spt"));
    assert!(mp.ends_with("vault.spt.meta"));
}
