//! Local file-backed encrypted vault.
//!
//! Layout on disk:
//!
//! * `vault.spt` — binary blob, JSON-encoded `VaultFile { records:
//!   { "<ns>/<name>": { nonce, ciphertext } } }`. Each record's
//!   `ciphertext` is AES-256-GCM over the plaintext, with AAD =
//!   `ns || 0x00 || name`.
//! * `vault.spt.meta` — TOML sidecar holding format version, KDF
//!   parameters, and a salt for the passphrase fallback.
//!
//! Master key resolution (in order):
//!
//! 1. The OS keychain entry `(service = "spt", account = "vault-master")`.
//!    Stored as 32 raw bytes.
//! 2. A passphrase-derived key. The passphrase is supplied at vault open
//!    time; Argon2id with parameters from `.meta` derives 32 bytes.
//!
//! On `init`, a fresh master key is generated and stored in the keychain
//! when available, otherwise the caller must supply a passphrase.

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Argon2, Params};
use atomicwrites::{AllowOverwrite, AtomicFile};
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use spt_core::{Error, Result};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use crate::backend::{secret_bytes, BackendDoctor, BackendKind, SecretBackend, SecretBytes};
use crate::keychain::KeychainBackend;
use crate::reference::SecretRef;

/// Vault format major version. Bump when on-disk layout changes
/// incompatibly.
pub const FORMAT_VERSION: u32 = 1;

/// AES-256-GCM nonce length.
const NONCE_LEN: usize = 12;
/// Master-key length (AES-256).
const KEY_LEN: usize = 32;
/// Passphrase salt length.
const SALT_LEN: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
struct VaultFile {
    /// Map from `"ns/name"` to record.
    records: BTreeMap<String, Record>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    /// Hex-encoded 12-byte nonce.
    nonce: String,
    /// Hex-encoded ciphertext (includes 16-byte GCM tag).
    ciphertext: String,
}

/// Sidecar metadata kept next to `vault.spt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultMeta {
    /// Format version of the vault file.
    pub version: u32,
    /// Argon2id parameters used for the passphrase fallback.
    pub argon2: Argon2Params,
    /// Hex-encoded salt for the passphrase KDF.
    pub salt_hex: String,
    /// `true` once a master key has been provisioned (either keychain or
    /// passphrase). Doctor uses this to surface "vault initialized" state.
    pub initialized: bool,
}

/// Argon2id parameters serialized in the meta file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Time cost (iterations).
    pub time_cost: u32,
    /// Parallelism (lanes).
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        // OWASP-recommended baseline as of Argon2id v1.3 (m=64MiB, t=3, p=4).
        Self {
            memory_kib: 64 * 1024,
            time_cost: 3,
            parallelism: 4,
        }
    }
}

/// Master-key source for [`VaultBackend`].
pub enum MasterKey {
    /// 32-byte raw key already in memory (typically loaded from the
    /// keychain by [`VaultBackend::open_with_keychain`]).
    Raw(SecretBox<Zeroizing<[u8; KEY_LEN]>>),
}

impl MasterKey {
    fn cipher(&self) -> Aes256Gcm {
        match self {
            Self::Raw(k) => Aes256Gcm::new(k.expose_secret().as_ref().into()),
        }
    }
}

/// File-backed encrypted vault.
///
/// `Debug` is implemented manually to avoid leaking the master key or any
/// record material — only the on-disk paths and the meta version are
/// shown.
pub struct VaultBackend {
    vault_path: PathBuf,
    /// Retained so `rotate_master_key` and future migrations can rewrite
    /// `vault.spt.meta` without re-deriving its location.
    #[allow(dead_code)]
    meta_path: PathBuf,
    master: MasterKey,
    meta: VaultMeta,
}

impl std::fmt::Debug for VaultBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultBackend")
            .field("vault_path", &self.vault_path)
            .field("meta_path", &self.meta_path)
            .field("version", &self.meta.version)
            .field("master", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl VaultBackend {
    /// Path to the vault binary file given a directory.
    #[must_use]
    pub fn vault_path(dir: &Path) -> PathBuf {
        dir.join("vault.spt")
    }

    /// Path to the vault metadata sidecar given a directory.
    #[must_use]
    pub fn meta_path(dir: &Path) -> PathBuf {
        dir.join("vault.spt.meta")
    }

    /// Initialize a fresh vault on disk, generating a 32-byte master key
    /// and storing it in the OS keychain. Fails if a vault already exists.
    pub fn init_with_keychain(dir: &Path, keychain: &KeychainBackend) -> Result<Self> {
        let vault_path = Self::vault_path(dir);
        let meta_path = Self::meta_path(dir);
        if vault_path.exists() || meta_path.exists() {
            return Err(Error::SecretCryptoFailed(format!(
                "vault already exists at `{}`",
                dir.display()
            )));
        }
        fs::create_dir_all(dir).map_err(|e| {
            Error::SecretCryptoFailed(format!("create vault dir `{}`: {e}", dir.display()))
        })?;

        // Generate fresh master key.
        let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
        rand::thread_rng().fill_bytes(key_bytes.as_mut());

        // Store in keychain.
        let entry = keychain.master_entry()?;
        entry
            .set_secret(key_bytes.as_ref())
            .map_err(|e| Error::SecretCryptoFailed(format!("store master key: {e}")))?;

        // Build meta with fresh salt.
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let meta = VaultMeta {
            version: FORMAT_VERSION,
            argon2: Argon2Params::default(),
            salt_hex: hex::encode(salt),
            initialized: true,
        };

        // Write empty vault + meta.
        write_vault(
            &vault_path,
            &VaultFile {
                records: BTreeMap::new(),
            },
        )?;
        write_meta(&meta_path, &meta)?;

        Ok(Self {
            vault_path,
            meta_path,
            master: MasterKey::Raw(SecretBox::new(Box::new(key_bytes))),
            meta,
        })
    }

    /// Open an existing vault using the master key stored in the keychain.
    pub fn open_with_keychain(dir: &Path, keychain: &KeychainBackend) -> Result<Self> {
        let meta = read_meta(&Self::meta_path(dir))?;
        let entry = keychain.master_entry()?;
        let raw = entry.get_secret().map_err(|e| match e {
            keyring::Error::NoEntry => Error::SecretCryptoFailed(
                "vault master key not present in keychain; run `spt secret store init`".into(),
            ),
            other => Error::SecretCryptoFailed(format!("load master key: {other}")),
        })?;
        if raw.len() != KEY_LEN {
            return Err(Error::SecretCryptoFailed(format!(
                "master key in keychain has wrong length {} (expected {KEY_LEN})",
                raw.len()
            )));
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&raw);
        Ok(Self {
            vault_path: Self::vault_path(dir),
            meta_path: Self::meta_path(dir),
            master: MasterKey::Raw(SecretBox::new(Box::new(key))),
            meta,
        })
    }

    /// Open an existing vault using a passphrase.
    pub fn open_with_passphrase(dir: &Path, passphrase: &[u8]) -> Result<Self> {
        let meta = read_meta(&Self::meta_path(dir))?;
        let key = derive_key(passphrase, &meta)?;
        Ok(Self {
            vault_path: Self::vault_path(dir),
            meta_path: Self::meta_path(dir),
            master: MasterKey::Raw(SecretBox::new(Box::new(key))),
            meta,
        })
    }

    /// Initialize a fresh vault on disk using a passphrase as the only key
    /// source. Useful for headless deployments without a keychain.
    pub fn init_with_passphrase(dir: &Path, passphrase: &[u8]) -> Result<Self> {
        let vault_path = Self::vault_path(dir);
        let meta_path = Self::meta_path(dir);
        if vault_path.exists() || meta_path.exists() {
            return Err(Error::SecretCryptoFailed(format!(
                "vault already exists at `{}`",
                dir.display()
            )));
        }
        fs::create_dir_all(dir).map_err(|e| {
            Error::SecretCryptoFailed(format!("create vault dir `{}`: {e}", dir.display()))
        })?;
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let meta = VaultMeta {
            version: FORMAT_VERSION,
            argon2: Argon2Params::default(),
            salt_hex: hex::encode(salt),
            initialized: true,
        };
        let key = derive_key(passphrase, &meta)?;
        write_vault(
            &vault_path,
            &VaultFile {
                records: BTreeMap::new(),
            },
        )?;
        write_meta(&meta_path, &meta)?;
        Ok(Self {
            vault_path,
            meta_path,
            master: MasterKey::Raw(SecretBox::new(Box::new(key))),
            meta,
        })
    }

    /// Return a copy of the 32-byte vault master key for config sealing.
    ///
    /// The returned buffer zeroizes on drop. This is intended for
    /// `spt-config-crypt`'s vault-master KDF only; callers must not log,
    /// persist, or expose the returned bytes.
    #[must_use]
    pub fn config_crypt_master_key(&self) -> Zeroizing<[u8; 32]> {
        match &self.master {
            MasterKey::Raw(key) => {
                let mut out = [0u8; 32];
                out.copy_from_slice(key.expose_secret().as_ref());
                Zeroizing::new(out)
            }
        }
    }

    /// Replace the master key, re-encrypting every record. The new key is
    /// stored in the keychain via `keychain.master_entry()`.
    pub fn rotate_master_key(&mut self, keychain: &KeychainBackend) -> Result<()> {
        // Decrypt every record under the current key.
        let file = read_vault(&self.vault_path)?;
        let cipher = self.master.cipher();
        let mut decrypted: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        for (k, rec) in &file.records {
            let (ns, name) = split_key(k)?;
            let aad = aad_bytes(ns, name);
            let nonce_bytes = hex::decode(&rec.nonce)
                .map_err(|e| Error::SecretCryptoFailed(format!("decode nonce: {e}")))?;
            let ct = hex::decode(&rec.ciphertext)
                .map_err(|e| Error::SecretCryptoFailed(format!("decode ct: {e}")))?;
            let pt = cipher
                .decrypt(
                    Nonce::from_slice(&nonce_bytes),
                    Payload {
                        msg: &ct,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::SecretCryptoFailed(format!("decrypt `{k}` failed")))?;
            decrypted.insert(k.clone(), pt);
        }

        // Generate fresh master key.
        let mut new_key = Zeroizing::new([0u8; KEY_LEN]);
        rand::thread_rng().fill_bytes(new_key.as_mut());
        let new_cipher = Aes256Gcm::new(new_key.as_ref().into());

        // Re-encrypt every record under the new key.
        let mut new_records: BTreeMap<String, Record> = BTreeMap::new();
        for (k, pt) in decrypted {
            let (ns, name) = split_key(&k)?;
            let aad = aad_bytes(ns, name);
            let mut nonce = [0u8; NONCE_LEN];
            rand::thread_rng().fill_bytes(&mut nonce);
            let ct = new_cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &pt,
                        aad: &aad,
                    },
                )
                .map_err(|_| Error::SecretCryptoFailed("encrypt failed".into()))?;
            new_records.insert(
                k,
                Record {
                    nonce: hex::encode(nonce),
                    ciphertext: hex::encode(ct),
                },
            );
        }

        // Persist new vault file and master key.
        write_vault(
            &self.vault_path,
            &VaultFile {
                records: new_records,
            },
        )?;
        let entry = keychain.master_entry()?;
        entry
            .set_secret(new_key.as_ref())
            .map_err(|e| Error::SecretCryptoFailed(format!("store rotated master key: {e}")))?;

        self.master = MasterKey::Raw(SecretBox::new(Box::new(new_key)));
        Ok(())
    }

    fn read(&self) -> Result<VaultFile> {
        read_vault(&self.vault_path)
    }

    fn write(&self, file: &VaultFile) -> Result<()> {
        write_vault(&self.vault_path, file)
    }

    /// Enumerate stored secret references, optionally filtered to a single
    /// namespace.
    ///
    /// Decryption is **not** performed — only the on-disk record keys are
    /// inspected, so this method never materialises plaintext. A `None`
    /// `namespace` returns every entry in the vault; a `Some(ns)` filter
    /// only matches records whose namespace equals `ns` exactly.
    ///
    /// Order is undefined but stable for a given vault state (`BTreeMap`
    /// iteration order on the encoded `"<ns>/<name>"` keys).
    pub fn list_refs(&self, namespace: Option<&str>) -> Result<Vec<SecretRef>> {
        let file = self.read()?;
        let mut out = Vec::with_capacity(file.records.len());
        for k in file.records.keys() {
            let (ns, name) = split_key(k)?;
            if let Some(want) = namespace {
                if ns != want {
                    continue;
                }
            }
            if let Ok(r) = SecretRef::new(ns.to_owned(), name.to_owned()) {
                out.push(r);
            }
        }
        Ok(out)
    }
}

fn key_for(r: &SecretRef) -> String {
    format!("{}/{}", r.ns(), r.name())
}

fn split_key(k: &str) -> Result<(&str, &str)> {
    k.split_once('/').ok_or_else(|| {
        Error::SecretCryptoFailed(format!("vault record key `{k}` is not `<ns>/<name>`"))
    })
}

fn aad_bytes(ns: &str, name: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ns.len() + 1 + name.len());
    aad.extend_from_slice(ns.as_bytes());
    aad.push(0);
    aad.extend_from_slice(name.as_bytes());
    aad
}

fn read_vault(path: &Path) -> Result<VaultFile> {
    if !path.exists() {
        return Ok(VaultFile {
            records: BTreeMap::new(),
        });
    }
    let bytes = fs::read(path)
        .map_err(|e| Error::SecretCryptoFailed(format!("read vault `{}`: {e}", path.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::SecretCryptoFailed(format!("parse vault `{}`: {e}", path.display())))
}

fn write_vault(path: &Path, file: &VaultFile) -> Result<()> {
    let bytes = serde_json::to_vec(file)
        .map_err(|e| Error::SecretCryptoFailed(format!("encode vault: {e}")))?;
    // F6: on Windows, ensure the containing directory is owner-only before the
    // vault blob lands, so it is born with a restrictive DACL. No-op on Unix.
    crate::file::restrict_parent_dir(path);
    AtomicFile::new(path, AllowOverwrite)
        .write(|f| std::io::Write::write_all(f, &bytes))
        .map_err(|e| Error::SecretCryptoFailed(format!("write vault `{}`: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    // H2: Windows has no mode bit — restrict the DACL to owner + SYSTEM/
    // Administrators so the encrypted vault is not readable by all local Users
    // when written under a shared path.
    crate::file::restrict_to_owner(path);
    Ok(())
}

fn read_meta(path: &Path) -> Result<VaultMeta> {
    let s = fs::read_to_string(path)
        .map_err(|e| Error::SecretCryptoFailed(format!("read meta `{}`: {e}", path.display())))?;
    toml::from_str(&s)
        .map_err(|e| Error::SecretCryptoFailed(format!("parse meta `{}`: {e}", path.display())))
}

fn write_meta(path: &Path, meta: &VaultMeta) -> Result<()> {
    let s = toml::to_string_pretty(meta)
        .map_err(|e| Error::SecretCryptoFailed(format!("encode meta: {e}")))?;
    // F6: pre-restrict the containing directory on Windows (the meta sidecar
    // carries the Argon2id salt). No-op on Unix.
    crate::file::restrict_parent_dir(path);
    AtomicFile::new(path, AllowOverwrite)
        .write(|f| std::io::Write::write_all(f, s.as_bytes()))
        .map_err(|e| Error::SecretCryptoFailed(format!("write meta `{}`: {e}", path.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    // H2: restrict the meta file's DACL on Windows (carries the Argon2id salt).
    crate::file::restrict_to_owner(path);
    Ok(())
}

fn derive_key(passphrase: &[u8], meta: &VaultMeta) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let salt = hex::decode(&meta.salt_hex)
        .map_err(|e| Error::SecretCryptoFailed(format!("decode salt: {e}")))?;
    let params = Params::new(
        meta.argon2.memory_kib,
        meta.argon2.time_cost,
        meta.argon2.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| Error::SecretCryptoFailed(format!("invalid argon2 params: {e}")))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon2
        .hash_password_into(passphrase, &salt, out.as_mut())
        .map_err(|e| Error::SecretCryptoFailed(format!("argon2 derive: {e}")))?;
    Ok(out)
}

impl SecretBackend for VaultBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Vault
    }

    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        let file = self.read()?;
        let Some(rec) = file.records.get(&key_for(r)) else {
            return Ok(None);
        };
        let nonce = hex::decode(&rec.nonce)
            .map_err(|e| Error::SecretCryptoFailed(format!("decode nonce: {e}")))?;
        let ct = hex::decode(&rec.ciphertext)
            .map_err(|e| Error::SecretCryptoFailed(format!("decode ct: {e}")))?;
        let aad = r.aad();
        let pt = self
            .master
            .cipher()
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &ct,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::SecretCryptoFailed(format!("decrypt `{r}` failed")))?;
        Ok(Some(secret_bytes(pt)))
    }

    fn set(&self, r: &SecretRef, value: &[u8]) -> Result<()> {
        let mut file = self.read()?;
        let mut nonce = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce);
        let aad = r.aad();
        let ct = self
            .master
            .cipher()
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: value,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::SecretCryptoFailed(format!("encrypt `{r}` failed")))?;
        file.records.insert(
            key_for(r),
            Record {
                nonce: hex::encode(nonce),
                ciphertext: hex::encode(ct),
            },
        );
        self.write(&file)
    }

    fn list(&self) -> Result<Vec<SecretRef>> {
        let file = self.read()?;
        let mut out = Vec::with_capacity(file.records.len());
        for k in file.records.keys() {
            let (ns, name) = split_key(k)?;
            if let Ok(r) = SecretRef::new(ns.to_owned(), name.to_owned()) {
                out.push(r);
            }
        }
        Ok(out)
    }

    fn remove(&self, r: &SecretRef) -> Result<bool> {
        let mut file = self.read()?;
        let removed = file.records.remove(&key_for(r)).is_some();
        if removed {
            self.write(&file)?;
        }
        Ok(removed)
    }

    fn doctor(&self) -> BackendDoctor {
        if self.meta.version != FORMAT_VERSION {
            return BackendDoctor::degraded(
                BackendKind::Vault,
                format!(
                    "vault meta version {} is older than current {FORMAT_VERSION}",
                    self.meta.version
                ),
                "run `spt secret store migrate`",
            );
        }
        if self.vault_path.exists() {
            BackendDoctor::ok(
                BackendKind::Vault,
                format!("vault open at `{}`", self.vault_path.display()),
            )
        } else {
            BackendDoctor::degraded(
                BackendKind::Vault,
                format!("vault file `{}` is missing", self.vault_path.display()),
                "run `spt secret store init`",
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use tempfile::tempdir;

    // Keychain-backed tests share the crate's single mock builder + store
    // (`crate::testing::keymock`) rather than a second, private one. Two
    // competing builders would fight over `keyring`'s one global default and
    // race on which store an `Entry` routes to. `install_mock_keyring()`
    // returns a guard that holds a process-wide lock for the whole test body,
    // so every keychain test in this binary runs serially and never observes
    // another test's install/reset mid-run.
    use crate::testing::install_mock_keyring;

    #[test]
    fn round_trip_keychain() {
        let _g = install_mock_keyring();
        let dir = tempdir().unwrap();
        let kc = KeychainBackend::with_service("spt-test-vault");
        let v = VaultBackend::init_with_keychain(dir.path(), &kc).unwrap();
        let r = SecretRef::new("ns", "name").unwrap();
        v.set(&r, b"payload").unwrap();
        let got = v.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"payload");

        // Reopen and read back.
        drop(v);
        let v2 = VaultBackend::open_with_keychain(dir.path(), &kc).unwrap();
        let got = v2.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"payload");
    }

    #[test]
    fn list_and_remove() {
        let _g = install_mock_keyring();
        let dir = tempdir().unwrap();
        let kc = KeychainBackend::with_service("spt-test-vault-list");
        let v = VaultBackend::init_with_keychain(dir.path(), &kc).unwrap();
        let r1 = SecretRef::new("ns1", "a").unwrap();
        let r2 = SecretRef::new("ns2", "b").unwrap();
        v.set(&r1, b"x").unwrap();
        v.set(&r2, b"y").unwrap();
        let mut got = v.list().unwrap();
        got.sort_by_key(ToString::to_string);
        assert_eq!(got, vec![r1.clone(), r2.clone()]);
        assert!(v.remove(&r1).unwrap());
        assert!(!v.remove(&r1).unwrap());
        assert!(v.get(&r1).unwrap().is_none());
    }

    #[test]
    fn aad_binds_record_to_reference() {
        let _g = install_mock_keyring();
        let dir = tempdir().unwrap();
        let kc = KeychainBackend::with_service("spt-test-vault-aad");
        let v = VaultBackend::init_with_keychain(dir.path(), &kc).unwrap();
        let r1 = SecretRef::new("ns", "a").unwrap();
        let r2 = SecretRef::new("ns", "b").unwrap();
        v.set(&r1, b"alpha").unwrap();

        // Surgically copy r1's record to r2's slot to simulate tampering.
        let mut file = v.read().unwrap();
        let stolen = file.records.get(&key_for(&r1)).cloned().unwrap();
        file.records.insert(key_for(&r2), stolen);
        v.write(&file).unwrap();

        // Reading r2 must fail because AAD will not match.
        let err = v.get(&r2).unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn rotate_master_key_preserves_records() {
        let _g = install_mock_keyring();
        let dir = tempdir().unwrap();
        let kc = KeychainBackend::with_service("spt-test-vault-rotate");
        let mut v = VaultBackend::init_with_keychain(dir.path(), &kc).unwrap();
        let r = SecretRef::new("ns", "name").unwrap();
        v.set(&r, b"payload").unwrap();
        v.rotate_master_key(&kc).unwrap();
        let got = v.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"payload");

        // Reopen with the new key from the keychain and read again.
        drop(v);
        let v2 = VaultBackend::open_with_keychain(dir.path(), &kc).unwrap();
        let got = v2.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"payload");
    }

    #[test]
    fn passphrase_round_trip() {
        let dir = tempdir().unwrap();
        // Use very weak Argon2 params for the test or it will be slow.
        // The default params apply; this test uses a tiny passphrase.
        // (Default params produce ~10ms hashes on a modern CPU.)
        let v = VaultBackend::init_with_passphrase(dir.path(), b"correct horse").unwrap();
        let r = SecretRef::new("ns", "n").unwrap();
        v.set(&r, b"x").unwrap();
        drop(v);
        let v2 = VaultBackend::open_with_passphrase(dir.path(), b"correct horse").unwrap();
        let got = v2.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"x");
    }

    #[test]
    fn passphrase_wrong_fails() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"hunter2").unwrap();
        let r = SecretRef::new("ns", "n").unwrap();
        v.set(&r, b"x").unwrap();
        drop(v);
        let v2 = VaultBackend::open_with_passphrase(dir.path(), b"WRONG").unwrap();
        let err = v2.get(&r).unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn list_refs_filters_by_namespace() {
        let _g = install_mock_keyring();
        let dir = tempdir().unwrap();
        let kc = KeychainBackend::with_service("spt-test-vault-list-refs");
        let v = VaultBackend::init_with_keychain(dir.path(), &kc).unwrap();
        let r1 = SecretRef::new("alpha", "one").unwrap();
        let r2 = SecretRef::new("alpha", "two").unwrap();
        let r3 = SecretRef::new("beta", "three").unwrap();
        v.set(&r1, b"x").unwrap();
        v.set(&r2, b"y").unwrap();
        v.set(&r3, b"z").unwrap();

        let mut all = v.list_refs(None).unwrap();
        all.sort_by_key(ToString::to_string);
        assert_eq!(all, vec![r1.clone(), r2.clone(), r3.clone()]);

        let mut alpha = v.list_refs(Some("alpha")).unwrap();
        alpha.sort_by_key(ToString::to_string);
        assert_eq!(alpha, vec![r1.clone(), r2.clone()]);

        let beta = v.list_refs(Some("beta")).unwrap();
        assert_eq!(beta, vec![r3.clone()]);

        let none = v.list_refs(Some("gamma")).unwrap();
        assert!(none.is_empty());
    }

    #[test]
    fn double_init_rejected() {
        let _g = install_mock_keyring();
        let dir = tempdir().unwrap();
        let kc = KeychainBackend::with_service("spt-test-vault-double");
        VaultBackend::init_with_keychain(dir.path(), &kc).unwrap();
        let err = VaultBackend::init_with_keychain(dir.path(), &kc).unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn double_init_passphrase_rejected() {
        let dir = tempdir().unwrap();
        VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        let err = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn open_with_missing_meta_errors() {
        let dir = tempdir().unwrap();
        let err = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn malformed_meta_toml_errors() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let mp = VaultBackend::meta_path(dir.path());
        fs::write(&mp, b"= not toml =").unwrap();
        let err = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn malformed_vault_json_errors() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        fs::write(&v.vault_path, b"not json").unwrap();
        let r = SecretRef::new("ns", "n").unwrap();
        let err = v.get(&r).unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn missing_vault_file_yields_empty_records() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        fs::remove_file(&v.vault_path).unwrap();
        assert!(v.list().unwrap().is_empty());
        assert!(v.list_refs(None).unwrap().is_empty());
    }

    #[test]
    fn record_with_invalid_nonce_hex_errors() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        let r = SecretRef::new("ns", "n").unwrap();
        v.set(&r, b"x").unwrap();
        let mut file = v.read().unwrap();
        let rec = file.records.get_mut(&key_for(&r)).unwrap();
        rec.nonce = "zzz".to_owned();
        v.write(&file).unwrap();
        let err = v.get(&r).unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn record_with_invalid_ciphertext_hex_errors() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        let r = SecretRef::new("ns", "n").unwrap();
        v.set(&r, b"x").unwrap();
        let mut file = v.read().unwrap();
        let rec = file.records.get_mut(&key_for(&r)).unwrap();
        rec.ciphertext = "not hex".to_owned();
        v.write(&file).unwrap();
        let err = v.get(&r).unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn record_with_invalid_key_format_errors_on_list() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        let mut file = v.read().unwrap();
        file.records.insert(
            "no-slash".to_owned(),
            Record {
                nonce: hex::encode([0u8; NONCE_LEN]),
                ciphertext: hex::encode([0u8; 16]),
            },
        );
        v.write(&file).unwrap();
        let err = v.list().unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn doctor_reports_degraded_when_vault_file_missing() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        fs::remove_file(&v.vault_path).unwrap();
        let d = v.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Degraded));
        assert!(d.message.contains("is missing"));
        assert!(d.remediation.is_some());
    }

    #[test]
    fn doctor_reports_degraded_for_old_version() {
        let dir = tempdir().unwrap();
        let mut v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        v.meta.version = 0;
        let d = v.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Degraded));
        assert!(d.message.contains("older"));
    }

    #[test]
    fn doctor_reports_ok_for_initialized_vault() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        let d = v.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Ok));
        assert_eq!(d.kind, BackendKind::Vault);
        assert!(d.message.contains("vault open at"));
    }

    #[test]
    fn debug_redacts_master_key() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        // The actual 32-byte master key derived for this vault. A marker-only
        // assertion ("[REDACTED]" present) would still pass if a second field
        // leaked the real key bytes, so assert the bytes are genuinely ABSENT.
        let key = v.config_crypt_master_key();
        let key_bytes: &[u8] = &key[..];
        assert_eq!(key_bytes.len(), KEY_LEN);

        let s = format!("{v:?}");
        assert!(s.contains("VaultBackend"));
        assert!(s.contains("[REDACTED]"));

        // Not present as a hex encoding...
        let hex_key = hex::encode(key_bytes);
        assert!(
            !s.to_lowercase().contains(&hex_key),
            "master key leaked (hex) in Debug output"
        );
        // ...nor as the raw byte sequence anywhere in the rendered string.
        assert!(
            !s.as_bytes()
                .windows(key_bytes.len())
                .any(|w| w == key_bytes),
            "master key leaked (raw bytes) in Debug output"
        );
    }

    #[test]
    fn argon2_params_default_matches_owasp_baseline() {
        let p = Argon2Params::default();
        assert_eq!(p.memory_kib, 64 * 1024);
        assert_eq!(p.time_cost, 3);
        assert_eq!(p.parallelism, 4);
    }

    #[test]
    fn invalid_argon2_params_in_meta_rejected() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let meta = VaultMeta {
            version: FORMAT_VERSION,
            argon2: Argon2Params {
                memory_kib: 8,
                time_cost: 0,
                parallelism: 1,
            },
            salt_hex: hex::encode([0u8; SALT_LEN]),
            initialized: true,
        };
        write_meta(&VaultBackend::meta_path(dir.path()), &meta).unwrap();
        write_vault(
            &VaultBackend::vault_path(dir.path()),
            &VaultFile {
                records: BTreeMap::new(),
            },
        )
        .unwrap();
        let err = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn invalid_salt_hex_in_meta_rejected() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path()).unwrap();
        let meta = VaultMeta {
            version: FORMAT_VERSION,
            argon2: Argon2Params::default(),
            salt_hex: "not hex".to_owned(),
            initialized: true,
        };
        write_meta(&VaultBackend::meta_path(dir.path()), &meta).unwrap();
        write_vault(
            &VaultBackend::vault_path(dir.path()),
            &VaultFile {
                records: BTreeMap::new(),
            },
        )
        .unwrap();
        let err = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap_err();
        assert!(matches!(err, Error::SecretCryptoFailed(_)));
    }

    #[test]
    fn list_refs_skips_records_with_invalid_segment_chars() {
        let dir = tempdir().unwrap();
        let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
        let mut file = v.read().unwrap();
        file.records.insert(
            "ns/has space".to_owned(),
            Record {
                nonce: hex::encode([0u8; NONCE_LEN]),
                ciphertext: hex::encode([0u8; 16]),
            },
        );
        v.write(&file).unwrap();
        let refs = v.list_refs(None).unwrap();
        assert!(refs.is_empty());
    }
}
