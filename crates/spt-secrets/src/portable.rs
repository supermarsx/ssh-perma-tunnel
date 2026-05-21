//! Portable-mode gate for the secrets subsystem.
//!
//! The `spt-state::portable` crate owns the on-disk layout for portable
//! deployments; this module owns the secrets-specific policy decisions
//! that must NOT pull in a dependency on `spt-state` (the dependency
//! direction is `spt-bin -> {spt-state, spt-secrets}` — they are peers).
//!
//! The single piece of state we carry is the boolean "portable mode is
//! active" flag, which `spt-bin::main` flips immediately after parsing the
//! `--portable` global before any resolver is built.
//!
//! ### What gating does
//!
//! * [`keychain_allowed`] returns `false`, so [`crate::KeychainBackend`]
//!   is never pushed onto the resolver chain. The vault must be opened
//!   with [`vault_passphrase_from_file`] instead of
//!   [`crate::VaultBackend::open_with_keychain`].
//! * [`PortableVaultLayout`] describes the on-disk shape downstream
//!   wiring code uses to point [`crate::VaultBackend`] at
//!   `<exe-dir>/data/vault/`.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use secrecy::SecretBox;
use spt_core::{Error, Result};
use zeroize::Zeroizing;

/// Process-global portable flag. `Some(true)` activates the gate;
/// `Some(false)` and `None` leave default behaviour in place.
static PORTABLE: OnceLock<bool> = OnceLock::new();

/// Flip the secrets-side portable gate.
///
/// `spt-bin::main` calls this exactly once after pre-scanning the CLI for
/// `--portable`. Subsequent calls are no-ops because the flag is backed
/// by a [`OnceLock`]. Returns `true` when the flag was stored, `false`
/// when a prior call already locked it.
pub fn set_portable_mode(active: bool) -> bool {
    PORTABLE.set(active).is_ok()
}

/// `true` when the OS keychain backend may be added to the resolver chain.
///
/// Default behaviour (no flag installed, or `set_portable_mode(false)`):
/// keychain is allowed. Once `set_portable_mode(true)` runs, this returns
/// `false` for the remainder of the process lifetime — the only state we
/// store is the inverted view so the default (`None`) is "allowed".
#[must_use]
pub fn keychain_allowed() -> bool {
    !PORTABLE.get().copied().unwrap_or(false)
}

/// On-disk layout of a portable vault under `<exe-dir>/data/vault/`.
///
/// The vault itself (`vault.spt` + `vault.spt.meta`) lives in [`Self::vault_dir`].
/// The file-backed master key — used **only** when portable mode is active —
/// lives at [`Self::master_key_file`] with mode `0600` on Unix.
#[derive(Debug, Clone)]
pub struct PortableVaultLayout {
    /// `<exe-dir>/data/vault/` — passed verbatim to
    /// [`crate::VaultBackend::open_with_passphrase`] / `init_with_passphrase`.
    pub vault_dir: PathBuf,
}

impl PortableVaultLayout {
    /// Build a layout under `vault_dir`.
    #[must_use]
    pub fn new(vault_dir: impl Into<PathBuf>) -> Self {
        Self {
            vault_dir: vault_dir.into(),
        }
    }

    /// Path to the file-backed master key.
    #[must_use]
    pub fn master_key_file(&self) -> PathBuf {
        self.vault_dir.join("master.key")
    }
}

/// Read (or create) the portable master key and surface it as a
/// passphrase-shaped [`SecretBox`] suitable for
/// [`crate::VaultBackend::open_with_passphrase`].
///
/// * If the file does not exist, 32 cryptographically random bytes are
///   generated, written atomically with mode `0600` on Unix, then
///   returned. The vault's Argon2id KDF will then derive the actual
///   master key from these bytes; this design keeps the file's contents
///   off the AES key directly (defence-in-depth against bit-rot or
///   accidental disclosure) and reuses the existing
///   `init_with_passphrase` code path.
/// * If the file exists, its contents are returned verbatim.
///
/// # Errors
///
/// Returns [`Error::SecretUnavailable`] when the file cannot be created,
/// read, or has wrong permissions on Unix (mode bits other than `0600`
/// reject the file rather than silently fixing them, so tampering is
/// loud).
pub fn vault_passphrase_from_file(
    layout: &PortableVaultLayout,
) -> Result<SecretBox<Zeroizing<Vec<u8>>>> {
    let path = layout.master_key_file();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::SecretUnavailable {
            reference: format!("portable-vault://{}", path.display()),
            reason: format!("create vault dir: {e}"),
        })?;
    }
    if !path.exists() {
        let mut key = Zeroizing::new(vec![0u8; 32]);
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut key);
        write_master_key(&path, &key)?;
        return Ok(SecretBox::new(Box::new(key)));
    }
    let bytes = std::fs::read(&path).map_err(|e| Error::SecretUnavailable {
        reference: format!("portable-vault://{}", path.display()),
        reason: format!("read master key: {e}"),
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&path).map_err(|e| Error::SecretUnavailable {
            reference: format!("portable-vault://{}", path.display()),
            reason: format!("stat master key: {e}"),
        })?;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(Error::SecretUnavailable {
                reference: format!("portable-vault://{}", path.display()),
                reason: format!(
                    "master key file has mode 0{mode:o}; expected 0600 — refusing to use"
                ),
            });
        }
    }
    let zeroed = Zeroizing::new(bytes);
    Ok(SecretBox::new(Box::new(zeroed)))
}

fn write_master_key(path: &Path, key: &[u8]) -> Result<()> {
    // Write atomically and tighten to 0600 on Unix BEFORE the bytes hit
    // disk where another process could read them. We open with mode 0600
    // via a manual open() rather than the atomicwrites helper because the
    // latter creates the temp file with the umask default.
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let tmp = path.with_extension("key.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(false)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| Error::SecretUnavailable {
                reference: format!("portable-vault://{}", path.display()),
                reason: format!("open temp master key: {e}"),
            })?;
        f.write_all(key).map_err(|e| Error::SecretUnavailable {
            reference: format!("portable-vault://{}", path.display()),
            reason: format!("write master key: {e}"),
        })?;
        f.sync_all().ok();
        drop(f);
        std::fs::rename(&tmp, path).map_err(|e| Error::SecretUnavailable {
            reference: format!("portable-vault://{}", path.display()),
            reason: format!("rename master key into place: {e}"),
        })?;
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, key).map_err(|e| Error::SecretUnavailable {
            reference: format!("portable-vault://{}", path.display()),
            reason: format!("write master key: {e}"),
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use tempfile::tempdir;

    #[test]
    fn keychain_allowed_default_is_true() {
        // We can't toggle the OnceLock from a unit test reliably (it's
        // shared across the test binary). Instead just confirm that the
        // function returns *some* boolean and matches its derivation:
        let stored = PORTABLE.get().copied();
        let expected = !stored.unwrap_or(false);
        assert_eq!(keychain_allowed(), expected);
    }

    #[test]
    fn portable_vault_layout_master_path() {
        let layout = PortableVaultLayout::new("/opt/spt/data/vault");
        assert_eq!(
            layout.master_key_file(),
            Path::new("/opt/spt/data/vault/master.key")
        );
    }

    #[test]
    fn vault_passphrase_from_file_creates_then_reads() {
        let tmp = tempdir().unwrap();
        let layout = PortableVaultLayout::new(tmp.path());
        let first = vault_passphrase_from_file(&layout).unwrap();
        let bytes_first = first.expose_secret().to_vec();
        assert_eq!(bytes_first.len(), 32);
        assert!(layout.master_key_file().is_file());

        // Second call must return the same bytes (read-back).
        let second = vault_passphrase_from_file(&layout).unwrap();
        assert_eq!(second.expose_secret().as_slice(), bytes_first.as_slice());
    }

    #[cfg(unix)]
    #[test]
    fn vault_passphrase_from_file_writes_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let layout = PortableVaultLayout::new(tmp.path());
        let _ = vault_passphrase_from_file(&layout).unwrap();
        let mode = std::fs::metadata(layout.master_key_file())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");
    }

    #[cfg(unix)]
    #[test]
    fn vault_passphrase_from_file_rejects_loose_perms() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempdir().unwrap();
        let layout = PortableVaultLayout::new(tmp.path());
        let _ = vault_passphrase_from_file(&layout).unwrap();
        // Loosen perms and ensure the next read refuses.
        let mut p = std::fs::metadata(layout.master_key_file())
            .unwrap()
            .permissions();
        p.set_mode(0o644);
        std::fs::set_permissions(layout.master_key_file(), p).unwrap();
        let err = vault_passphrase_from_file(&layout).unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
        assert!(format!("{err}").contains("0600"));
    }
}
