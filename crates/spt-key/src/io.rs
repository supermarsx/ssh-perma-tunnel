//! Key generation, OpenSSH PEM I/O, and passphrase management.

use std::fs;
use std::path::Path;

use atomicwrites::{AtomicFile, OverwriteBehavior};
use rand::rngs::OsRng;
use ssh_key::{LineEnding, PrivateKey};

use spt_core::{Error, Result};

use crate::algorithm::KeyAlgorithm;
use crate::keypair::KeyPair;

/// Generate a fresh key pair.
///
/// Uses the OS RNG (`getrandom`) for all algorithms. Equivalent to
/// `ssh-keygen -t <alg>` for the chosen algorithm and (for RSA) bit size.
pub fn generate(alg: KeyAlgorithm) -> Result<KeyPair> {
    let private = match alg {
        KeyAlgorithm::Rsa3072 | KeyAlgorithm::Rsa4096 => {
            let bits = alg.rsa_bits().unwrap_or(4096);
            let rsa = ssh_key::private::RsaKeypair::random(&mut OsRng, bits).map_err(map_err)?;
            let kd = ssh_key::private::KeypairData::from(rsa);
            PrivateKey::new(kd, "spt").map_err(map_err)?
        }
        _ => PrivateKey::random(&mut OsRng, alg.to_ssh_key()).map_err(map_err)?,
    };
    Ok(KeyPair::from_private(private))
}

/// Encode the keypair as OpenSSH PEM and write atomically to `path`.
///
/// When `passphrase` is `Some(_)` the key is encrypted with the OpenSSH default
/// cipher (`aes256-ctr`) and bcrypt KDF. Atomic write semantics guarantee no
/// half-written file is observed by readers.
pub fn save_encrypted(kp: &KeyPair, path: &Path, passphrase: Option<&str>) -> Result<()> {
    let encoded = match passphrase {
        Some(pw) if !pw.is_empty() => {
            let encrypted = kp
                .private()
                .encrypt(&mut OsRng, pw.as_bytes())
                .map_err(map_err)?;
            encrypted.to_openssh(LineEnding::LF).map_err(map_err)?
        }
        _ => kp.private().to_openssh(LineEnding::LF).map_err(map_err)?,
    };

    let af = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
    af.write(|f| {
        use std::io::Write;
        f.write_all(encoded.as_bytes())
    })
    .map_err(|e| {
        Error::RuntimeFailure(format!("atomic write of `{}` failed: {e}", path.display()))
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Load a (possibly encrypted) OpenSSH-format private key from `path`.
pub fn load(path: &Path, passphrase: Option<&str>) -> Result<KeyPair> {
    let pem = fs::read_to_string(path)
        .map_err(|e| Error::RuntimeFailure(format!("read `{}`: {e}", path.display())))?;
    let mut pk = PrivateKey::from_openssh(&pem).map_err(map_err)?;
    if pk.is_encrypted() {
        let pw = passphrase.ok_or_else(|| {
            Error::InvalidArgs(format!(
                "key `{}` is encrypted but no passphrase was supplied",
                path.display()
            ))
        })?;
        pk = pk.decrypt(pw.as_bytes()).map_err(|_| {
            Error::AuthFailed(format!("incorrect passphrase for `{}`", path.display()))
        })?;
    }
    Ok(KeyPair::from_private(pk))
}

/// Change (or remove) the passphrase on an existing on-disk key.
///
/// Procedure:
/// 1. Load + decrypt with `old`.
/// 2. Re-encrypt with `new` (or strip encryption when `new` is `None`/empty).
/// 3. Write a backup at `<path>.bak` (rename of the original).
/// 4. Atomically write the new key.
///
/// On failure the backup file is left in place so no key material is lost.
pub fn change_passphrase(path: &Path, old: Option<&str>, new: Option<&str>) -> Result<()> {
    let kp = load(path, old)?;

    let backup = with_extension_appended(path, "bak");
    if path.exists() {
        // best-effort: copy first, then rename original to .bak so the
        // backup survives even if AtomicFile fails on a hostile filesystem.
        fs::copy(path, &backup).map_err(|e| {
            Error::RuntimeFailure(format!(
                "could not write backup `{}`: {e}",
                backup.display()
            ))
        })?;
    }

    save_encrypted(&kp, path, new)?;
    Ok(())
}

fn with_extension_appended(path: &Path, ext: &str) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    s.into()
}

#[allow(clippy::needless_pass_by_value)]
fn map_err(e: ssh_key::Error) -> Error {
    Error::InvalidConfig(format!("ssh-key: {e}"))
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::fingerprint::fingerprint_sha256;

    #[test]
    fn ed25519_roundtrip() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_ed25519");

        let fp = fingerprint_sha256(kp.public_ref());
        save_encrypted(&kp, &p, Some("hunter2")).unwrap();

        // wrong passphrase fails
        assert!(load(&p, Some("wrong")).is_err());
        // correct passphrase succeeds
        let loaded = load(&p, Some("hunter2")).unwrap();
        assert_eq!(fingerprint_sha256(loaded.public_ref()), fp);
    }

    #[test]
    fn unencrypted_save_load() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_plain");
        save_encrypted(&kp, &p, None).unwrap();
        let loaded = load(&p, None).unwrap();
        assert_eq!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp.public_ref())
        );
    }

    #[test]
    fn change_passphrase_creates_backup() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id");
        save_encrypted(&kp, &p, Some("old")).unwrap();
        change_passphrase(&p, Some("old"), Some("new")).unwrap();
        let bak = with_extension_appended(&p, "bak");
        assert!(bak.exists());
        let _loaded = load(&p, Some("new")).unwrap();
        assert!(load(&p, Some("old")).is_err());
    }

    #[test]
    fn ecdsa_p256_roundtrip() {
        let kp = generate(KeyAlgorithm::EcdsaP256).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_ecdsa");
        save_encrypted(&kp, &p, None).unwrap();
        load(&p, None).unwrap();
    }

    // RSA tests are gated since RSA keygen is slow (~few seconds).
    #[test]
    #[ignore = "RSA-3072 keygen is slow (~5s+)"]
    fn rsa_3072_roundtrip() {
        let kp = generate(KeyAlgorithm::Rsa3072).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_rsa");
        save_encrypted(&kp, &p, None).unwrap();
        load(&p, None).unwrap();
    }
}
