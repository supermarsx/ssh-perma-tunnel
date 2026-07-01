//! Key generation, OpenSSH PEM I/O, and passphrase management.

use std::fs;
use std::path::Path;

#[cfg(not(unix))]
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

    write_secret_file(path, encoded.as_bytes())
}

/// Write `bytes` to `path`, atomically, with `0600` perms from creation on Unix.
///
/// sec-hardening (M5): the secret must NEVER touch disk with broader-than-`0600`
/// permissions, not even for the brief window between an atomic rename and a
/// follow-up `chmod`. On Unix we therefore open a sibling temp file with
/// `.mode(0o600)` BEFORE writing the secret bytes, then rename it into place —
/// mirroring `spt-secrets`' `write_master_key`. The umask can only narrow the
/// mode further, never widen it, so the key is never world-readable. On
/// non-Unix platforms we keep the existing `atomicwrites` behavior (ACL
/// inheritance handles confidentiality there).
fn write_secret_file(path: &Path, bytes: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;

        let tmp = with_extension_appended(path, "tmp");
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| {
                Error::RuntimeFailure(format!("open temp key `{}` failed: {e}", tmp.display()))
            })?;
        f.write_all(bytes).map_err(|e| {
            Error::RuntimeFailure(format!("write temp key `{}` failed: {e}", tmp.display()))
        })?;
        f.sync_all().ok();
        drop(f);
        fs::rename(&tmp, path).map_err(|e| {
            // best-effort cleanup of the temp file so a failed rename doesn't
            // leave a stray (0600) secret behind.
            let _ = fs::remove_file(&tmp);
            Error::RuntimeFailure(format!(
                "atomic rename of `{}` -> `{}` failed: {e}",
                tmp.display(),
                path.display()
            ))
        })?;
        Ok(())
    }

    #[cfg(not(unix))]
    {
        // F6: on Windows, create + owner-restrict the parent directory FIRST so
        // the key file is born with a restrictive DACL (no post-write TOCTOU
        // window) and an attacker cannot pre-create a predictable target inside
        // an owner-only directory. No-op on non-windows non-unix targets.
        restrict_parent_dir(path);
        let af = AtomicFile::new(path, OverwriteBehavior::AllowOverwrite);
        af.write(|f| {
            use std::io::Write;
            f.write_all(bytes)
        })
        .map_err(|e| {
            Error::RuntimeFailure(format!("atomic write of `{}` failed: {e}", path.display()))
        })?;
        // H2: Windows has no `0600` mode bit. A private key written under a
        // shared path (e.g. a LocalSystem service pointed at `C:\ProgramData`)
        // would inherit `Users:Read`. Tighten the DACL to owner + SYSTEM/
        // Administrators, removing inherited access. Best-effort + no-op on
        // non-windows non-unix targets. Defense in depth on top of the
        // pre-restricted parent directory above.
        restrict_to_owner(path);
        Ok(())
    }
}

/// Restrict a freshly-written key file's DACL on Windows (owner + SYSTEM +
/// Administrators only, inheritance removed). No-op on non-Windows. See the
/// `spt-secrets` equivalent for the full rationale (H1/H2). Implemented via
/// `icacls` (always present on Windows) so no new crate dependency is added.
#[cfg(windows)]
fn restrict_to_owner(path: &Path) {
    use std::process::Command;

    // Well-known SIDs avoid locale-dependent group names:
    //   *S-1-5-18     = Local System
    //   *S-1-5-32-544 = BUILTIN\Administrators
    let mut cmd = Command::new("icacls");
    cmd.arg(path)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(F)")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(F)");
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.is_empty() {
            let principal = match std::env::var("USERDOMAIN") {
                Ok(dom) if !dom.is_empty() => format!("{dom}\\{user}"),
                _ => user,
            };
            cmd.arg("/grant:r").arg(format!("{principal}:(F)"));
        }
    }
    match cmd.output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => tracing::warn!(
            path = %path.display(),
            code = ?out.status.code(),
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "icacls could not restrict DACL on a key file; it may be readable by non-owner principals"
        ),
        Err(e) => tracing::warn!(
            path = %path.display(),
            error = %e,
            "could not run icacls to restrict key file DACL"
        ),
    }
}

// Only the `not(unix)` write arm calls this; on unix neither definition is
// compiled (nor is the call site), so the no-op is gated to non-unix non-windows
// targets to avoid a dead-code warning on unix.
#[cfg(all(not(unix), not(windows)))]
fn restrict_to_owner(_path: &Path) {}

/// F6: ensure the directory that will hold a freshly-written key exists and —
/// when *we* create it — carries an inheritable, non-inherited owner + SYSTEM/
/// Administrators DACL (mirrors `spt-state::dir` and the `spt-secrets`
/// equivalent). This makes the key file born owner-only (closing the
/// post-write TOCTOU window) and prevents an attacker from pre-creating a
/// predictable target inside an owner-only directory (the explicit-ACE
/// survival vector). Restriction is applied only on the transition where this
/// call creates the directory, so an operator's existing directory is not
/// clobbered; the per-file [`restrict_to_owner`] stays as defense in depth.
#[cfg(windows)]
fn restrict_parent_dir(path: &Path) {
    use std::process::Command;

    let Some(parent) = path.parent() else { return };
    if parent.as_os_str().is_empty() {
        return;
    }
    let freshly_created = !parent.exists();
    if fs::create_dir_all(parent).is_err() {
        // A genuine create failure is surfaced by the caller's atomic write.
        return;
    }
    if !freshly_created {
        return;
    }
    // `(OI)(CI)(F)` = object+container inherit, full control — so child files
    // inherit the owner-only DACL. Well-known SIDs keep it locale-independent.
    let mut cmd = Command::new("icacls");
    cmd.arg(parent)
        .arg("/inheritance:r")
        .arg("/grant:r")
        .arg("*S-1-5-18:(OI)(CI)(F)")
        .arg("/grant:r")
        .arg("*S-1-5-32-544:(OI)(CI)(F)");
    if let Ok(user) = std::env::var("USERNAME") {
        if !user.is_empty() {
            let principal = match std::env::var("USERDOMAIN") {
                Ok(dom) if !dom.is_empty() => format!("{dom}\\{user}"),
                _ => user,
            };
            cmd.arg("/grant:r").arg(format!("{principal}:(OI)(CI)(F)"));
        }
    }
    match cmd.output() {
        Ok(out) if out.status.success() => {}
        Ok(out) => tracing::warn!(
            path = %parent.display(),
            code = ?out.status.code(),
            stderr = %String::from_utf8_lossy(&out.stderr).trim(),
            "icacls could not restrict the key directory DACL; key files may be readable by non-owner principals"
        ),
        Err(e) => tracing::warn!(
            path = %parent.display(),
            error = %e,
            "could not run icacls to restrict the key directory DACL"
        ),
    }
}

#[cfg(all(not(unix), not(windows)))]
fn restrict_parent_dir(_path: &Path) {}

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

    // sec-hardening (M5): the freshly-written key file must be 0600 the moment
    // it appears on disk — there must be no window where it is world-readable.
    // We can only assert the FINAL mode here, but the implementation creates the
    // temp with mode 0600 before any secret byte is written and renames it into
    // place, so the file is never observable with broader perms. (An encrypted
    // key still must not leak its ciphertext/KDF salt with loose perms either.)
    #[cfg(unix)]
    #[test]
    fn freshly_written_key_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();

        // unencrypted arm (the one M5 specifically calls out)
        let plain = dir.path().join("id_plain_perm");
        save_encrypted(&kp, &plain, None).unwrap();
        let mode = fs::metadata(&plain).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "unencrypted key must be 0600, got 0{mode:o}");

        // encrypted arm
        let enc = dir.path().join("id_enc_perm");
        save_encrypted(&kp, &enc, Some("pw")).unwrap();
        let mode = fs::metadata(&enc).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "encrypted key must be 0600, got 0{mode:o}");

        // overwrite path also lands at 0600 (no leftover temp, mode preserved)
        let kp2 = generate(KeyAlgorithm::Ed25519).unwrap();
        save_encrypted(&kp2, &plain, None).unwrap();
        let mode = fs::metadata(&plain).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "overwritten key must be 0600, got 0{mode:o}");
        // the sibling temp must not survive a successful write
        assert!(!with_extension_appended(&plain, "tmp").exists());
    }

    // H2: a key written on Windows must have its DACL restricted so the Users
    // group / Everyone lose read. We read the DACL back via `icacls`.
    // (GitHub-hosted Windows runners are en-US; the `(I)` inheritance check is
    // locale-independent.)
    // F6: the directory a key is written into must be owner-only BEFORE the
    // key file is created, so the file is born restricted and an attacker
    // cannot pre-create a predictable target inside an owner-only directory.
    #[cfg(windows)]
    #[test]
    fn windows_key_parent_dir_is_owner_only_before_write() {
        use std::process::Command;
        let dir = tempdir().unwrap();
        let subdir = dir.path().join("fresh-keydir");
        let target = subdir.join("id_ed25519");
        assert!(!subdir.exists());

        // Pre-write step performed by `write_secret_file`.
        restrict_parent_dir(&target);

        assert!(subdir.is_dir(), "key dir must have been created");
        assert!(!target.exists(), "no key file written yet");

        let out = Command::new("icacls").arg(&subdir).output().unwrap();
        assert!(out.status.success(), "icacls readback failed");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            !text.contains("\\Users:") && !text.contains("Everyone:"),
            "Users/Everyone present on key dir before write: {text}"
        );
        assert!(
            !text.contains("(I)"),
            "inherited ACEs survived on key dir: {text}"
        );
        assert!(text.contains("SYSTEM"), "SYSTEM grant missing: {text}");

        // A real save into the fresh dir still round-trips for the owner.
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        save_encrypted(&kp, &target, None).unwrap();
        assert!(load(&target, None).is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn windows_written_key_drops_users_read() {
        use std::process::Command;
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_win");
        save_encrypted(&kp, &p, None).unwrap();

        let out = Command::new("icacls").arg(&p).output().unwrap();
        assert!(out.status.success(), "icacls readback failed");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            !text.contains("\\Users:") && !text.contains("Everyone:"),
            "Users/Everyone still present in key DACL: {text}"
        );
        assert!(
            !text.contains("(I)"),
            "inherited ACEs survived key restriction: {text}"
        );
        // The key is still loadable by the owner after restriction.
        assert!(load(&p, None).is_ok());
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

    #[test]
    fn load_missing_file_is_runtime_failure() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("nope");
        let err = load(&p, None).unwrap_err();
        // Path string is interpolated into the message.
        let msg = format!("{err}");
        assert!(msg.contains("nope") || msg.contains("read"));
    }

    #[test]
    fn load_corrupt_pem_is_invalid_config() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("junk");
        fs::write(&p, b"this is not an ssh key").unwrap();
        let err = load(&p, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("ssh-key") || msg.to_lowercase().contains("invalid"));
    }

    #[test]
    fn load_encrypted_without_passphrase_is_invalid_args() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("enc");
        save_encrypted(&kp, &p, Some("pw")).unwrap();
        let err = load(&p, None).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("encrypted") || msg.contains("passphrase"));
    }

    #[test]
    fn save_encrypted_with_empty_passphrase_is_unencrypted() {
        // `passphrase: Some("")` falls through to the unencrypted branch.
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("empty_pass");
        save_encrypted(&kp, &p, Some("")).unwrap();
        // No passphrase needed to load.
        let loaded = load(&p, None).unwrap();
        assert_eq!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp.public_ref())
        );
    }

    #[test]
    fn change_passphrase_strips_encryption_when_new_is_none() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_strip");
        save_encrypted(&kp, &p, Some("old")).unwrap();
        change_passphrase(&p, Some("old"), None).unwrap();
        // Loadable with no passphrase now.
        let loaded = load(&p, None).unwrap();
        assert_eq!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp.public_ref())
        );
    }

    #[test]
    fn change_passphrase_strips_encryption_when_new_is_empty() {
        // `new = Some("")` should also strip — empty-pw branch matches `_`.
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_strip_empty");
        save_encrypted(&kp, &p, Some("old")).unwrap();
        change_passphrase(&p, Some("old"), Some("")).unwrap();
        let loaded = load(&p, None).unwrap();
        assert_eq!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp.public_ref())
        );
    }

    #[test]
    fn change_passphrase_with_wrong_old_fails() {
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_wrong_old");
        save_encrypted(&kp, &p, Some("old")).unwrap();
        let err = change_passphrase(&p, Some("nope"), Some("new")).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("passphrase") || msg.contains("auth"));
    }

    #[test]
    fn change_passphrase_adds_encryption() {
        // Start unencrypted, then add a passphrase.
        let kp = generate(KeyAlgorithm::Ed25519).unwrap();
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_plain_then_enc");
        save_encrypted(&kp, &p, None).unwrap();
        change_passphrase(&p, None, Some("new")).unwrap();
        assert!(load(&p, None).is_err());
        let loaded = load(&p, Some("new")).unwrap();
        assert_eq!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp.public_ref())
        );
    }

    #[test]
    fn with_extension_appended_appends_dot_ext() {
        let p = std::path::PathBuf::from("/tmp/key");
        let bak = with_extension_appended(&p, "bak");
        assert_eq!(bak, std::path::PathBuf::from("/tmp/key.bak"));
    }

    #[test]
    fn with_extension_appended_on_already_extended_path() {
        // We APPEND — we don't replace — so foo.txt + bak => foo.txt.bak.
        let p = std::path::PathBuf::from("foo.txt");
        let out = with_extension_appended(&p, "bak");
        assert_eq!(out, std::path::PathBuf::from("foo.txt.bak"));
    }

    #[test]
    fn save_then_overwrite_preserves_load() {
        // AtomicWrite OverwriteBehavior::AllowOverwrite: re-saving must
        // succeed and the new key must be readable.
        let dir = tempdir().unwrap();
        let p = dir.path().join("id_over");
        let kp1 = generate(KeyAlgorithm::Ed25519).unwrap();
        save_encrypted(&kp1, &p, None).unwrap();
        let kp2 = generate(KeyAlgorithm::Ed25519).unwrap();
        save_encrypted(&kp2, &p, None).unwrap();
        let loaded = load(&p, None).unwrap();
        assert_eq!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp2.public_ref())
        );
        assert_ne!(
            fingerprint_sha256(loaded.public_ref()),
            fingerprint_sha256(kp1.public_ref())
        );
    }
}
