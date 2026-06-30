//! Adversarial / corruption-path tests for `spt-secrets` (W2 #8).
//!
//! TOFU/keychain-fallthrough and the happy-path round-trips are already
//! covered elsewhere. This suite targets the *attack* and *corruption* paths:
//!
//! * **File backend** — a symlinked secret file (cfg(unix)): the mode gate must
//!   inspect the resolved target (no confused-deputy read of an unintended
//!   world-readable file); a hardlink with a permissive mode; the full mode
//!   matrix including `0o666`; a directory where a file is expected.
//! * **Vault** — a truncated vault file, a corrupted/garbage vault file, a
//!   missing/corrupted meta sidecar with records present, an on-disk
//!   stale-format-version, Argon2 parameter edges (bounded; no `DoS` / no
//!   panic), a wrong passphrase.
//!
//! Every assertion is fail-closed: a clean typed error, never a panic and never
//! a read of an unintended file. Symlink / mode tests are `cfg(unix)` (verified
//! on Linux docker per the task gate); the rest run on every platform.

use spt_core::Error;
use spt_secrets::{FileBackend, SecretBackend, SecretRef, VaultBackend};
use tempfile::tempdir;

// ===========================================================================
// File backend — symlink / hardlink / mode matrix / directory (cfg(unix)).
// ===========================================================================

/// A `secret://ns/name` whose on-disk path is a SYMLINK pointing at a
/// world-readable target must be rejected by the mode gate. `fs::metadata`
/// follows the link, so the resolved target's `0o644` mode is what is checked —
/// the backend must NOT serve the world-readable target (no confused deputy).
#[cfg(unix)]
#[test]
fn file_symlink_to_world_readable_target_is_rejected() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let root = tempdir().unwrap();
    let ns_dir = root.path().join("ns");
    fs::create_dir_all(&ns_dir).unwrap();

    // The real secret material lives elsewhere and is world-readable (0o644).
    let target_dir = tempdir().unwrap();
    let target = target_dir.path().join("evil-target");
    fs::write(&target, b"world-readable-payload").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();

    // The secret path is a symlink to that world-readable file.
    let link = ns_dir.join("name");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let b = FileBackend::new(root.path());
    let r = SecretRef::new("ns", "name").unwrap();
    let err = b.get(&r).unwrap_err();
    assert!(
        matches!(err, Error::PermissionDenied(_)),
        "symlink to a 0644 target must be rejected, got {err:?}"
    );
}

/// A symlink whose resolved target is owner-only (0o600) is accepted — the gate
/// keys on the target's real mode, and the content returned is the target's.
/// This pins that the symlink path is not blanket-rejected (which would break
/// legitimate setups), only world-readable targets are.
#[cfg(unix)]
#[test]
fn file_symlink_to_owner_only_target_is_accepted() {
    use secrecy::ExposeSecret;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let root = tempdir().unwrap();
    let ns_dir = root.path().join("ns");
    fs::create_dir_all(&ns_dir).unwrap();

    let target_dir = tempdir().unwrap();
    let target = target_dir.path().join("ok-target");
    fs::write(&target, b"owner-only-payload").unwrap();
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();

    let link = ns_dir.join("name");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let b = FileBackend::new(root.path());
    let r = SecretRef::new("ns", "name").unwrap();
    let got = b.get(&r).unwrap().unwrap();
    assert_eq!(got.expose_secret().as_slice(), b"owner-only-payload");
}

/// A dangling symlink (target does not exist) must surface a clean
/// `SecretUnavailable` (stat fails), not a panic — `path.exists()` returns
/// false for a broken link, so the backend short-circuits to `Ok(None)`; a
/// `resolve` over a single-backend chain then reports unavailable.
#[cfg(unix)]
#[test]
fn file_dangling_symlink_is_not_a_panic() {
    use std::fs;
    let root = tempdir().unwrap();
    let ns_dir = root.path().join("ns");
    fs::create_dir_all(&ns_dir).unwrap();
    let link = ns_dir.join("name");
    std::os::unix::fs::symlink(root.path().join("does-not-exist"), &link).unwrap();

    let b = FileBackend::new(root.path());
    let r = SecretRef::new("ns", "name").unwrap();
    // A broken symlink: `exists()` is false → treated as absent, not a crash.
    let got = b.get(&r).unwrap();
    assert!(got.is_none(), "dangling symlink resolves to absent");
}

/// A HARDLINK to a world-readable file: a hardlink shares the inode, so its
/// mode IS the shared mode. The gate must reject it exactly like the original.
#[cfg(unix)]
#[test]
fn file_hardlink_inherits_and_is_mode_checked() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let root = tempdir().unwrap();
    let ns_dir = root.path().join("ns");
    fs::create_dir_all(&ns_dir).unwrap();

    let other_dir = tempdir().unwrap();
    let original = other_dir.path().join("orig");
    fs::write(&original, b"shared-inode").unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();

    let link = ns_dir.join("name");
    fs::hard_link(&original, &link).unwrap();

    let b = FileBackend::new(root.path());
    let r = SecretRef::new("ns", "name").unwrap();
    let err = b.get(&r).unwrap_err();
    assert!(
        matches!(err, Error::PermissionDenied(_)),
        "hardlink to a 0644 inode must be rejected, got {err:?}"
    );
}

/// The full mode matrix: only `0o400` and `0o600` are accepted; everything
/// broader (`0o640`, `0o644`, `0o660`, `0o666`, `0o777`) is rejected
/// fail-closed. Exercises the `0o666` group-and-world-writable case the
/// existing tests omit.
#[cfg(unix)]
#[test]
fn file_mode_matrix_owner_only_accepted_rest_rejected() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let accepted = [0o400u32, 0o600];
    let rejected = [0o640u32, 0o644, 0o660, 0o666, 0o777, 0o604];

    for mode in accepted {
        let root = tempdir().unwrap();
        let b = FileBackend::new(root.path());
        let r = SecretRef::new("ns", "name").unwrap();
        b.set(&r, b"x").unwrap();
        fs::set_permissions(b.path_for(&r), fs::Permissions::from_mode(mode)).unwrap();
        assert!(b.get(&r).is_ok(), "mode {mode:o} should be accepted");
    }
    for mode in rejected {
        let root = tempdir().unwrap();
        let b = FileBackend::new(root.path());
        let r = SecretRef::new("ns", "name").unwrap();
        b.set(&r, b"x").unwrap();
        fs::set_permissions(b.path_for(&r), fs::Permissions::from_mode(mode)).unwrap();
        let err = b.get(&r).unwrap_err();
        assert!(
            matches!(err, Error::PermissionDenied(_)),
            "mode {mode:o} should be rejected, got {err:?}"
        );
    }
}

/// A DIRECTORY where the backend expects a regular file: reading must produce a
/// clean error (or absent), never a panic. On Unix a directory's mode is
/// typically `0o755`, so the mode gate rejects it with `PermissionDenied`
/// before any read is attempted.
#[cfg(unix)]
#[test]
fn file_directory_where_file_expected_is_clean_error() {
    use std::fs;
    let root = tempdir().unwrap();
    let ns_dir = root.path().join("ns");
    fs::create_dir_all(&ns_dir).unwrap();
    // Create a directory at the secret's leaf path.
    fs::create_dir_all(ns_dir.join("name")).unwrap();

    let b = FileBackend::new(root.path());
    let r = SecretRef::new("ns", "name").unwrap();
    let err = b.get(&r).unwrap_err();
    // Directory mode (0o7xx) fails the owner-only gate first.
    assert!(
        matches!(
            err,
            Error::PermissionDenied(_) | Error::SecretUnavailable { .. }
        ),
        "directory-where-file must be a clean error, got {err:?}"
    );
}

/// Non-unix platforms (Windows): a directory where a file is expected must also
/// fail cleanly rather than panic. `check_mode` stats the path (a dir stats OK)
/// and the subsequent `fs::read` of a directory errors → `SecretUnavailable`.
#[cfg(windows)]
#[test]
fn file_directory_where_file_expected_is_clean_error_windows() {
    use std::fs;
    let root = tempdir().unwrap();
    let ns_dir = root.path().join("ns");
    fs::create_dir_all(&ns_dir).unwrap();
    fs::create_dir_all(ns_dir.join("name")).unwrap();

    let b = FileBackend::new(root.path());
    let r = SecretRef::new("ns", "name").unwrap();
    let err = b.get(&r).unwrap_err();
    assert!(
        matches!(err, Error::SecretUnavailable { .. }),
        "directory-where-file must be a clean error, got {err:?}"
    );
}

// ===========================================================================
// File backend — path-traversal containment (M4). All platforms.
// ===========================================================================

/// A `secret://../foo` reference must be rejected at parse time so the file
/// backend can never resolve a path outside its root. Covers `..`, a leaf `..`,
/// nested traversal, an absolute-looking segment, separators, and NUL — every
/// form that could otherwise escape `<root>`.
#[test]
fn secret_ref_traversal_forms_are_rejected_at_parse() {
    use std::str::FromStr;
    let rejected = [
        "secret://../foo",
        "secret://ns/..",
        "secret://ns/.",
        "secret://./name",
        "secret://ns/../../etc/x",
    ];
    for raw in rejected {
        assert!(
            SecretRef::from_str(raw).is_err(),
            "traversal reference {raw:?} must be rejected"
        );
    }
    // Direct construction is guarded too (separators, absolute marker, NUL).
    for seg in ["..", ".", "a/b", "a\\b", "/abs", "a\0b"] {
        assert!(
            SecretRef::new(seg, "name").is_err(),
            "ns segment {seg:?} must be rejected"
        );
        assert!(
            SecretRef::new("ns", seg).is_err(),
            "name segment {seg:?} must be rejected"
        );
    }
    // A normal reference still resolves and round-trips through the backend.
    let dir = tempdir().unwrap();
    let b = FileBackend::new(dir.path());
    let r = SecretRef::new("ns", "name").unwrap();
    b.set(&r, b"ok").unwrap();
    assert!(b.get(&r).unwrap().is_some());
}

// ===========================================================================
// Vault — corruption / truncation / meta / argon2 edges. All platforms.
// ===========================================================================

/// A TRUNCATED vault file (valid JSON prefix, cut mid-object) must produce a
/// clean `SecretCryptoFailed` parse error — never a panic.
#[test]
fn vault_truncated_file_is_clean_error() {
    use std::fs;
    let dir = tempdir().unwrap();
    let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
    let r = SecretRef::new("ns", "n").unwrap();
    v.set(&r, b"payload").unwrap();
    drop(v);

    // Truncate the on-disk vault to a partial JSON prefix.
    let vpath = VaultBackend::vault_path(dir.path());
    let full = fs::read(&vpath).unwrap();
    assert!(full.len() > 8, "vault should have content to truncate");
    fs::write(&vpath, &full[..full.len() / 2]).unwrap();

    let v2 = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap();
    let err = v2.get(&r).unwrap_err();
    assert!(
        matches!(err, Error::SecretCryptoFailed(_)),
        "truncated vault must be a clean crypto/parse error, got {err:?}"
    );
}

/// A garbage (non-JSON) vault file must produce a clean parse error on read.
#[test]
fn vault_garbage_file_is_clean_error() {
    use std::fs;
    let dir = tempdir().unwrap();
    let v = VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
    let vpath = VaultBackend::vault_path(dir.path());
    fs::write(&vpath, b"\x00\x01\x02 not json at all \xff\xfe").unwrap();
    let r = SecretRef::new("ns", "n").unwrap();
    let err = v.get(&r).unwrap_err();
    assert!(
        matches!(err, Error::SecretCryptoFailed(_)),
        "garbage vault must be a clean error, got {err:?}"
    );
}

/// A CORRUPTED meta sidecar (garbage TOML) must fail the open cleanly —
/// before any key is derived — rather than panicking.
#[test]
fn vault_corrupted_meta_sidecar_fails_open() {
    use std::fs;
    let dir = tempdir().unwrap();
    VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
    // Corrupt the meta sidecar.
    let mpath = VaultBackend::meta_path(dir.path());
    fs::write(&mpath, b"this is = not [valid toml").unwrap();
    let err = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap_err();
    assert!(
        matches!(err, Error::SecretCryptoFailed(_)),
        "corrupted meta must fail open cleanly, got {err:?}"
    );
}

/// A MISSING meta sidecar (deleted) while the vault file remains must fail the
/// open cleanly — the backend cannot derive a key without the salt/params.
#[test]
fn vault_missing_meta_sidecar_fails_open() {
    use std::fs;
    let dir = tempdir().unwrap();
    VaultBackend::init_with_passphrase(dir.path(), b"pw").unwrap();
    fs::remove_file(VaultBackend::meta_path(dir.path())).unwrap();
    let err = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap_err();
    assert!(
        matches!(err, Error::SecretCryptoFailed(_)),
        "missing meta must fail open cleanly, got {err:?}"
    );
}

/// A meta whose Argon2 `time_cost = 0` is below the algorithm's minimum: the
/// `Params::new` validation rejects it cleanly on open (no panic, no `DoS`).
#[test]
fn vault_argon2_zero_time_cost_rejected() {
    write_meta_and_assert_open_fails(VaultMetaSpec {
        memory_kib: 64 * 1024,
        time_cost: 0,
        parallelism: 4,
    });
}

/// A meta whose Argon2 `memory_kib` is far below the `8 * parallelism` minimum
/// is rejected cleanly rather than panicking or running unbounded.
#[test]
fn vault_argon2_undersized_memory_rejected() {
    write_meta_and_assert_open_fails(VaultMetaSpec {
        memory_kib: 1,
        time_cost: 3,
        parallelism: 4,
    });
}

/// A meta whose Argon2 `parallelism = 0` is invalid and rejected cleanly.
#[test]
fn vault_argon2_zero_parallelism_rejected() {
    write_meta_and_assert_open_fails(VaultMetaSpec {
        memory_kib: 64 * 1024,
        time_cost: 3,
        parallelism: 0,
    });
}

/// A meta with a tiny-but-VALID memory cost at the algorithm minimum
/// (`8 * parallelism` KiB) derives a key and round-trips — proving the edge is
/// bounded but usable, not a hang.
#[test]
fn vault_argon2_minimum_valid_params_round_trip() {
    use secrecy::ExposeSecret;
    use std::fs;
    let dir = tempdir().unwrap();
    // Minimum memory for parallelism=1 is 8 KiB; time_cost minimum is 1.
    let meta = format!(
        "version = 1\nsalt_hex = \"{}\"\ninitialized = true\n\n[argon2]\nmemory_kib = 8\ntime_cost = 1\nparallelism = 1\n",
        hex::encode([7u8; 16])
    );
    fs::create_dir_all(dir.path()).unwrap();
    fs::write(VaultBackend::meta_path(dir.path()), meta).unwrap();
    fs::write(VaultBackend::vault_path(dir.path()), b"{\"records\":{}}").unwrap();

    // Open derives a key with these tiny params; set+get round-trips.
    let v = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap();
    let r = SecretRef::new("ns", "n").unwrap();
    v.set(&r, b"tiny-params-ok").unwrap();
    let got = v.get(&r).unwrap().unwrap();
    assert_eq!(got.expose_secret().as_slice(), b"tiny-params-ok");
}

/// Wrong passphrase: opening with a different passphrase derives a different
/// key, so any `get` of an existing record fails AEAD authentication with a
/// clean `SecretCryptoFailed` — fail-closed, no plaintext leak.
#[test]
fn vault_wrong_passphrase_fails_closed() {
    let dir = tempdir().unwrap();
    let v = VaultBackend::init_with_passphrase(dir.path(), b"the-right-one").unwrap();
    let r = SecretRef::new("ns", "n").unwrap();
    v.set(&r, b"top-secret").unwrap();
    drop(v);

    let v2 = VaultBackend::open_with_passphrase(dir.path(), b"a-wrong-one").unwrap();
    let err = v2.get(&r).unwrap_err();
    assert!(
        matches!(err, Error::SecretCryptoFailed(_)),
        "wrong passphrase must fail AEAD auth, got {err:?}"
    );
}

/// A meta whose on-disk format `version` is newer/older than the supported one
/// still opens (version is informational for derivation) but `doctor` reports
/// the vault as degraded with a migration hint — surfacing the mismatch rather
/// than silently trusting an incompatible layout.
#[test]
fn vault_stale_format_version_surfaced_by_doctor() {
    use std::fs;
    let dir = tempdir().unwrap();
    // version = 0 (older than FORMAT_VERSION = 1).
    let meta = format!(
        "version = 0\nsalt_hex = \"{}\"\ninitialized = true\n\n[argon2]\nmemory_kib = 65536\ntime_cost = 3\nparallelism = 4\n",
        hex::encode([3u8; 16])
    );
    fs::create_dir_all(dir.path()).unwrap();
    fs::write(VaultBackend::meta_path(dir.path()), meta).unwrap();
    fs::write(VaultBackend::vault_path(dir.path()), b"{\"records\":{}}").unwrap();

    let v = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap();
    let d = v.doctor();
    assert!(
        matches!(d.status, spt_secrets::BackendStatus::Degraded),
        "stale version must be flagged degraded"
    );
    assert!(d.remediation.is_some(), "must offer a migration hint");
}

// ---------------------------------------------------------------------------
// Helper: write a meta with the given Argon2 params + an empty vault, then
// assert that opening with a passphrase fails cleanly (no panic).
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct VaultMetaSpec {
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
}

fn write_meta_and_assert_open_fails(spec: VaultMetaSpec) {
    use std::fs;
    let dir = tempdir().unwrap();
    let meta = format!(
        "version = 1\nsalt_hex = \"{}\"\ninitialized = true\n\n[argon2]\nmemory_kib = {}\ntime_cost = {}\nparallelism = {}\n",
        hex::encode([0u8; 16]),
        spec.memory_kib,
        spec.time_cost,
        spec.parallelism,
    );
    fs::create_dir_all(dir.path()).unwrap();
    fs::write(VaultBackend::meta_path(dir.path()), meta).unwrap();
    fs::write(VaultBackend::vault_path(dir.path()), b"{\"records\":{}}").unwrap();

    let err = VaultBackend::open_with_passphrase(dir.path(), b"pw").unwrap_err();
    assert!(
        matches!(err, Error::SecretCryptoFailed(_)),
        "invalid argon2 params must be rejected cleanly, got {err:?}"
    );
}
