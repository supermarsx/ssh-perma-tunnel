//! Artifact verification — SHA256SUMS checksum + minisign (ed25519) signature.
//!
//! # What this verifies
//!
//! Two independent, composable checks, gated by [`VerifyConfig`]:
//!
//! 1. **SHA256SUMS** (`require_sha256sums`) — the downloaded artifact's
//!    SHA-256 is compared against a published `SHA256SUMS` entry. The
//!    digest can be supplied either inline (the source backend already
//!    populated [`ReleaseArtifact::sha256`]) or by passing the bytes of a
//!    `SHA256SUMS` file to [`verify_checksum_against_sums`]. `sha2` does the
//!    hashing; it is already in the dependency tree.
//! 2. **minisign signature** (`require_minisign`) — a detached
//!    `<artifact>.minisig` is verified against an operator-configured
//!    minisign public key. Minisign is an ed25519 scheme; verification uses
//!    the pure-Rust `minisign-verify` crate (already in the tree). This is
//!    the "detached ed25519 / minisign-style" signature path.
//!
//! # Absence handling (fail-closed vs best-effort)
//!
//! The [`VerifyConfig`] flags decide policy:
//!
//! * `require_sha256sums = true` / `require_minisign = true` → the
//!   corresponding material **must** be present and valid, otherwise
//!   verification fails (fail-closed).
//! * `require_* = false` → the check is **best-effort**: if material is
//!   present it is still validated (a *present-but-wrong* checksum/signature
//!   always fails), but a *missing* artifact only emits a `tracing::warn!`
//!   and verification proceeds.
//!
//! # GPG
//!
//! [`VerifyConfig::gpg_pubkey`] selects a GPG-signed `SHA256SUMS.asc`
//! detached-signature check. No `OpenPGP` crate is present in the workspace
//! dependency tree, and adding one is out of scope (the updater must not
//! grow `Cargo.lock`). When `gpg_pubkey` is set we therefore **fail closed
//! with a clear, actionable error** rather than silently skip a check the
//! operator explicitly asked for — GPG verification must be performed by an
//! external `gpg` invocation (e.g. a post-download hook) until an in-tree
//! `OpenPGP` verifier is available.
//!
//! # Release-CI dependency
//!
//! This machinery engages **only when the release publishes the material**:
//! a `SHA256SUMS` file (or per-asset digests, which GitHub already exposes
//! via the asset `digest` field) and `<artifact>.minisig` signatures next to
//! each asset. The release workflow under `.github/workflows` is **not**
//! modified by this crate. If a given release does not yet publish those
//! files, strict mode fails closed (the safe default) and best-effort mode
//! warns-and-proceeds. Once the release process publishes checksums/minisigs,
//! verification activates with no code change here.

use std::path::Path;

use sha2::{Digest, Sha256};
use tracing::{error, info, warn};

use crate::config::VerifyConfig;
use crate::error::{UpdaterError, UpdaterResult};

/// Compute the lowercase hex SHA-256 of a file's contents.
pub fn sha256_file(path: &Path) -> UpdaterResult<String> {
    let bytes = std::fs::read(path)
        .map_err(|e| UpdaterError::Verify(format!("read {}: {e}", path.display())))?;
    Ok(sha256_bytes(&bytes))
}

/// Compute the lowercase hex SHA-256 of a byte slice.
#[must_use]
pub fn sha256_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

/// Look up `filename`'s expected digest in a `SHA256SUMS` body.
///
/// `SHA256SUMS` is the coreutils format: `<hex>  <name>` per line (two
/// spaces for binary mode, one space + `*` is also tolerated). Returns the
/// lowercase expected hex, or `None` if the file isn't listed.
#[must_use]
pub fn lookup_in_sha256sums(sums_body: &str, filename: &str) -> Option<String> {
    for line in sums_body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Split off the leading hex digest; the remainder (after optional
        // `*`/space) is the name.
        let mut it = line.splitn(2, char::is_whitespace);
        let hex_part = it.next().unwrap_or("");
        let name_part = it.next().unwrap_or("").trim_start().trim_start_matches('*');
        // Match either the bare name or a path whose final component matches
        // (release SHA256SUMS sometimes list `./dist/<name>`).
        let name_matches = name_part == filename
            || Path::new(name_part)
                .file_name()
                .is_some_and(|f| f == filename);
        if name_matches && hex_part.len() == 64 {
            return Some(hex_part.to_lowercase());
        }
    }
    None
}

/// Verify `artifact`'s SHA-256 against an entry in a `SHA256SUMS` body.
///
/// * `Ok(true)`  — the artifact is listed and its digest matches.
/// * `Err(_)`    — the artifact is listed but the digest is **wrong**.
/// * `Ok(false)` — the artifact is **not listed** in the body (caller
///   decides whether absence is fatal, per policy).
pub fn verify_checksum_against_sums(
    artifact: &Path,
    sums_body: &str,
    filename: &str,
) -> UpdaterResult<bool> {
    let Some(expected) = lookup_in_sha256sums(sums_body, filename) else {
        return Ok(false);
    };
    verify_checksum_against_digest(artifact, &expected).map(|()| true)
}

/// Verify `artifact`'s SHA-256 against a single expected lowercase-hex digest.
pub fn verify_checksum_against_digest(artifact: &Path, expected: &str) -> UpdaterResult<()> {
    let got = sha256_file(artifact)?;
    let expected = expected.trim().to_lowercase();
    if got == expected {
        Ok(())
    } else {
        // Security-critical: a checksum mismatch means the artifact on disk is
        // NOT the published one (tamper / corruption / MITM). Log at ERROR at
        // the detection site BEFORE returning so a tampered artifact is not
        // indistinguishable from a transient error in the operator's logs.
        error!(
            target: "spt_updater::verify",
            check = "sha256",
            artifact = %artifact.display(),
            expected = %expected,
            got = %got,
            "artifact SHA-256 verification FAILED (checksum mismatch) — refusing artifact"
        );
        Err(UpdaterError::Verify(format!(
            "SHA-256 mismatch for {}: expected {expected}, got {got}",
            artifact.display()
        )))
    }
}

/// Verify a detached minisign signature over `artifact` using the public key
/// at `pubkey_path`. `signature_path` is the `<artifact>.minisig` file.
pub fn verify_minisign(
    artifact: &Path,
    signature_path: &Path,
    pubkey_path: &Path,
) -> UpdaterResult<()> {
    let pk = minisign_verify::PublicKey::from_file(pubkey_path).map_err(|e| {
        error!(
            target: "spt_updater::verify",
            check = "minisign",
            artifact = %artifact.display(),
            pubkey = %pubkey_path.display(),
            error = %e,
            "minisign verification FAILED to load the configured public key — refusing artifact"
        );
        UpdaterError::Verify(format!(
            "load minisign pubkey {}: {e}",
            pubkey_path.display()
        ))
    })?;
    let sig = minisign_verify::Signature::from_file(signature_path).map_err(|e| {
        error!(
            target: "spt_updater::verify",
            check = "minisign",
            artifact = %artifact.display(),
            signature = %signature_path.display(),
            error = %e,
            "minisign verification FAILED to load the detached signature — refusing artifact"
        );
        UpdaterError::Verify(format!(
            "load minisign signature {}: {e}",
            signature_path.display()
        ))
    })?;
    let bytes = std::fs::read(artifact)
        .map_err(|e| UpdaterError::Verify(format!("read {}: {e}", artifact.display())))?;
    // `allow_legacy = false` — require modern prehashed signatures (the
    // default `minisign -S` output since 0.6). Legacy un-prehashed sigs are
    // rejected, which is the stronger posture.
    pk.verify(&bytes, &sig, false).map_err(|e| {
        // Security-critical: a bad signature means the artifact was not signed
        // by the trusted key (tamper / forgery). Log at ERROR at the detection
        // site BEFORE returning.
        error!(
            target: "spt_updater::verify",
            check = "minisign",
            artifact = %artifact.display(),
            error = %e,
            "artifact minisign signature verification FAILED — refusing artifact"
        );
        UpdaterError::Verify(format!("minisign verification failed: {e}"))
    })
}

/// Optional inputs to [`verify_artifact`], threaded from the source/download
/// step so the caller doesn't have to re-fetch `SHA256SUMS`.
#[derive(Debug, Default, Clone)]
pub struct VerifyInputs {
    /// The expected per-artifact digest, if the source surfaced one
    /// (GitHub asset `digest`, URL/static manifest `sha256`).
    pub expected_sha256: Option<String>,
    /// The full body of a published `SHA256SUMS` file, if one was fetched.
    pub sha256sums_body: Option<String>,
    /// The artifact's filename as it appears in `SHA256SUMS`.
    pub artifact_name: Option<String>,
}

/// Verify a downloaded artifact against the configured policy. Returns
/// `Ok(())` only when every **required** check passed (or, for best-effort
/// checks, when present material validated / absent material was tolerated).
///
/// * `cfg`       — the verification policy.
/// * `artifact`  — path to the downloaded artifact on disk.
/// * `signature` — path to the detached `.minisig`, if one was downloaded.
/// * `inputs`    — optional checksum material (see [`VerifyInputs`]).
///
/// Synchronous: all verification is local CPU + filesystem work. Callers on
/// an async path should wrap it in `spawn_blocking` for large artifacts.
pub fn verify_artifact(
    cfg: &VerifyConfig,
    artifact: &Path,
    signature: Option<&Path>,
    inputs: &VerifyInputs,
) -> UpdaterResult<()> {
    // ---- GPG: explicitly requested but unsupported in-process ----------
    if let Some(gpg) = &cfg.gpg_pubkey {
        error!(
            target: "spt_updater::verify",
            check = "gpg",
            artifact = %artifact.display(),
            gpg_pubkey = %gpg.display(),
            "gpg_pubkey is configured but in-process GPG verification is unavailable — refusing artifact (fail-closed)"
        );
        return Err(UpdaterError::Verify(format!(
            "gpg_pubkey is set ({}) but in-process GPG verification is not \
             available (no `OpenPGP` crate in the dependency tree). Verify \
             SHA256SUMS.asc with an external `gpg --verify` step, or remove \
             gpg_pubkey and rely on minisign + SHA256SUMS.",
            gpg.display()
        )));
    }

    // ---- SHA-256 checksum ----------------------------------------------
    let checksum_ok = run_checksum_check(artifact, inputs)?;
    if cfg.require_sha256sums && !checksum_ok {
        error!(
            target: "spt_updater::verify",
            check = "sha256",
            artifact = %artifact.display(),
            "require_sha256sums = true but no SHA-256 digest was available — refusing artifact (fail-closed)"
        );
        return Err(UpdaterError::Verify(format!(
            "require_sha256sums = true but no SHA-256 digest was available for {} \
             (the release published neither a per-asset digest nor a SHA256SUMS entry)",
            artifact.display()
        )));
    }
    if !cfg.require_sha256sums && !checksum_ok {
        warn!(
            target: "spt_updater::verify",
            artifact = %artifact.display(),
            "no SHA-256 digest available; installing without checksum verification \
             (require_sha256sums = false)"
        );
    }

    // ---- minisign signature --------------------------------------------
    let signature_ok = run_minisign_check(cfg, artifact, signature)?;
    if cfg.require_minisign && !signature_ok {
        error!(
            target: "spt_updater::verify",
            check = "minisign",
            artifact = %artifact.display(),
            "require_minisign = true but no valid minisign material was available — refusing artifact (fail-closed)"
        );
        return Err(UpdaterError::Verify(format!(
            "require_minisign = true but no valid minisign material was available for {} \
             (need both a configured minisign_pubkey and a downloaded .minisig)",
            artifact.display()
        )));
    }
    if !cfg.require_minisign && !signature_ok {
        warn!(
            target: "spt_updater::verify",
            artifact = %artifact.display(),
            "no minisign signature verified; installing without signature \
             verification (require_minisign = false)"
        );
    }

    // Successful verification (every REQUIRED check passed; present best-effort
    // material validated). Log at INFO so a good install is observable in the
    // log stream, not just failures.
    info!(
        target: "spt_updater::verify",
        artifact = %artifact.display(),
        sha256_verified = checksum_ok,
        minisign_verified = signature_ok,
        "artifact verification passed"
    );
    Ok(())
}

/// Run whichever checksum material is available. Returns `Ok(true)` if a
/// digest was found AND matched, `Ok(false)` if no digest material was
/// available, `Err` if a digest was present but mismatched.
fn run_checksum_check(artifact: &Path, inputs: &VerifyInputs) -> UpdaterResult<bool> {
    // Prefer the SHA256SUMS body when present (authoritative, multi-artifact),
    // else the per-artifact digest from the source.
    if let (Some(body), Some(name)) = (&inputs.sha256sums_body, &inputs.artifact_name) {
        if verify_checksum_against_sums(artifact, body, name)? {
            return Ok(true);
        }
        // Listed-but-absent falls through to the inline digest, if any.
    }
    if let Some(expected) = &inputs.expected_sha256 {
        verify_checksum_against_digest(artifact, expected)?;
        return Ok(true);
    }
    Ok(false)
}

/// Run the minisign check when both a pubkey and a signature file are
/// available. Returns `Ok(true)` on a verified signature, `Ok(false)` when
/// material is missing, `Err` on a present-but-invalid signature.
fn run_minisign_check(
    cfg: &VerifyConfig,
    artifact: &Path,
    signature: Option<&Path>,
) -> UpdaterResult<bool> {
    match (&cfg.minisign_pubkey, signature) {
        (Some(pubkey), Some(sig)) => {
            verify_minisign(artifact, sig, pubkey)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn vcfg(require_minisign: bool, require_sha256sums: bool) -> VerifyConfig {
        VerifyConfig {
            require_minisign,
            minisign_pubkey: None,
            require_sha256sums,
            gpg_pubkey: None,
        }
    }

    fn write_tmp(dir: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(body).unwrap();
        p
    }

    #[test]
    fn sha256_of_known_input() {
        // SHA-256("abc")
        assert_eq!(
            sha256_bytes(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn lookup_parses_coreutils_format() {
        let body = "deadbeef  ignored\n\
            ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  spt.tar.gz\n";
        assert_eq!(
            lookup_in_sha256sums(body, "spt.tar.gz").as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert!(lookup_in_sha256sums(body, "missing").is_none());
    }

    #[test]
    fn lookup_matches_path_tail() {
        let body =
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  ./dist/spt.tar.gz\n";
        assert!(lookup_in_sha256sums(body, "spt.tar.gz").is_some());
    }

    #[test]
    fn checksum_match_and_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let good = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert!(verify_checksum_against_digest(&art, good).is_ok());
        assert!(verify_checksum_against_digest(&art, "00").is_err());
        // Case-insensitive on the expected side.
        assert!(verify_checksum_against_digest(&art, &good.to_uppercase()).is_ok());
    }

    #[test]
    fn checksum_against_sums_listed_vs_unlisted() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let body = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a.bin\n";
        assert!(verify_checksum_against_sums(&art, body, "a.bin").unwrap());
        // Not listed → Ok(false).
        assert!(!verify_checksum_against_sums(&art, body, "other.bin").unwrap());
        // Listed but wrong → Err.
        let bad = "0000000000000000000000000000000000000000000000000000000000000000  a.bin\n";
        assert!(verify_checksum_against_sums(&art, bad, "a.bin").is_err());
    }

    #[test]
    fn required_sha256_fails_closed_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = vcfg(false, true);
        let err = verify_artifact(&cfg, &art, None, &VerifyInputs::default()).unwrap_err();
        assert_eq!(err.code(), "updater_verify");
    }

    #[test]
    fn best_effort_sha256_tolerates_absence() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = vcfg(false, false);
        // No checksum, no signature, nothing required → Ok.
        verify_artifact(&cfg, &art, None, &VerifyInputs::default()).unwrap();
    }

    #[test]
    fn best_effort_still_rejects_wrong_inline_digest() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = vcfg(false, false);
        let inputs = VerifyInputs {
            expected_sha256: Some("00".repeat(32)),
            ..Default::default()
        };
        // Present-but-wrong digest always fails, even in best-effort mode.
        let err = verify_artifact(&cfg, &art, None, &inputs).unwrap_err();
        assert_eq!(err.code(), "updater_verify");
    }

    #[test]
    fn inline_digest_match_satisfies_required() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = vcfg(false, true);
        let inputs = VerifyInputs {
            expected_sha256: Some(
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".into(),
            ),
            ..Default::default()
        };
        verify_artifact(&cfg, &art, None, &inputs).unwrap();
    }

    #[test]
    fn required_minisign_fails_closed_without_material() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = vcfg(true, false);
        let err = verify_artifact(&cfg, &art, None, &VerifyInputs::default()).unwrap_err();
        assert_eq!(err.code(), "updater_verify");
    }

    #[test]
    fn gpg_pubkey_set_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = VerifyConfig {
            require_minisign: false,
            minisign_pubkey: None,
            require_sha256sums: false,
            gpg_pubkey: Some(std::path::PathBuf::from("/keys/release.gpg")),
        };
        let err = verify_artifact(&cfg, &art, None, &VerifyInputs::default()).unwrap_err();
        assert_eq!(err.code(), "updater_verify");
        assert!(err.to_string().contains("gpg"));
    }

    // A verify FAILURE must be LOGGED at ERROR at the detection site, not
    // silently swallowed into a returned `Err` (audit CRIT #2). Pre-fix the
    // crate had no `error!` anywhere and this assertion fails.
    #[tracing_test::traced_test]
    #[test]
    fn checksum_failure_logs_error_before_returning() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = vcfg(false, false);
        let inputs = VerifyInputs {
            expected_sha256: Some("00".repeat(32)),
            ..Default::default()
        };
        let err = verify_artifact(&cfg, &art, None, &inputs).unwrap_err();
        assert_eq!(err.code(), "updater_verify");
        // The failure must have been logged at ERROR (not swallowed).
        logs_assert(|lines: &[&str]| {
            if lines
                .iter()
                .any(|l| l.contains("ERROR") && l.contains("SHA-256 verification FAILED"))
            {
                Ok(())
            } else {
                Err(format!(
                    "expected an ERROR verify-failure log, got: {lines:?}"
                ))
            }
        });
    }

    #[tracing_test::traced_test]
    #[test]
    fn required_minisign_absent_logs_error() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let cfg = vcfg(true, false);
        let _ = verify_artifact(&cfg, &art, None, &VerifyInputs::default()).unwrap_err();
        logs_assert(|lines: &[&str]| {
            if lines
                .iter()
                .any(|l| l.contains("ERROR") && l.contains("refusing artifact"))
            {
                Ok(())
            } else {
                Err(format!("expected an ERROR fail-closed log, got: {lines:?}"))
            }
        });
    }

    #[test]
    fn minisign_invalid_signature_file_errors() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", b"abc");
        let sig = write_tmp(tmp.path(), "a.bin.minisig", b"not a signature");
        // A syntactically valid 42-byte-decoding minisign pubkey is needed
        // to even load; a garbage key fails to load → Verify error.
        let pk = write_tmp(tmp.path(), "key.pub", b"untrusted\nINVALIDBASE64====");
        let err = verify_minisign(&art, &sig, &pk).unwrap_err();
        assert_eq!(err.code(), "updater_verify");
    }

    // --- Genuine minisign/ed25519 signature-verification fixtures ----------
    //
    // These exercise the real `pk.verify(...)` cryptographic path (the
    // security-critical branch at the `verify_minisign` end that all the
    // malformed-material tests above stop short of). The fixtures are real
    // minisign material: two ed25519 keypairs (K1, K2) and a genuine
    // prehashed (`ED`) detached signature over `ARTIFACT_A` produced with
    // K1's secret key. They were generated deterministically from fixed
    // seeds (K1 = bytes 0x00..0x1f, K2 = those XOR 0xAA) with a standalone
    // RFC-8032 ed25519 signer + BLAKE2b-512 prehash — `minisign-verify` is
    // verify-only and adding a signer would grow `Cargo.lock`. The fixtures
    // are NOT a mock: they are validated against this very `minisign-verify`
    // crate below, and flipping one artifact byte or swapping the public key
    // makes the real ed25519 verify reject.
    //
    // If `verify` ever regressed to accept-anything (`Ok(())`), every
    // `*_rejected` test below flips from red to unexpectedly green.

    const ARTIFACT_A: &[u8] = b"spt-update-artifact-A: the genuinely signed payload v1\n";

    const PUBKEY_K1: &str = "untrusted comment: minisign public key K1 (spt-updater test)\nRWQRIjNEVWZ3iAOhB7/zzhC+HXDdGOdLwJln5NYwm6UNXx3chmQSVTG4\n";

    // A completely independent keypair (different key material AND key_id).
    const PUBKEY_K2: &str = "untrusted comment: minisign public key K2 (spt-updater test)\nRWSZqrvM3e7/AK1v+ZsuEJsWF/LuvsmUJWAnF9i27gwPnC3nYZVGYRD9\n";

    // K2's key material stamped with K1's key_id: the cheap key_id precheck
    // passes, so rejection must come from the real ed25519 verify itself.
    const PUBKEY_K2_ID1: &str = "untrusted comment: minisign public key K2-as-K1id (spt-updater test)\nRWQRIjNEVWZ3iK1v+ZsuEJsWF/LuvsmUJWAnF9i27gwPnC3nYZVGYRD9\n";

    // Valid detached signature over ARTIFACT_A, produced with K1's secret key.
    const SIG_A_BY_K1: &str = "untrusted comment: signature from spt-updater test key K1\nRUQRIjNEVWZ3iHOEwR0LOSyDA8/E19Io8BltLGGGrveklzKGXNrec+8ZjgQCef1TlKB75GeG1Bkv7DgE5I1UgQTnzsfTM4uebgc=\ntrusted comment: timestamp:1700000000\tfile:a.bin\tprehashed\nxHmt+2qAC79VxwdYwvcOk4w7F1gHGxiDkqlWOykSLUQY3VOm5OQDabXDt1b4TTlnE+m0Lb0jGMQ69HX2fPTMBQ==\n";

    /// Materialize the artifact + `.minisig` + pubkey fixtures into `dir` and
    /// return `(artifact, signature, pubkey)` paths.
    fn minisign_fixture(
        dir: &Path,
        artifact_bytes: &[u8],
        pubkey_txt: &str,
    ) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let art = write_tmp(dir, "a.bin", artifact_bytes);
        let sig = write_tmp(dir, "a.bin.minisig", SIG_A_BY_K1.as_bytes());
        let pk = write_tmp(dir, "minisign.pub", pubkey_txt.as_bytes());
        (art, sig, pk)
    }

    /// Requirement #2: correct key + correct artifact + correct signature → Ok.
    /// If this fails, the fixtures themselves are broken (guards the negative
    /// tests below from being vacuously green).
    #[test]
    fn minisign_valid_signature_accepted() {
        let tmp = tempfile::tempdir().unwrap();
        let (art, sig, pk) = minisign_fixture(tmp.path(), ARTIFACT_A, PUBKEY_K1);
        verify_minisign(&art, &sig, &pk).expect("genuine signature over A by K1 must verify");
    }

    /// Requirement #1a — FORGERY: a valid signature over artifact A is
    /// presented against artifact B (one byte flipped), with A's own public
    /// key (`key_id` still matches, so this reaches and is rejected by the
    /// real ed25519 verify — not the `key_id` precheck). MUST reject.
    #[test]
    fn minisign_forged_over_tampered_artifact_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        // Artifact B: ARTIFACT_A with a single trailing byte flipped.
        let mut tampered = ARTIFACT_A.to_vec();
        *tampered.last_mut().unwrap() ^= 0x01;
        assert_ne!(tampered.as_slice(), ARTIFACT_A);
        let (art, sig, pk) = minisign_fixture(tmp.path(), &tampered, PUBKEY_K1);
        let err = verify_minisign(&art, &sig, &pk)
            .expect_err("signature over A must NOT verify against tampered artifact B");
        assert_eq!(err.code(), "updater_verify");
        assert!(err.to_string().contains("minisign verification failed"));
    }

    /// Requirement #1b — WRONG KEY (real crypto): sign with K1, verify with a
    /// DIFFERENT public key. K2 is stamped with K1's `key_id` so the `key_id`
    /// precheck passes and the rejection is produced by `pk.verify` itself.
    /// MUST reject.
    #[test]
    fn minisign_wrong_public_key_same_keyid_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let (art, sig, pk) = minisign_fixture(tmp.path(), ARTIFACT_A, PUBKEY_K2_ID1);
        let err = verify_minisign(&art, &sig, &pk)
            .expect_err("K1's signature must NOT verify under K2's public key");
        assert_eq!(err.code(), "updater_verify");
    }

    /// Requirement #1b (belt-and-suspenders): an entirely independent key
    /// (different `key_id` too) also rejects. Covers the `key_id` mismatch
    /// guard.
    #[test]
    fn minisign_wrong_public_key_different_keyid_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let (art, sig, pk) = minisign_fixture(tmp.path(), ARTIFACT_A, PUBKEY_K2);
        let err = verify_minisign(&art, &sig, &pk)
            .expect_err("K1's signature must NOT verify under unrelated key K2");
        assert_eq!(err.code(), "updater_verify");
    }

    /// A corrupted (bit-flipped) signature blob over the correct artifact with
    /// the correct key MUST reject — proves the signature bytes are actually
    /// consumed by the verify, not ignored.
    #[test]
    fn minisign_tampered_signature_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", ARTIFACT_A);
        let pk = write_tmp(tmp.path(), "minisign.pub", PUBKEY_K1.as_bytes());
        // Swap one character in the middle of the base64 signature line
        // (line 2). base64 is ASCII, so `len()/2` is a valid char boundary.
        let mut lines: Vec<String> = SIG_A_BY_K1.lines().map(str::to_string).collect();
        let sig_line = &lines[1];
        let mid = sig_line.len() / 2;
        let (head, tail) = sig_line.split_at(mid);
        let mut chars = tail.chars();
        let first = chars.next().unwrap();
        let repl = if first == 'A' { 'B' } else { 'A' };
        lines[1] = format!("{head}{repl}{}", chars.as_str());
        let tampered_sig = format!("{}\n", lines.join("\n"));
        let sig = write_tmp(tmp.path(), "a.bin.minisig", tampered_sig.as_bytes());
        // Either a decode error or an InvalidSignature — both are `Err`.
        assert!(
            verify_minisign(&art, &sig, &pk).is_err(),
            "a tampered signature blob must never verify"
        );
    }

    /// Full policy path (`verify_artifact`): `require_minisign = true` with a
    /// configured pubkey + a genuine signature over the artifact → Ok.
    #[test]
    fn verify_artifact_accepts_required_valid_minisign() {
        let tmp = tempfile::tempdir().unwrap();
        let (art, sig, pk) = minisign_fixture(tmp.path(), ARTIFACT_A, PUBKEY_K1);
        let cfg = VerifyConfig {
            require_minisign: true,
            minisign_pubkey: Some(pk),
            require_sha256sums: false,
            gpg_pubkey: None,
        };
        verify_artifact(&cfg, &art, Some(&sig), &VerifyInputs::default())
            .expect("required minisign with valid material must pass");
    }

    /// Full policy path: `require_minisign = true`, valid pubkey + signature,
    /// but the artifact bytes were tampered → the whole verification MUST
    /// fail (fail-closed). This is the end-to-end supply-chain guard: a
    /// regressed verify would silently install artifact B.
    #[test]
    fn verify_artifact_rejects_required_forged_minisign() {
        let tmp = tempfile::tempdir().unwrap();
        let mut tampered = ARTIFACT_A.to_vec();
        tampered.extend_from_slice(b"EVIL");
        let (art, sig, pk) = minisign_fixture(tmp.path(), &tampered, PUBKEY_K1);
        let cfg = VerifyConfig {
            require_minisign: true,
            minisign_pubkey: Some(pk),
            require_sha256sums: false,
            gpg_pubkey: None,
        };
        let err = verify_artifact(&cfg, &art, Some(&sig), &VerifyInputs::default())
            .expect_err("required minisign over a tampered artifact must fail closed");
        assert_eq!(err.code(), "updater_verify");
    }

    /// Fail-closed: `require_minisign = true` and a pubkey is configured, but
    /// NO signature file was downloaded → verify aborts (the intended
    /// fail-closed posture), even though the pubkey material is valid.
    #[test]
    fn verify_artifact_required_minisign_no_signature_fails_closed() {
        let tmp = tempfile::tempdir().unwrap();
        let art = write_tmp(tmp.path(), "a.bin", ARTIFACT_A);
        let pk = write_tmp(tmp.path(), "minisign.pub", PUBKEY_K1.as_bytes());
        let cfg = VerifyConfig {
            require_minisign: true,
            minisign_pubkey: Some(pk),
            require_sha256sums: false,
            gpg_pubkey: None,
        };
        let err = verify_artifact(&cfg, &art, None, &VerifyInputs::default())
            .expect_err("required minisign with no signature must fail closed");
        assert_eq!(err.code(), "updater_verify");
    }

    /// Best-effort (`require_minisign = false`): a PRESENT-but-forged
    /// signature must still be rejected. Best-effort only tolerates *absent*
    /// material — present-but-wrong always fails.
    #[test]
    fn verify_artifact_best_effort_rejects_present_forged_minisign() {
        let tmp = tempfile::tempdir().unwrap();
        let mut tampered = ARTIFACT_A.to_vec();
        *tampered.last_mut().unwrap() ^= 0xFF;
        let (art, sig, pk) = minisign_fixture(tmp.path(), &tampered, PUBKEY_K1);
        let cfg = VerifyConfig {
            require_minisign: false,
            minisign_pubkey: Some(pk),
            require_sha256sums: false,
            gpg_pubkey: None,
        };
        let err = verify_artifact(&cfg, &art, Some(&sig), &VerifyInputs::default())
            .expect_err("a present-but-forged signature must fail even in best-effort mode");
        assert_eq!(err.code(), "updater_verify");
    }
}
