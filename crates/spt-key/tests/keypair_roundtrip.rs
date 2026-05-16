//! Public-API round-trip integration tests for `spt-key`.
//!
//! Exercises `generate` -> `save_encrypted` -> `load` for each supported
//! algorithm together with `sign_cert` / `verify_cert` across algorithm
//! pairings. RSA cases live behind `#[ignore]` because keygen is slow.

use spt_key::{
    fingerprint_sha256, generate, load, save_encrypted, sign_cert, verify_cert, CertOptions,
    KeyAlgorithm,
};
use tempfile::tempdir;

#[test]
fn ed25519_generate_save_load_roundtrip() {
    let kp = generate(KeyAlgorithm::Ed25519).unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("id_ed25519");

    save_encrypted(&kp, &path, None).unwrap();
    let loaded = load(&path, None).unwrap();
    assert_eq!(
        fingerprint_sha256(loaded.public_ref()),
        fingerprint_sha256(kp.public_ref())
    );
    assert_eq!(loaded.algorithm(), Some(KeyAlgorithm::Ed25519));
}

#[test]
fn ed25519_encrypted_roundtrip() {
    let kp = generate(KeyAlgorithm::Ed25519).unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("id_ed25519_enc");

    save_encrypted(&kp, &path, Some("correct horse battery staple")).unwrap();
    // Missing passphrase on encrypted key fails.
    assert!(load(&path, None).is_err());
    // Wrong passphrase fails with auth-failed shape.
    assert!(load(&path, Some("wrong")).is_err());
    // Correct passphrase succeeds and fingerprint matches.
    let loaded = load(&path, Some("correct horse battery staple")).unwrap();
    assert_eq!(
        fingerprint_sha256(loaded.public_ref()),
        fingerprint_sha256(kp.public_ref())
    );
}

#[test]
fn ecdsa_p256_generate_save_load_roundtrip() {
    let kp = generate(KeyAlgorithm::EcdsaP256).unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("id_p256");

    save_encrypted(&kp, &path, Some("pw")).unwrap();
    let loaded = load(&path, Some("pw")).unwrap();
    assert_eq!(
        fingerprint_sha256(loaded.public_ref()),
        fingerprint_sha256(kp.public_ref())
    );
    assert_eq!(loaded.algorithm(), Some(KeyAlgorithm::EcdsaP256));
}

#[test]
fn cert_sign_and_verify_ed25519_to_ed25519() {
    let ca = generate(KeyAlgorithm::Ed25519).unwrap();
    let subject = generate(KeyAlgorithm::Ed25519).unwrap();

    let cert = sign_cert(
        &ca,
        subject.public_ref(),
        CertOptions {
            key_id: "alice@spt".into(),
            principals: vec!["alice".into(), "alice@host".into()],
            ..CertOptions::default()
        },
    )
    .unwrap();

    verify_cert(&cert, &[ca.public()]).unwrap();
}

#[test]
fn cert_sign_ed25519_ca_p256_subject() {
    let ca = generate(KeyAlgorithm::Ed25519).unwrap();
    let subject = generate(KeyAlgorithm::EcdsaP256).unwrap();

    let cert = sign_cert(
        &ca,
        subject.public_ref(),
        CertOptions {
            key_id: "p256-subj".into(),
            principals: vec!["bob".into()],
            ..CertOptions::default()
        },
    )
    .unwrap();
    verify_cert(&cert, &[ca.public()]).unwrap();
}

// RSA cases are slow; gated.
#[test]
#[ignore = "RSA-3072 keygen is slow (~5s+)"]
fn rsa3072_generate_save_load_roundtrip() {
    let kp = generate(KeyAlgorithm::Rsa3072).unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("id_rsa3072");
    save_encrypted(&kp, &path, None).unwrap();
    let loaded = load(&path, None).unwrap();
    assert_eq!(loaded.algorithm(), Some(KeyAlgorithm::Rsa3072));
}

#[test]
#[ignore = "RSA-4096 keygen is very slow"]
fn rsa4096_generate_save_load_roundtrip() {
    let kp = generate(KeyAlgorithm::Rsa4096).unwrap();
    let dir = tempdir().unwrap();
    let path = dir.path().join("id_rsa4096");
    save_encrypted(&kp, &path, Some("rsa-pass")).unwrap();
    let loaded = load(&path, Some("rsa-pass")).unwrap();
    assert_eq!(loaded.algorithm(), Some(KeyAlgorithm::Rsa4096));
}
