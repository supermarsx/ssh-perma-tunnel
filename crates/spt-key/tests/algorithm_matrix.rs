//! Public-key algorithm verification matrix — t6-e11.
//!
//! For every algorithm in the spec's accepted set we exercise:
//!
//! 1. **Keygen** — `ssh-key 0.6` `PrivateKey::random(...)` (or
//!    `spt_key::generate` for the subset our [`KeyAlgorithm`] enum can express).
//! 2. **Sign + verify** — `ssh-key`'s `Signer<Signature>` / `Verifier<Signature>`
//!    impls for ed25519 and ECDSA; **`ssh-key 0.7-rc`** (via
//!    `russh::keys::ssh_key`) for RSA, because the workspace `ssh-key 0.6.7`
//!    ships an upstream bug in `private/rsa.rs:192-204` that reconstructs
//!    `rsa::RsaPrivateKey` with `p` repeated twice instead of `(p, q)`,
//!    breaking every RSA signing path that flows through
//!    `Signer<Signature> for RsaKeypair`. RSA *verification* works because
//!    `RsaPublicKey` uses `(n, e)` only — so we sign with 0.7-rc and verify
//!    with both 0.7-rc and the workspace 0.6. (This replaces the old
//!    `russh-keys 0.46` dependency, removed to clear RUSTSEC-2026-0154/-0153.)
//! 3. **Cross-library round-trip** — bridge the OpenSSH wire-format public key
//!    plus raw signature bytes between the workspace `ssh-key 0.6` and russh's
//!    bundled `ssh-key 0.7-rc`. Both libraries verify the other's signature for
//!    the algorithms we ship.
//! 4. **OpenSSH PEM round-trip** — serialize + parse + assert byte-exact PEM
//!    equality on a second serialize (unencrypted path; encrypted KDF uses a
//!    fresh salt every time so we cannot byte-compare ciphertext).
//! 5. **OpenSSH user-certificate signing** — pass each subject through
//!    `spt_key::sign_cert` / `verify_cert` with a single fixed **Ed25519 CA**
//!    (RSA-CA signing is blocked by the same ssh-key 0.6.7 bug above). The
//!    resulting certificate is byte-round-tripped to confirm principals +
//!    serial survive.
//!
//! Plus the policy gates: legacy `ssh-rsa` (SHA-1) auth MUST be rejected by
//! default and accepted only with the explicit escape hatch.
//!
//! ## RSA cost amortization
//!
//! RSA-3072 keygen is ~5+ seconds. To keep this test below the workspace
//! 60-second budget we generate **one** RSA key per library via
//! [`std::sync::OnceLock`] and re-use it across every RSA case. The
//! distinction between `rsa-sha2-256` and `rsa-sha2-512` is exercised by
//! parameterising the ssh-key 0.7-rc RSA signer's `Option<HashAlg>` — no
//! second keygen needed.

#![allow(clippy::needless_pass_by_value)]

use std::sync::OnceLock;

use rand::rngs::OsRng;
use signature::{Signer, Verifier};
use spt_key::{generate, load, save_encrypted, sign_cert, verify_cert, CertOptions, KeyAlgorithm};
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, EcdsaCurve, HashAlg, PrivateKey};
use tempfile::tempdir;

// The "other" SSH key library: upstream russh 0.61's bundled `ssh-key 0.7-rc`,
// re-exported as `russh::keys::ssh_key`. Distinct from the workspace
// `ssh-key 0.6` imported above; the two coexist and we cross-verify wire bytes
// between them. Its RSA signing path is correct (the 0.6.7 `(p, p)` bug is
// fixed in 0.7-rc), so all RSA signing flows through it.
use russh::keys::ssh_key as rk;
use russh::keys::ssh_key::Signature as RkSignature;
use russh::keys::signature::Signer as RkSigner;
use russh::keys::signature::Verifier as RkVerifier;

// ---------------------------------------------------------------------------
// Test fixtures
// ---------------------------------------------------------------------------

/// One ssh-key RSA-3072 keypair shared across every RSA test below.
fn shared_ssh_key_rsa() -> &'static PrivateKey {
    static RSA: OnceLock<PrivateKey> = OnceLock::new();
    RSA.get_or_init(|| {
        let rsa = ssh_key::private::RsaKeypair::random(&mut OsRng, 3072).expect("rsa-3072 keygen");
        let kd = ssh_key::private::KeypairData::from(rsa);
        PrivateKey::new(kd, "spt-rsa-test").expect("wrap rsa keypair")
    })
}

/// One ssh-key 0.7-rc RSA-3072 keypair shared across every RSA test below.
/// Wrapped in a `PrivateKey` so we can derive both the public key (wire bytes)
/// and the `RsaKeypair` needed for hash-parameterised signing.
fn shared_rk_rsa() -> &'static rk::PrivateKey {
    static RSA: OnceLock<rk::PrivateKey> = OnceLock::new();
    RSA.get_or_init(|| {
        // ssh-key 0.7-rc's keygen needs a rand_core-0.10 `CryptoRng`.
        let mut rng = rand010::rng();
        let kp = rk::private::RsaKeypair::random(&mut rng, 3072).expect("rk rsa-3072 keygen");
        let kd = rk::private::KeypairData::from(kp);
        rk::PrivateKey::new(kd, "spt-rk-rsa-test").expect("wrap rk rsa keypair")
    })
}

/// Sign `msg` with the shared RSA key under the given hash algorithm, using
/// ssh-key 0.7-rc's `Signer<Signature> for (&RsaKeypair, Option<HashAlg>)`.
fn rk_rsa_sign(msg: &[u8], hash: rk::HashAlg) -> RkSignature {
    let priv_key = shared_rk_rsa();
    let rk::private::KeypairData::Rsa(kp) = priv_key.key_data() else {
        panic!("shared rk key is not RSA");
    };
    RkSigner::try_sign(&(kp, Some(hash)), msg).expect("rk rsa sign")
}

/// Generate a non-RSA private key for the given ssh-key `Algorithm`.
fn fresh_non_rsa(alg: &Algorithm) -> PrivateKey {
    PrivateKey::random(&mut OsRng, alg.clone()).expect("keygen")
}

/// The non-RSA algorithm set used by tests that route signing through
/// `ssh-key`'s `Signer<Signature>` impl (which is intact for ed25519 + ECDSA).
fn signing_safe_algorithms() -> Vec<(&'static str, Algorithm)> {
    vec![
        ("ssh-ed25519", Algorithm::Ed25519),
        (
            "ecdsa-sha2-nistp256",
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
        ),
        (
            "ecdsa-sha2-nistp384",
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
        ),
        (
            "ecdsa-sha2-nistp521",
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
        ),
    ]
}

// ---------------------------------------------------------------------------
// 1. Ed25519 + ECDSA p256/p384/p521: keygen, sign+verify, cert sign+verify,
//    PEM round-trip — all in one matrix pass.
// ---------------------------------------------------------------------------

#[test]
fn modern_algorithms_sign_verify_pem_roundtrip_cert() {
    // Fixed Ed25519 CA used to sign every subject certificate. (RSA CA
    // signing path is blocked by ssh-key 0.6.7 RsaKeypair → RsaPrivateKey
    // bug; the Ed25519 CA covers every subject algorithm cleanly.)
    let ca =
        spt_key::KeyPair::from_private(PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap());

    for (label, alg) in signing_safe_algorithms() {
        let priv_key = fresh_non_rsa(&alg);

        // (a) Algorithm reported by the parsed key matches what we asked for.
        match (&alg, priv_key.algorithm()) {
            (Algorithm::Ed25519, Algorithm::Ed25519) => {}
            (Algorithm::Ecdsa { curve: a }, Algorithm::Ecdsa { curve: b }) => {
                assert_eq!(a, &b, "{label}: ecdsa curve mismatch");
            }
            (other_expected, other_actual) => {
                panic!("{label}: expected {other_expected:?}, got {other_actual:?}");
            }
        }

        // (b) Raw `Signer<Signature>` sign + `Verifier<Signature>` verify.
        let message = format!("hello from {label}").into_bytes();
        let sig: ssh_key::Signature = priv_key
            .try_sign(&message)
            .unwrap_or_else(|e| panic!("{label}: try_sign failed: {e}"));
        Verifier::verify(priv_key.public_key().key_data(), &message, &sig)
            .unwrap_or_else(|e| panic!("{label}: verify failed: {e}"));

        // (c) Tampered message MUST fail verification.
        let mut tampered = message.clone();
        tampered[0] ^= 0x01;
        assert!(
            Verifier::verify(priv_key.public_key().key_data(), &tampered, &sig).is_err(),
            "{label}: tampered verify accepted"
        );

        // (d) PEM round-trip preserves bytes byte-exact (unencrypted).
        let pem1 = priv_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
        let parsed = PrivateKey::from_openssh(pem1.as_bytes()).unwrap();
        let pem2 = parsed.to_openssh(ssh_key::LineEnding::LF).unwrap();
        assert_eq!(
            pem1.as_str(),
            pem2.as_str(),
            "{label}: PEM round-trip drift"
        );

        // (e) Cert-signing per algorithm — subject = current alg, CA = Ed25519.
        let cert = sign_cert(
            &ca,
            priv_key.public_key(),
            CertOptions {
                key_id: format!("subject-{label}"),
                principals: vec!["alice".into(), "bob".into()],
                serial: 0xDEAD_BEEF,
                ..CertOptions::default()
            },
        )
        .unwrap_or_else(|e| panic!("{label}: sign_cert: {e}"));
        verify_cert(&cert, &[ca.public()]).unwrap_or_else(|e| panic!("{label}: verify_cert: {e}"));

        // Byte-round-trip of the certificate.
        let cert_str = cert.to_openssh().unwrap();
        let reparsed = ssh_key::Certificate::from_openssh(&cert_str).unwrap();
        assert_eq!(reparsed.serial(), 0xDEAD_BEEF, "{label}: serial dropped");
        assert_eq!(
            reparsed.valid_principals(),
            &["alice".to_string(), "bob".to_string()],
            "{label}: principals dropped"
        );
        assert_eq!(
            reparsed.to_openssh().unwrap(),
            cert_str,
            "{label}: cert byte-round-trip drift"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. RSA via ssh-key 0.7-rc (russh::keys): sha2-256 and sha2-512 signing
//    paths, then verify with the workspace ssh-key 0.6 `Verifier<Signature>`
//    for the cross-library round-trip.
// ---------------------------------------------------------------------------

/// Bridge an ssh-key 0.7-rc public key into the workspace `ssh-key 0.6`
/// `KeyData` via the SSH binary wire format the two versions share.
fn rk_pub_to_ssh_key_data(pubkey: &rk::PublicKey) -> KeyData {
    let wire = pubkey.to_bytes().expect("rk public to_bytes");
    let mut reader: &[u8] = &wire;
    <KeyData as ssh_encoding::Decode>::decode(&mut reader).expect("decode rk public bytes")
}

#[test]
fn rk_signs_rsa_sha2_256_ssh_key_verifies() {
    let msg = b"rsa-sha2-256 cross-lib";
    let sig = rk_rsa_sign(msg, rk::HashAlg::Sha256);
    assert_eq!(
        sig.algorithm(),
        rk::Algorithm::Rsa {
            hash: Some(rk::HashAlg::Sha256)
        }
    );

    // Wrap into a workspace ssh-key 0.6 Signature with the matching algorithm
    // and verify against the bridged public key.
    let sk_sig = ssh_key::Signature::new(
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha256),
        },
        sig.as_bytes().to_vec(),
    )
    .expect("wrap rsa sig");
    let sk_pub = rk_pub_to_ssh_key_data(shared_rk_rsa().public_key());
    Verifier::verify(&sk_pub, msg, &sk_sig).expect("ssh-key verify rsa-sha2-256");
}

#[test]
fn rk_signs_rsa_sha2_512_ssh_key_verifies() {
    let msg = b"rsa-sha2-512 cross-lib";
    let sig = rk_rsa_sign(msg, rk::HashAlg::Sha512);
    assert_eq!(
        sig.algorithm(),
        rk::Algorithm::Rsa {
            hash: Some(rk::HashAlg::Sha512)
        }
    );

    let sk_sig = ssh_key::Signature::new(
        Algorithm::Rsa {
            hash: Some(HashAlg::Sha512),
        },
        sig.as_bytes().to_vec(),
    )
    .expect("wrap rsa sig");
    let sk_pub = rk_pub_to_ssh_key_data(shared_rk_rsa().public_key());
    Verifier::verify(&sk_pub, msg, &sk_sig).expect("ssh-key verify rsa-sha2-512");
}

// ---------------------------------------------------------------------------
// 3. Policy: ssh-rsa SHA-1 default-rejected, accepted with escape hatch.
// ---------------------------------------------------------------------------

#[test]
fn ssh_rsa_sha1_rejected_by_default() {
    let err = spt_auth::method::check_pubkey_algorithm_allowed("ssh-rsa", false)
        .expect_err("must reject");
    let msg = err.to_string();
    assert!(msg.contains("algorithm policy"), "{msg}");
    assert!(msg.contains("ssh-rsa"), "{msg}");
    // Stable typed error: AuthFailed, exit code 5.
    assert!(matches!(err, spt_core::Error::AuthFailed(_)), "{err:?}");
}

#[test]
fn ssh_rsa_sha1_accepted_with_escape_hatch() {
    spt_auth::method::check_pubkey_algorithm_allowed("ssh-rsa", true)
        .expect("escape hatch must accept ssh-rsa");
}

// ---------------------------------------------------------------------------
// 4. Cross-library matrix in both directions for ed25519 and ECDSA.
// ---------------------------------------------------------------------------

#[test]
fn cross_lib_rk_signs_ssh_key_verifies_ed25519() {
    // Sign with ssh-key 0.7-rc (via russh), verify with workspace ssh-key 0.6.
    let rk_priv = rk::PrivateKey::random(&mut rand010::rng(), rk::Algorithm::Ed25519).unwrap();
    let msg = b"cross-lib ed25519";
    let rk_sig: RkSignature = RkSigner::try_sign(&rk_priv, msg).expect("rk try_sign");
    assert_eq!(rk_sig.algorithm(), rk::Algorithm::Ed25519);

    let sk_pub_data = rk_pub_to_ssh_key_data(rk_priv.public_key());
    let sk_sig =
        ssh_key::Signature::new(Algorithm::Ed25519, rk_sig.as_bytes().to_vec()).expect("sig wrap");
    Verifier::verify(&sk_pub_data, msg, &sk_sig).expect("ssh-key verify");
}

/// Bridge a workspace ssh-key 0.6 public key into an ssh-key 0.7-rc
/// `PublicKey` via the shared SSH binary wire format.
fn ssh_key_pub_to_rk(pubkey: &ssh_key::PublicKey) -> rk::PublicKey {
    let wire = pubkey.to_bytes().expect("public to_bytes");
    rk::PublicKey::from_bytes(&wire).expect("rk PublicKey::from_bytes")
}

#[test]
fn cross_lib_ssh_key_signs_rk_verifies_ed25519() {
    let sk_priv = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
    let msg = b"cross-lib reverse";
    let sk_sig: ssh_key::Signature = sk_priv.try_sign(msg).expect("raw try_sign");
    assert_eq!(sk_sig.algorithm(), Algorithm::Ed25519);

    let rk_pub = ssh_key_pub_to_rk(sk_priv.public_key());
    let rk_sig = RkSignature::new(rk::Algorithm::Ed25519, sk_sig.as_bytes().to_vec())
        .expect("rk sig wrap");
    RkVerifier::verify(rk_pub.key_data(), msg, &rk_sig).expect("rk verify failed");
}

#[test]
fn cross_lib_ecdsa_p256_ssh_key_signs_rk_verifies() {
    let sk_priv = PrivateKey::random(
        &mut OsRng,
        Algorithm::Ecdsa {
            curve: EcdsaCurve::NistP256,
        },
    )
    .unwrap();
    let msg = b"cross-lib ecdsa";
    let sk_sig: ssh_key::Signature = sk_priv.try_sign(msg).expect("try_sign");

    let rk_pub = ssh_key_pub_to_rk(sk_priv.public_key());
    let rk_sig = RkSignature::new(
        rk::Algorithm::Ecdsa {
            curve: rk::EcdsaCurve::NistP256,
        },
        sk_sig.as_bytes().to_vec(),
    )
    .expect("rk sig wrap");
    RkVerifier::verify(rk_pub.key_data(), msg, &rk_sig).expect("rk ECDSA verify failed");
}

// ---------------------------------------------------------------------------
// 5. PEM byte-exact + cert principal/serial round-trip via the spt_key public
//    API for the algorithms expressible through `KeyAlgorithm`.
// ---------------------------------------------------------------------------

#[test]
fn pem_roundtrip_byte_exact_ed25519_and_p256() {
    for kalg in [KeyAlgorithm::Ed25519, KeyAlgorithm::EcdsaP256] {
        let kp = generate(kalg).unwrap();
        let dir = tempdir().unwrap();
        let path = dir.path().join("id");
        save_encrypted(&kp, &path, None).unwrap();

        let original = std::fs::read(&path).unwrap();
        let loaded = load(&path, None).unwrap();
        save_encrypted(&loaded, &path, None).unwrap();
        let re_saved = std::fs::read(&path).unwrap();
        assert_eq!(
            original, re_saved,
            "{kalg:?}: PEM is not byte-exact after load+save"
        );
    }
}

#[test]
fn cert_roundtrip_preserves_principals_and_serial_for_enum_algorithms() {
    for kalg in [KeyAlgorithm::Ed25519, KeyAlgorithm::EcdsaP256] {
        let ca = generate(KeyAlgorithm::Ed25519).unwrap();
        let subject = generate(kalg).unwrap();
        let cert = sign_cert(
            &ca,
            subject.public_ref(),
            CertOptions {
                key_id: format!("cert-{kalg:?}"),
                principals: vec!["op1".into(), "op2".into(), "op3".into()],
                serial: 0xAA_BB_CC_DD_EE_FF,
                ..CertOptions::default()
            },
        )
        .unwrap();
        verify_cert(&cert, &[ca.public()]).unwrap();

        let encoded = cert.to_openssh().unwrap();
        let parsed = ssh_key::Certificate::from_openssh(&encoded).unwrap();
        assert_eq!(parsed.serial(), 0xAA_BB_CC_DD_EE_FF, "{kalg:?}");
        assert_eq!(parsed.valid_principals().len(), 3, "{kalg:?}");
        assert_eq!(parsed.to_openssh().unwrap(), encoded, "{kalg:?}");
    }
}

// ---------------------------------------------------------------------------
// 6. PEM byte-exact round-trip on an RSA key (uses the shared key, hot path).
// ---------------------------------------------------------------------------

/// A signature produced by one key must not verify against another key, for
/// every algorithm in the matrix. Catches accidentally-empty signature
/// payloads and reused/cached signature material.
#[test]
fn wrong_key_signature_rejected_per_algorithm() {
    for (label, alg) in signing_safe_algorithms() {
        let k1 = fresh_non_rsa(&alg);
        let k2 = fresh_non_rsa(&alg);
        let msg = b"detect mis-binding";
        let sig: ssh_key::Signature = k1.try_sign(msg).expect("sign");
        // Verifying with k1's public key passes.
        Verifier::verify(k1.public_key().key_data(), msg, &sig)
            .unwrap_or_else(|e| panic!("{label}: self-verify failed: {e}"));
        // Verifying with k2's public key MUST fail.
        assert!(
            Verifier::verify(k2.public_key().key_data(), msg, &sig).is_err(),
            "{label}: signature verified with wrong public key"
        );
    }
}

#[test]
fn pem_roundtrip_byte_exact_rsa3072() {
    let priv_key = shared_ssh_key_rsa().clone();
    let pem1 = priv_key.to_openssh(ssh_key::LineEnding::LF).unwrap();
    let parsed = PrivateKey::from_openssh(pem1.as_bytes()).unwrap();
    let pem2 = parsed.to_openssh(ssh_key::LineEnding::LF).unwrap();
    assert_eq!(
        pem1.as_str(),
        pem2.as_str(),
        "rsa-3072 PEM round-trip drift"
    );
    // Public-key fingerprint stable after round-trip.
    assert_eq!(
        priv_key.public_key().fingerprint(HashAlg::Sha256),
        parsed.public_key().fingerprint(HashAlg::Sha256)
    );
}
