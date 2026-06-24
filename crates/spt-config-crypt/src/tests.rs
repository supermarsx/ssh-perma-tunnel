//! End-to-end tests for the SPTENC1 envelope.
//!
//! Per t5-e5 contract (≥15): round-trips across all four KDF variants,
//! wrong-passphrase rejects, tampering detection, signature verify, KDF
//! param sanity, nonce uniqueness, peek/is_sealed.

use rand::RngCore;

use crate::envelope::{Meta, MAGIC};
use crate::keygen::{generate_psk, generate_x25519, psk_id};
use crate::sealing::{is_sealed, peek_meta, seal, unseal, KeySource, Passphrase, X25519PublicKey};
use crate::signing::{sign, verify, verify_with_options, SigningKey, VerifyingKey};

// ---------------------------------------------------------------------------
// Fast-Argon2id helper. Default seal() uses m=64MiB which is too slow for
// the unit test loop; we wrap seal+unseal here to manually craft envelopes
// with a small Argon2 cost (still in the accepted bounds 8..=4MiB).
// ---------------------------------------------------------------------------
//
// Because real seal() picks the OWASP baseline, we test wrong-passphrase /
// round-trip on the **public** path with whatever seal/unseal produce.
// Many tests use vault-master or x25519 (no Argon2) which are fast.
// Argon2-specific tests cap at one or two invocations.

fn pp(bytes: &[u8]) -> Passphrase {
    // secrecy::SecretSlice<u8> = SecretBox<[u8]>. Constructed from Vec via
    // the blanket `From<Vec<T>> for SecretBox<[T]>` impl in secrecy 0.10.
    Passphrase::from(bytes.to_vec())
}

fn random_vault_master() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

fn fresh_x25519_secret() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    // Clamp per X25519 (the StaticSecret constructor does this internally).
    k
}

fn pub_from_secret(secret: &[u8; 32]) -> X25519PublicKey {
    let s = x25519_dalek::StaticSecret::from(*secret);
    X25519PublicKey::from(&s)
}

// ---------------------------------------------------------------------------
// 1. Round-trip: passphrase.
// ---------------------------------------------------------------------------
#[test]
fn roundtrip_passphrase() {
    let plaintext = b"[server]\nhost = \"example.com\"\n";
    let pass = pp(b"correct horse battery staple");
    let sealed = seal(plaintext, &KeySource::Passphrase(pass.clone())).unwrap();
    assert!(is_sealed(&sealed));
    let out = unseal(&sealed, &KeySource::Passphrase(pass)).unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(out.expose_secret().as_slice(), plaintext);
}

// ---------------------------------------------------------------------------
// 2. Round-trip: vault master.
// ---------------------------------------------------------------------------
#[test]
fn roundtrip_vault_master() {
    let plaintext = b"vault-master plaintext";
    let master = random_vault_master();
    let sealed = seal(plaintext, &KeySource::VaultMaster(master)).unwrap();
    let out = unseal(&sealed, &KeySource::VaultMaster(master)).unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(out.expose_secret().as_slice(), plaintext);
}

// ---------------------------------------------------------------------------
// 3. Round-trip: x25519 single recipient.
// ---------------------------------------------------------------------------
#[test]
fn roundtrip_x25519_single_recipient() {
    let plaintext = b"x25519 single recipient";
    let secret = fresh_x25519_secret();
    let pubkey = pub_from_secret(&secret);
    let sealed = seal(plaintext, &KeySource::X25519Recipients(vec![pubkey])).unwrap();
    let out = unseal(&sealed, &KeySource::X25519Secrets(vec![secret])).unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(out.expose_secret().as_slice(), plaintext);
}

// ---------------------------------------------------------------------------
// 4. Round-trip: x25519 multi-recipient (any holder can unseal).
// ---------------------------------------------------------------------------
#[test]
fn roundtrip_x25519_multi_recipient() {
    let plaintext = b"any of three can unseal";
    let secrets: Vec<[u8; 32]> = (0..3).map(|_| fresh_x25519_secret()).collect();
    let pubs: Vec<X25519PublicKey> = secrets.iter().map(pub_from_secret).collect();
    let sealed = seal(plaintext, &KeySource::X25519Recipients(pubs)).unwrap();

    // each holder can unseal independently
    for s in &secrets {
        let out = unseal(&sealed, &KeySource::X25519Secrets(vec![*s])).unwrap();
        use secrecy::ExposeSecret;
        assert_eq!(out.expose_secret().as_slice(), plaintext);
    }
}

// ---------------------------------------------------------------------------
// 5. Wrong-passphrase rejects with InvalidConfig (NOT SecretCryptoFailed).
// ---------------------------------------------------------------------------
#[test]
fn wrong_passphrase_rejects_with_invalid_config() {
    let sealed = seal(b"hello", &KeySource::Passphrase(pp(b"right"))).unwrap();
    let err = unseal(&sealed, &KeySource::Passphrase(pp(b"wrong"))).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidConfig(_));
}

// ---------------------------------------------------------------------------
// 6. Tamper ciphertext → AEAD-tag failure.
// ---------------------------------------------------------------------------
#[test]
fn tampered_ciphertext_rejects() {
    let master = random_vault_master();
    let mut sealed = seal(b"sensitive", &KeySource::VaultMaster(master)).unwrap();

    // Flip a byte near the end (inside the base64-encoded ciphertext).
    // Pick a position safely after the header but inside the body section.
    let len = sealed.len();
    sealed[len - 8] ^= 0x01;

    let err = unseal(&sealed, &KeySource::VaultMaster(master)).unwrap_err();
    // Either AEAD fails (SecretCryptoFailed) or the b64-decoded ciphertext
    // changed shape (also SecretCryptoFailed). Both are acceptable.
    matches::assert_matches!(err, spt_core::Error::SecretCryptoFailed(_));
}

// ---------------------------------------------------------------------------
// 7. Tamper magic → fail-fast "not sealed" before any KDF runs.
// ---------------------------------------------------------------------------
#[test]
fn tampered_magic_fails_fast() {
    let master = random_vault_master();
    let mut sealed = seal(b"x", &KeySource::VaultMaster(master)).unwrap();
    sealed[0] = b'X'; // SPTENC1 -> XPTENC1
    assert!(!is_sealed(&sealed));
    let err = unseal(&sealed, &KeySource::VaultMaster(master)).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::SecretCryptoFailed(msg) if msg.contains("not sealed"));
}

// ---------------------------------------------------------------------------
// 8. Signature: sign + verify succeeds.
// ---------------------------------------------------------------------------
#[test]
fn signature_verify_succeeds_when_configured() {
    let master = random_vault_master();
    let sealed = seal(b"signed payload", &KeySource::VaultMaster(master)).unwrap();

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let signed = sign(&sealed, &sk).unwrap();
    verify(&signed, &[vk]).unwrap();
}

// ---------------------------------------------------------------------------
// 9. Missing signature when required → TrustFailed.
// ---------------------------------------------------------------------------
#[test]
fn missing_signature_when_required_fails() {
    let master = random_vault_master();
    let unsigned = seal(b"payload", &KeySource::VaultMaster(master)).unwrap();

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let vk = SigningKey::from_bytes(&seed).verifying_key();

    let err = verify(&unsigned, &[vk]).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::TrustFailed(_));
}

// ---------------------------------------------------------------------------
// 10. Signature key not in allowed-keys → TrustFailed.
// ---------------------------------------------------------------------------
#[test]
fn signature_rejects_unknown_signer() {
    let master = random_vault_master();
    let sealed = seal(b"x", &KeySource::VaultMaster(master)).unwrap();

    let mut seed_a = [0u8; 32];
    let mut seed_b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed_a);
    rand::thread_rng().fill_bytes(&mut seed_b);
    let sk_a = SigningKey::from_bytes(&seed_a);
    let vk_b = SigningKey::from_bytes(&seed_b).verifying_key();

    let signed = sign(&sealed, &sk_a).unwrap();
    let err = verify(&signed, &[vk_b]).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::TrustFailed(_));
}

// ---------------------------------------------------------------------------
// 11. KDF param mismatch (envelope says vault, caller gives passphrase).
// ---------------------------------------------------------------------------
#[test]
fn kdf_variant_mismatch_rejected() {
    let master = random_vault_master();
    let sealed = seal(b"payload", &KeySource::VaultMaster(master)).unwrap();
    let err = unseal(&sealed, &KeySource::Passphrase(pp(b"any"))).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidConfig(msg) if msg.contains("kdf"));
}

// ---------------------------------------------------------------------------
// 12. KDF param-bounds check: refuse insane Argon2id memory cost.
// ---------------------------------------------------------------------------
#[test]
fn argon2id_parameter_out_of_bounds_rejected() {
    use crate::envelope::{
        body_to_bytes, meta_to_bytes, write_envelope, Argon2idParams, Body, MetaDoc,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};

    // Hand-craft an envelope claiming m=8 GiB.
    let meta = Meta {
        version: 1,
        aead: "aes-256-gcm".into(),
        kdf: "argon2id".into(),
        argon2id: Some(Argon2idParams {
            memory_kib: 8 * 1024 * 1024, // 8 GiB
            iterations: 3,
            parallelism: 4,
            salt_b64: B64.encode([0u8; 16]),
        }),
        recipients: vec![],
        vault: None,
        psk: None,
    };
    let meta_b = meta_to_bytes(&meta).unwrap();
    let body = Body {
        nonce_b64: B64.encode([0u8; 12]),
        ciphertext_b64: B64.encode([0u8; 32]),
    };
    let body_b = body_to_bytes(&body).unwrap();
    let env = write_envelope(&meta_b, &body_b, None).unwrap();

    let err = unseal(&env, &KeySource::Passphrase(pp(b"any"))).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidConfig(msg) if msg.contains("argon2id parameters"));
    let _ = MetaDoc { meta: meta.clone() }; // silence dead-code if MetaDoc gains private
}

// ---------------------------------------------------------------------------
// 13. Concurrent seals produce different nonces / different ciphertexts.
// ---------------------------------------------------------------------------
#[test]
fn concurrent_seals_produce_different_nonces() {
    let master = random_vault_master();
    let sealed_a = seal(b"hello", &KeySource::VaultMaster(master)).unwrap();
    let sealed_b = seal(b"hello", &KeySource::VaultMaster(master)).unwrap();
    // The envelopes must differ — fresh nonce + fresh salt every time.
    assert_ne!(sealed_a, sealed_b);
}

// ---------------------------------------------------------------------------
// 14. peek_meta works without a key.
// ---------------------------------------------------------------------------
#[test]
fn peek_meta_works_without_unsealing() {
    let master = random_vault_master();
    let sealed = seal(b"x", &KeySource::VaultMaster(master)).unwrap();
    let meta = peek_meta(&sealed).unwrap();
    assert_eq!(meta.version, 1);
    assert_eq!(meta.aead, "aes-256-gcm");
    assert_eq!(meta.kdf, "vault");
    assert!(meta.vault.is_some());
    assert!(meta.argon2id.is_none());
    assert!(meta.recipients.is_empty());
}

// ---------------------------------------------------------------------------
// 15. is_sealed: plain TOML returns false; sealed envelope returns true.
// ---------------------------------------------------------------------------
#[test]
fn is_sealed_discriminates_plain_vs_sealed() {
    let plain = b"[server]\nhost = \"example.com\"\n";
    assert!(!is_sealed(plain));
    let sealed = seal(plain, &KeySource::VaultMaster(random_vault_master())).unwrap();
    assert!(is_sealed(&sealed));
    assert!(!is_sealed(&[]));
    assert!(!is_sealed(b"SPTENC1")); // missing trailing \n
}

// ---------------------------------------------------------------------------
// Additional coverage (≥ baseline 15; these are bonus).
// ---------------------------------------------------------------------------

// 16. Tamper signature bytes → TrustFailed.
#[test]
fn tampered_signature_block_rejects() {
    let master = random_vault_master();
    let sealed = seal(b"x", &KeySource::VaultMaster(master)).unwrap();

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();

    let mut signed = sign(&sealed, &sk).unwrap();
    // Flip a byte near the end (inside the [signature] section).
    let n = signed.len();
    signed[n - 5] ^= 0x01;
    let err = verify(&signed, &[vk]).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::TrustFailed(_));
}

// 17. Tamper meta bytes after signing invalidates the signature.
//
// We flip one byte inside the base64-encoded salt — TOML still parses,
// the AAD changes, the signing input changes, signature fails.
#[test]
fn signature_covers_meta_section() {
    let master = random_vault_master();
    let sealed = seal(b"x", &KeySource::VaultMaster(master)).unwrap();

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let vk = sk.verifying_key();
    let mut signed = sign(&sealed, &sk).unwrap();

    // Locate the `salt_b64 = "...` line within the meta TOML and mutate
    // one b64 char to a different valid b64 char.
    let salt_marker = b"salt_b64 = \"";
    let pos = signed
        .windows(salt_marker.len())
        .position(|w| w == salt_marker)
        .expect("salt_b64 marker present");
    let target = pos + salt_marker.len();
    // Flip to another base64 character so TOML still parses.
    signed[target] = match signed[target] {
        b'A' => b'B',
        b'a' => b'b',
        b'0' => b'1',
        b'9' => b'8',
        b'+' => b'/',
        b'/' => b'+',
        b'=' => b'A',
        c if c.is_ascii_alphabetic() => c.wrapping_add(1),
        _ => b'A',
    };
    let err = verify(&signed, &[vk]).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::TrustFailed(_));
}

// 18. X25519 unseal with wrong private key → InvalidConfig.
#[test]
fn x25519_wrong_private_key_rejected() {
    let secret_a = fresh_x25519_secret();
    let secret_b = fresh_x25519_secret();
    let sealed = seal(
        b"x",
        &KeySource::X25519Recipients(vec![pub_from_secret(&secret_a)]),
    )
    .unwrap();
    let err = unseal(&sealed, &KeySource::X25519Secrets(vec![secret_b])).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidConfig(_));
}

// 19. Empty x25519 recipient list rejected at seal time.
#[test]
fn empty_x25519_recipient_list_rejected() {
    let err = seal(b"x", &KeySource::X25519Recipients(vec![])).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidArgs(_));
}

// 20. is_sealed for a truncated envelope (8 bytes of magic only) is true,
//     but unseal fails with a framing error.
#[test]
fn truncated_envelope_fails_framing() {
    let mut buf: Vec<u8> = MAGIC.to_vec();
    buf.extend_from_slice(&[0, 0, 0, 0]); // claims 0-byte meta
    assert!(is_sealed(&buf));
    let err = unseal(&buf, &KeySource::VaultMaster([0u8; 32])).unwrap_err();
    // Either truncated framing or KDF mismatch — both SecretCryptoFailed.
    matches::assert_matches!(err, spt_core::Error::SecretCryptoFailed(_));
}

// 21. Empty plaintext seals and round-trips.
#[test]
fn empty_plaintext_roundtrip() {
    let master = random_vault_master();
    let sealed = seal(b"", &KeySource::VaultMaster(master)).unwrap();
    let out = unseal(&sealed, &KeySource::VaultMaster(master)).unwrap();
    use secrecy::ExposeSecret;
    assert!(out.expose_secret().is_empty());
}

// 22. Large plaintext (1 MiB) round-trips under vault.
#[test]
fn large_plaintext_roundtrip() {
    let mut pt = vec![0u8; 1024 * 1024];
    rand::thread_rng().fill_bytes(&mut pt);
    let master = random_vault_master();
    let sealed = seal(&pt, &KeySource::VaultMaster(master)).unwrap();
    let out = unseal(&sealed, &KeySource::VaultMaster(master)).unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(out.expose_secret().as_slice(), pt.as_slice());
}

// 23. AAD binding: rewriting meta bytes in-place breaks the body AEAD.
#[test]
fn meta_bytes_are_aad_bound_to_body() {
    let master = random_vault_master();
    let sealed = seal(b"hello", &KeySource::VaultMaster(master)).unwrap();

    // Find the first byte of meta TOML and bit-flip it.
    let meta_start = MAGIC.len() + 4;
    let mut tampered = sealed.clone();
    tampered[meta_start] ^= 0x80;

    let err = unseal(&tampered, &KeySource::VaultMaster(master)).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::SecretCryptoFailed(_));
}

// 24. E2-F5: verify() with an empty allow-list is a hard error (fail-closed),
// but the explicit any_signed_ok opt-in still accepts any valid signature.
#[test]
fn verify_empty_allowed_keys_is_hard_error_unless_opted_in() {
    let master = random_vault_master();
    let sealed = seal(b"x", &KeySource::VaultMaster(master)).unwrap();

    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let sk = SigningKey::from_bytes(&seed);
    let signed = sign(&sealed, &sk).unwrap();

    let no_keys: &[VerifyingKey] = &[];

    // Default verify() rejects an empty allow-list with TrustFailed.
    let err = verify(&signed, no_keys).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::TrustFailed(_));

    // The explicit opt-in still accepts any valid self-embedded signature.
    verify_with_options(&signed, no_keys, true).unwrap();

    // A non-empty allow-list works regardless of the flag.
    verify_with_options(&signed, &[sk.verifying_key()], false).unwrap();

    // With opt-in but a *wrong* key in a non-empty list, the allow-list still
    // governs (opt-in only relaxes the empty case).
    let mut other = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut other);
    let wrong = SigningKey::from_bytes(&other).verifying_key();
    let err = verify_with_options(&signed, &[wrong], true).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::TrustFailed(_));
}

// 25. Re-signing replaces the existing signature.
#[test]
fn resign_replaces_previous_signature() {
    let master = random_vault_master();
    let sealed = seal(b"x", &KeySource::VaultMaster(master)).unwrap();

    let mut seed_a = [0u8; 32];
    let mut seed_b = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed_a);
    rand::thread_rng().fill_bytes(&mut seed_b);
    let sk_a = SigningKey::from_bytes(&seed_a);
    let sk_b = SigningKey::from_bytes(&seed_b);

    let signed_a = sign(&sealed, &sk_a).unwrap();
    let signed_ab = sign(&signed_a, &sk_b).unwrap();

    verify(&signed_ab, &[sk_b.verifying_key()]).unwrap();
    // sk_a should no longer be accepted as the signer.
    let err = verify(&signed_ab, &[sk_a.verifying_key()]).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::TrustFailed(_));
}

fn fresh_psk() -> [u8; 32] {
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    k
}

// ---------------------------------------------------------------------------
// 26. PSK round-trip: seal → unseal is byte-identical.
// ---------------------------------------------------------------------------
#[test]
fn roundtrip_psk() {
    let plaintext = b"[server]\nhost = \"psk.example.com\"\n";
    let key = fresh_psk();
    let sealed = seal(plaintext, &KeySource::Psk(key)).unwrap();
    assert!(is_sealed(&sealed));
    let out = unseal(&sealed, &KeySource::Psk(key)).unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(out.expose_secret().as_slice(), plaintext);
}

// ---------------------------------------------------------------------------
// 27. Wrong PSK → InvalidConfig (not a panic, not silent).
// ---------------------------------------------------------------------------
#[test]
fn wrong_psk_rejects_with_invalid_config() {
    let sealed = seal(b"sensitive", &KeySource::Psk(fresh_psk())).unwrap();
    let err = unseal(&sealed, &KeySource::Psk(fresh_psk())).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidConfig(_));
}

// ---------------------------------------------------------------------------
// 28. PSK tamper: flip a ciphertext byte → AEAD fail (InvalidConfig).
// ---------------------------------------------------------------------------
#[test]
fn psk_tampered_ciphertext_rejects() {
    let key = fresh_psk();
    let mut sealed = seal(b"sensitive", &KeySource::Psk(key)).unwrap();
    // Flip a byte near the end, inside the base64-encoded ciphertext.
    let len = sealed.len();
    sealed[len - 8] ^= 0x01;
    let err = unseal(&sealed, &KeySource::Psk(key)).unwrap_err();
    // AEAD-tag failure (or b64 shape change) — wrong-PSK/tamper path.
    matches::assert_matches!(
        err,
        spt_core::Error::InvalidConfig(_) | spt_core::Error::SecretCryptoFailed(_)
    );
}

// ---------------------------------------------------------------------------
// 29. PSK tamper: flip a meta byte → AAD binding fails the body AEAD.
// ---------------------------------------------------------------------------
#[test]
fn psk_tampered_meta_breaks_aad() {
    let key = fresh_psk();
    let sealed = seal(b"hello", &KeySource::Psk(key)).unwrap();
    // First byte of meta TOML.
    let meta_start = MAGIC.len() + 4;
    let mut tampered = sealed.clone();
    tampered[meta_start] ^= 0x80;
    let err = unseal(&tampered, &KeySource::Psk(key)).unwrap_err();
    // The mutated meta still parses as TOML in some flips → AAD mismatch
    // → InvalidConfig; a shape-breaking flip → SecretCryptoFailed. Both OK.
    matches::assert_matches!(
        err,
        spt_core::Error::InvalidConfig(_) | spt_core::Error::SecretCryptoFailed(_)
    );
}

// ---------------------------------------------------------------------------
// 30. peek_meta on a PSK envelope reports kdf="psk" and leaks no secret.
// ---------------------------------------------------------------------------
#[test]
fn peek_meta_psk_reports_kdf_and_no_secret() {
    let key = fresh_psk();
    let sealed = seal(b"x", &KeySource::Psk(key)).unwrap();
    let meta = peek_meta(&sealed).unwrap();
    assert_eq!(meta.version, 1);
    assert_eq!(meta.aead, "aes-256-gcm");
    assert_eq!(meta.kdf, "psk");
    assert!(meta.argon2id.is_none());
    assert!(meta.vault.is_none());
    assert!(meta.recipients.is_empty());
    // psk_id is recorded (non-secret label) and matches the deterministic id.
    let params = meta.psk.expect("psk params present");
    assert_eq!(params.psk_id.as_deref(), Some(psk_id(&key).as_str()));

    // The raw PSK must NOT appear anywhere in the on-disk meta bytes.
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    let key_b64 = B64.encode(key);
    let sealed_str = String::from_utf8_lossy(&sealed);
    assert!(
        !sealed_str.contains(&key_b64),
        "raw PSK leaked into envelope"
    );
}

// ---------------------------------------------------------------------------
// 31. Cross-mode reject: PSK key against an x25519 envelope → mismatch.
// ---------------------------------------------------------------------------
#[test]
fn psk_against_x25519_envelope_rejected() {
    let secret = fresh_x25519_secret();
    let sealed = seal(
        b"x",
        &KeySource::X25519Recipients(vec![pub_from_secret(&secret)]),
    )
    .unwrap();
    let err = unseal(&sealed, &KeySource::Psk(fresh_psk())).unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidConfig(msg) if msg.contains("kdf"));
}

// ---------------------------------------------------------------------------
// 32. Cross-mode reject: x25519 secret against a PSK envelope → mismatch.
// ---------------------------------------------------------------------------
#[test]
fn x25519_secret_against_psk_envelope_rejected() {
    let sealed = seal(b"x", &KeySource::Psk(fresh_psk())).unwrap();
    let err = unseal(
        &sealed,
        &KeySource::X25519Secrets(vec![fresh_x25519_secret()]),
    )
    .unwrap_err();
    matches::assert_matches!(err, spt_core::Error::InvalidConfig(msg) if msg.contains("kdf"));
}

// ---------------------------------------------------------------------------
// 33. keygen: two generate_psk() calls differ.
// ---------------------------------------------------------------------------
#[test]
fn generate_psk_produces_distinct_keys() {
    let a = generate_psk();
    let b = generate_psk();
    assert_ne!(a, b);
    // A generated PSK round-trips through seal/unseal.
    let sealed = seal(b"gen", &KeySource::Psk(a)).unwrap();
    let out = unseal(&sealed, &KeySource::Psk(a)).unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(out.expose_secret().as_slice(), b"gen");
}

// ---------------------------------------------------------------------------
// 34. keygen: generate_x25519 public == PublicKey::from(&private).
// ---------------------------------------------------------------------------
#[test]
fn generate_x25519_public_matches_private() {
    let (private, public) = generate_x25519();
    let rederived = pub_from_secret(&private);
    assert_eq!(public.as_bytes(), rederived.as_bytes());

    // The generated keypair feeds the existing asymmetric path end-to-end.
    let sealed = seal(b"asym", &KeySource::X25519Recipients(vec![public])).unwrap();
    let out = unseal(&sealed, &KeySource::X25519Secrets(vec![private])).unwrap();
    use secrecy::ExposeSecret;
    assert_eq!(out.expose_secret().as_slice(), b"asym");
}

// ---------------------------------------------------------------------------
// 35. keygen: psk_id is deterministic and differs for different PSKs.
// ---------------------------------------------------------------------------
#[test]
fn psk_id_deterministic_and_distinct() {
    let a = fresh_psk();
    let b = fresh_psk();
    assert_eq!(psk_id(&a), psk_id(&a));
    assert_ne!(psk_id(&a), psk_id(&b));
    // 8 hex chars.
    assert_eq!(psk_id(&a).len(), 8);
    assert!(psk_id(&a).chars().all(|c| c.is_ascii_hexdigit()));
}

// Stub external crate used in matches::assert_matches!.
// We don't depend on the `matches` crate — use a local macro instead.
mod matches {
    macro_rules! assert_matches {
        ($expression:expr, $pattern:pat $(if $guard:expr)?) => {
            match $expression {
                $pattern $(if $guard)? => {}
                ref e => panic!(
                    "assertion failed: `{:?}` does not match `{}`",
                    e,
                    stringify!($pattern $(if $guard)?)
                ),
            }
        };
    }
    pub(crate) use assert_matches;
}
