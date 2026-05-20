//! Seal / unseal core logic.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use rand::RngCore;
use secrecy::{ExposeSecret, SecretBox};
use spt_core::audit::{record_audit, AuditEvent, AuditSeverity};
use spt_core::Error;
use zeroize::Zeroizing;

use crate::envelope::{
    body_to_bytes, meta_to_bytes, write_envelope, Argon2idParams, Body, Meta, ParsedEnvelope,
    Recipient, VaultParams, FORMAT_VERSION, MAGIC,
};
use crate::kdf::{derive_argon2id, hkdf_sha256};

/// Re-export the X25519 public key newtype.
pub use x25519_dalek::PublicKey as X25519PublicKey;
use x25519_dalek::{EphemeralSecret, StaticSecret};

/// Secret-bytes type returned by [`unseal`].
///
/// Wraps a `Zeroizing<Vec<u8>>` under `secrecy::SecretBox`, ensuring the
/// buffer is zeroed on drop and never exposed via `Debug`. When the
/// `spt-secrets` feature is enabled, callers may convert to/from
/// `spt_secrets::SecretBytes` (same shape).
pub type SecretSlice = SecretBox<Zeroizing<Vec<u8>>>;

/// Type alias for the secret passphrase carried in
/// [`KeySource::Passphrase`]. This is exactly the `secrecy::SecretSlice<u8>`
/// alias (= `SecretBox<[u8]>`) — exposing it here lets callers construct
/// one without taking a direct dep on `secrecy`'s minor versioning.
pub type Passphrase = secrecy::SecretSlice<u8>;

fn wrap_secret(v: Vec<u8>) -> SecretSlice {
    SecretBox::new(Box::new(Zeroizing::new(v)))
}

/// Source of the body-key for a [`seal`] / [`unseal`] call.
pub enum KeySource {
    /// Passphrase → Argon2id with the [`crate::envelope::Argon2idParams`]
    /// embedded in `[meta.argon2id]`.
    Passphrase(Passphrase),
    /// 32-byte vault master key (typically resolved from the OS keychain
    /// via [`spt_secrets::VaultBackend`]). The on-disk meta records only
    /// a random 16-byte salt; the master itself stays out-of-band.
    VaultMaster([u8; 32]),
    /// One or more X25519 recipient *public* keys. `seal` sets all of
    /// them; `unseal` uses the first entry's *private* key (the
    /// `StaticSecret` derived from raw bytes — see
    /// [`x25519_recipients_from_secrets`]).
    X25519Recipients(Vec<X25519PublicKey>),
    /// Convenience constructor for unsealing under X25519: the caller
    /// supplies one or more candidate static secrets (raw 32-byte
    /// scalars). Any recipient that matches is used.
    X25519Secrets(Vec<[u8; 32]>),
}

impl KeySource {
    fn variant_tag(&self) -> &'static str {
        match self {
            Self::Passphrase(_) => "argon2id",
            Self::VaultMaster(_) => "vault",
            Self::X25519Recipients(_) | Self::X25519Secrets(_) => "x25519",
        }
    }
}

/// Returns `true` if `bytes` starts with the [`MAGIC`] prefix.
///
/// This is a fast pre-check intended for loader auto-detection — it does
/// **not** validate framing or AEAD; pass to [`unseal`] for that.
#[must_use]
pub fn is_sealed(bytes: &[u8]) -> bool {
    bytes.len() >= MAGIC.len() && &bytes[..MAGIC.len()] == MAGIC
}

/// Parse the `[meta]` table without unsealing or holding any key.
///
/// Useful for tooling (e.g. `spt config inspect`) that needs to show the
/// KDF + algorithm without prompting for a passphrase.
pub fn peek_meta(bytes: &[u8]) -> Result<Meta, Error> {
    let (_p, meta, _b, _s) = ParsedEnvelope::parse(bytes)?;
    Ok(meta)
}

/// Encrypt `plaintext` under `key` and frame the result as an `SPTENC1`
/// envelope.
pub fn seal(plaintext: &[u8], key: &KeySource) -> Result<Vec<u8>, Error> {
    // Audit at entry — captures the *attempt* even if encrypt fails.
    let recipients_count = match key {
        KeySource::X25519Recipients(r) => r.len(),
        _ => 0,
    };
    record_audit(
        AuditEvent::new("audit.config_crypt.seal", AuditSeverity::Info)
            .with_field("kdf", key.variant_tag())
            .with_field("recipients_count", recipients_count.to_string()),
    );

    let mut rng = rand::thread_rng();

    // 1. Build meta (+ derive the AEAD body key).
    let (meta, body_key) = match key {
        KeySource::Passphrase(pp) => {
            let mut salt = [0u8; 16];
            rng.fill_bytes(&mut salt);
            let params = Argon2idParams::default_with_salt(&salt);
            let key = derive_argon2id(pp.expose_secret(), &params)?;
            (
                Meta {
                    version: FORMAT_VERSION,
                    aead: "aes-256-gcm".into(),
                    kdf: "argon2id".into(),
                    argon2id: Some(params),
                    recipients: Vec::new(),
                    vault: None,
                },
                key,
            )
        }
        KeySource::VaultMaster(master) => {
            let vault = VaultParams::new_random(&mut rng);
            let salt = vault.salt()?;
            let derived = hkdf_sha256(master, &salt, b"spt-config-crypt/v1/vault");
            (
                Meta {
                    version: FORMAT_VERSION,
                    aead: "aes-256-gcm".into(),
                    kdf: "vault".into(),
                    argon2id: None,
                    recipients: Vec::new(),
                    vault: Some(vault),
                },
                derived,
            )
        }
        KeySource::X25519Recipients(recipients) => {
            if recipients.is_empty() {
                return Err(Error::InvalidArgs(
                    "x25519 seal requires at least one recipient".into(),
                ));
            }
            // Fresh random body key.
            let mut body_key = Zeroizing::new([0u8; 32]);
            rng.fill_bytes(body_key.as_mut());

            // For each recipient: generate an ephemeral key, ECDH, HKDF
            // → wrap key, AES-GCM-wrap the body key under it.
            let mut recs: Vec<Recipient> = Vec::with_capacity(recipients.len());
            for pk in recipients {
                let eph = EphemeralSecret::random_from_rng(&mut rng);
                let eph_pub = X25519PublicKey::from(&eph);
                let shared = eph.diffie_hellman(pk);
                let mut info = Vec::with_capacity(64 + 32 + 32);
                info.extend_from_slice(b"spt-config-crypt/v1/x25519");
                info.extend_from_slice(eph_pub.as_bytes());
                info.extend_from_slice(pk.as_bytes());
                let wrap_key = hkdf_sha256(shared.as_bytes(), &[], &info);

                let cipher = Aes256Gcm::new((&*wrap_key).into());
                let mut wrap_nonce = [0u8; 12];
                rng.fill_bytes(&mut wrap_nonce);
                let wrapped = cipher
                    .encrypt(Nonce::from_slice(&wrap_nonce), body_key.as_ref().as_ref())
                    .map_err(|e| Error::SecretCryptoFailed(format!("x25519 wrap: {e}")))?;

                recs.push(Recipient {
                    pubkey_b64: B64.encode(pk.as_bytes()),
                    ephemeral_b64: B64.encode(eph_pub.as_bytes()),
                    wrap_nonce_b64: B64.encode(wrap_nonce),
                    wrapped_key_b64: B64.encode(wrapped),
                });
            }
            (
                Meta {
                    version: FORMAT_VERSION,
                    aead: "aes-256-gcm".into(),
                    kdf: "x25519".into(),
                    argon2id: None,
                    recipients: recs,
                    vault: None,
                },
                body_key,
            )
        }
        KeySource::X25519Secrets(_) => {
            return Err(Error::InvalidArgs(
                "X25519Secrets is unseal-only; seal with X25519Recipients(public keys)".into(),
            ));
        }
    };

    // 2. Serialize meta canonically → those bytes are part of the AAD.
    let meta_bytes = meta_to_bytes(&meta)?;

    // 3. AEAD-encrypt the body.
    let mut body_nonce = [0u8; 12];
    rng.fill_bytes(&mut body_nonce);
    let cipher = Aes256Gcm::new((&*body_key).into());
    let mut aad = Vec::with_capacity(MAGIC.len() + meta_bytes.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&meta_bytes);
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&body_nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|e| Error::SecretCryptoFailed(format!("body encrypt: {e}")))?;

    let body = Body {
        nonce_b64: B64.encode(body_nonce),
        ciphertext_b64: B64.encode(ciphertext),
    };
    let body_bytes = body_to_bytes(&body)?;

    write_envelope(&meta_bytes, &body_bytes, None)
}

/// Decrypt an `SPTENC1` envelope. Returns a [`SecretSlice`] holding the
/// plaintext; the buffer is zeroed on drop.
///
/// Errors:
///
/// * [`Error::SecretCryptoFailed`] for framing / AEAD / KDF failures.
/// * [`Error::InvalidConfig`] when the caller's key does not match the
///   envelope's KDF discriminant (e.g. passphrase given for an X25519
///   envelope), **and** for wrong-passphrase (AEAD tag mismatch under the
///   `argon2id` KDF — the caller almost certainly mistyped).
pub fn unseal(sealed: &[u8], key: &KeySource) -> Result<SecretSlice, Error> {
    let (parsed, meta, body, _sig) = ParsedEnvelope::parse(sealed)?;

    // Audit at entry. `recipients_count` reflects the envelope's
    // recipient list (0 for argon2id / vault); the caller's key shape
    // is captured via the variant tag.
    record_audit(
        AuditEvent::new("audit.config_crypt.unseal", AuditSeverity::Info)
            .with_field("kdf", meta.kdf.clone())
            .with_field("recipients_count", meta.recipients.len().to_string()),
    );

    // Reject early if the caller's key shape can't possibly fit the envelope.
    if meta.kdf != key.variant_tag() {
        return Err(Error::InvalidConfig(format!(
            "sealed config uses kdf `{}` but caller supplied `{}`",
            meta.kdf,
            key.variant_tag()
        )));
    }

    // Derive the AEAD body key.
    let body_key: Zeroizing<[u8; 32]> = match (key, meta.kdf.as_str()) {
        (KeySource::Passphrase(pp), "argon2id") => {
            let params = meta.argon2id.as_ref().ok_or_else(|| {
                Error::SecretCryptoFailed("argon2id kdf without [meta.argon2id]".into())
            })?;
            // KDF-param sanity: refuse pathological values so a hostile
            // envelope can't force a multi-GB Argon2 allocation.
            if params.memory_kib < 8
                || params.memory_kib > 4 * 1024 * 1024
                || params.iterations < 1
                || params.iterations > 32
                || params.parallelism < 1
                || params.parallelism > 64
            {
                return Err(Error::InvalidConfig(format!(
                    "argon2id parameters out of accepted bounds: m={} t={} p={}",
                    params.memory_kib, params.iterations, params.parallelism
                )));
            }
            derive_argon2id(pp.expose_secret(), params)?
        }
        (KeySource::VaultMaster(master), "vault") => {
            let vault = meta
                .vault
                .as_ref()
                .ok_or_else(|| Error::SecretCryptoFailed("vault kdf without [meta.vault]".into()))?;
            let salt = vault.salt()?;
            hkdf_sha256(master, &salt, b"spt-config-crypt/v1/vault")
        }
        (KeySource::X25519Secrets(secrets), "x25519") => {
            x25519_unwrap_body_key(&meta, secrets)?
        }
        (KeySource::X25519Recipients(_), "x25519") => {
            return Err(Error::InvalidArgs(
                "unsealing under X25519 requires private keys — use KeySource::X25519Secrets".into(),
            ));
        }
        _ => {
            return Err(Error::InvalidConfig(format!(
                "sealed config kdf `{}` does not match supplied key variant",
                meta.kdf
            )));
        }
    };

    // AEAD-decrypt the body, with AAD = magic || on-disk meta bytes.
    let cipher = Aes256Gcm::new((&*body_key).into());
    let nonce_arr = body.nonce()?;
    let ct = body.ciphertext()?;
    let mut aad = Vec::with_capacity(MAGIC.len() + parsed.meta_bytes.len());
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(parsed.meta_bytes);

    let pt = cipher
        .decrypt(
            Nonce::from_slice(&nonce_arr),
            Payload {
                msg: &ct,
                aad: &aad,
            },
        )
        .map_err(|_| {
            // AEAD-tag failure under argon2id is overwhelmingly "wrong
            // passphrase" — surface as InvalidConfig so the CLI can give
            // a helpful exit code.
            if meta.kdf == "argon2id" {
                Error::InvalidConfig("decrypt failed: wrong passphrase or tampered envelope".into())
            } else {
                Error::SecretCryptoFailed("aead decrypt failed".into())
            }
        })?;

    Ok(wrap_secret(pt))
}

/// Try each candidate secret against each [`Recipient`] until one ECDH
/// produces a wrap key that authenticates the wrapped body key.
fn x25519_unwrap_body_key(
    meta: &Meta,
    secrets: &[[u8; 32]],
) -> Result<Zeroizing<[u8; 32]>, Error> {
    if meta.recipients.is_empty() {
        return Err(Error::SecretCryptoFailed(
            "x25519 envelope without recipients".into(),
        ));
    }
    if secrets.is_empty() {
        return Err(Error::InvalidArgs(
            "x25519 unseal requires at least one candidate secret".into(),
        ));
    }
    for rec in &meta.recipients {
        let eph_pub_bytes = B64
            .decode(&rec.ephemeral_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("recipient ephemeral b64: {e}")))?;
        if eph_pub_bytes.len() != 32 {
            continue;
        }
        let mut eph_pub_arr = [0u8; 32];
        eph_pub_arr.copy_from_slice(&eph_pub_bytes);
        let eph_pub = X25519PublicKey::from(eph_pub_arr);

        let rec_pub_bytes = B64
            .decode(&rec.pubkey_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("recipient pubkey b64: {e}")))?;
        if rec_pub_bytes.len() != 32 {
            continue;
        }

        let wrap_nonce_bytes = B64
            .decode(&rec.wrap_nonce_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("recipient wrap_nonce b64: {e}")))?;
        if wrap_nonce_bytes.len() != 12 {
            continue;
        }
        let mut wrap_nonce = [0u8; 12];
        wrap_nonce.copy_from_slice(&wrap_nonce_bytes);

        let wrapped = B64
            .decode(&rec.wrapped_key_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("recipient wrapped b64: {e}")))?;

        for secret in secrets {
            // StaticSecret::from clamps + zeroizes-on-drop internally; we
            // give it an owned copy of the raw scalar.
            let static_secret = StaticSecret::from(*secret);
            let shared = static_secret.diffie_hellman(&eph_pub);

            let mut info = Vec::with_capacity(64);
            info.extend_from_slice(b"spt-config-crypt/v1/x25519");
            info.extend_from_slice(eph_pub.as_bytes());
            info.extend_from_slice(&rec_pub_bytes);
            let wrap_key = hkdf_sha256(shared.as_bytes(), &[], &info);

            let cipher = Aes256Gcm::new((&*wrap_key).into());
            if let Ok(body_key_vec) =
                cipher.decrypt(Nonce::from_slice(&wrap_nonce), wrapped.as_slice())
            {
                if body_key_vec.len() != 32 {
                    continue;
                }
                let mut out = Zeroizing::new([0u8; 32]);
                out.copy_from_slice(&body_key_vec);
                return Ok(out);
            }
        }
    }
    Err(Error::InvalidConfig(
        "no supplied x25519 secret matched any recipient".into(),
    ))
}

