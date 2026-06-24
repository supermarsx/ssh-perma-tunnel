//! On-disk envelope parsing and serialization.

use serde::{Deserialize, Serialize};
use spt_core::Error;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// 8-byte magic marker. The trailing `\n` makes the first line printable in
/// `head -1` while still being binary-safe (LF is treated as part of the
/// fixed-width prefix).
pub const MAGIC: &[u8; 8] = b"SPTENC1\n";

/// Current format revision. Bump when the on-disk layout or any KDF/AEAD
/// algorithm identifier moves to a value an older reader cannot decode.
pub const FORMAT_VERSION: u32 = 1;

/// Maximum size of any single framed section. 16 MiB is far above any
/// realistic config payload and keeps `(u32 as usize)` casts safe on 32-bit
/// targets while preventing trivial out-of-memory crashes on a hostile
/// envelope.
pub(crate) const MAX_SECTION_LEN: usize = 16 * 1024 * 1024;

/// `[meta]` table — visible header describing how to unseal the body.
///
/// Serialized to TOML with `serde`; the canonical bytes on disk are the
/// exact UTF-8 TOML produced by [`toml::to_string`], framed verbatim
/// between the length prefix and the body.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Meta {
    /// Format revision; this crate only writes `1`.
    pub version: u32,
    /// AEAD algorithm tag. Always `"aes-256-gcm"` for this crate.
    pub aead: String,
    /// KDF discriminant: `"argon2id"`, `"vault"`, `"x25519"`, or `"psk"`.
    pub kdf: String,

    /// Argon2id parameters — present iff `kdf == "argon2id"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon2id: Option<Argon2idParams>,

    /// X25519 sealed-recipient list — present iff `kdf == "x25519"`.
    ///
    /// Each entry binds an X25519 recipient public key to an AES-256-GCM
    /// wrapping of the body key under a per-recipient HKDF-derived key.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub recipients: Vec<Recipient>,

    /// Vault-master KDF tag — present iff `kdf == "vault"`. The salt is
    /// used as HKDF info; the actual 32-byte master key is supplied
    /// out-of-band by the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<VaultParams>,

    /// Raw-PSK parameters — present (optionally) iff `kdf == "psk"`.
    ///
    /// Carries **nothing secret**: only an optional non-secret `psk_id`
    /// label so an operator can tell which pre-shared key sealed a blob
    /// without trying keys. The 32-byte PSK itself is supplied out-of-band
    /// and used directly as the AES-256-GCM body key (no KDF).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk: Option<PskParams>,
}

/// Raw-PSK KDF parameters (`[meta.psk]`).
///
/// Holds no secret material — just an optional key-fingerprint label.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PskParams {
    /// Optional non-secret key label: the first 8 hex characters of
    /// `SHA-256(psk)`. Lets operators identify which PSK sealed a blob.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psk_id: Option<String>,
}

/// Argon2id parameters as serialized into `[meta.argon2id]`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Argon2idParams {
    /// Memory cost in KiB. Default: 65536 (= 64 MiB).
    pub memory_kib: u32,
    /// Iteration count. Default: 3.
    pub iterations: u32,
    /// Parallelism (lanes). Default: 4.
    pub parallelism: u32,
    /// Base64-encoded salt (16 random bytes).
    pub salt_b64: String,
}

impl Argon2idParams {
    /// OWASP-recommended Argon2id v1.3 baseline.
    pub(crate) fn default_with_salt(salt: &[u8; 16]) -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 4,
            salt_b64: B64.encode(salt),
        }
    }

    pub(crate) fn salt(&self) -> Result<Vec<u8>, Error> {
        B64.decode(&self.salt_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("argon2id salt b64: {e}")))
    }
}

/// Per-recipient sealed-body-key record for the X25519 KDF.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Recipient {
    /// Base64-encoded 32-byte recipient X25519 public key.
    pub pubkey_b64: String,
    /// Base64-encoded 32-byte ephemeral X25519 public key used for this
    /// recipient's ECDH.
    pub ephemeral_b64: String,
    /// Base64-encoded 12-byte AES-GCM nonce for the wrapped body key.
    pub wrap_nonce_b64: String,
    /// Base64-encoded AES-256-GCM wrapping of the 32-byte body key.
    pub wrapped_key_b64: String,
}

/// Vault-master KDF parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultParams {
    /// Base64-encoded 16-byte salt fed into HKDF-SHA-256 to derive the
    /// body key from the 32-byte vault master.
    pub salt_b64: String,
}

impl VaultParams {
    pub(crate) fn new_random(rng: &mut impl rand::RngCore) -> Self {
        let mut salt = [0u8; 16];
        rng.fill_bytes(&mut salt);
        Self {
            salt_b64: B64.encode(salt),
        }
    }

    pub(crate) fn salt(&self) -> Result<Vec<u8>, Error> {
        B64.decode(&self.salt_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("vault salt b64: {e}")))
    }
}

/// `[body]` table — opaque AEAD output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Body {
    /// Base64-encoded 12-byte AES-GCM nonce.
    pub nonce_b64: String,
    /// Base64-encoded ciphertext (includes the 16-byte GCM tag).
    pub ciphertext_b64: String,
}

impl Body {
    pub(crate) fn nonce(&self) -> Result<[u8; 12], Error> {
        let raw = B64
            .decode(&self.nonce_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("body nonce b64: {e}")))?;
        if raw.len() != 12 {
            return Err(Error::SecretCryptoFailed(format!(
                "body nonce must be 12 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 12];
        out.copy_from_slice(&raw);
        Ok(out)
    }

    pub(crate) fn ciphertext(&self) -> Result<Vec<u8>, Error> {
        B64.decode(&self.ciphertext_b64)
            .map_err(|e| Error::SecretCryptoFailed(format!("body ciphertext b64: {e}")))
    }
}

/// `[signature]` table — optional Ed25519 detached signature over
/// `magic || meta_bytes || body_bytes`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Base64-encoded 32-byte Ed25519 public key (the verifying key).
    pub pubkey_b64: String,
    /// Base64-encoded 64-byte Ed25519 signature.
    pub sig_b64: String,
}

/// Wraps `Meta` as `{ meta = ... }` for the on-disk TOML.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MetaDoc {
    pub meta: Meta,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BodyDoc {
    pub body: Body,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SignatureDoc {
    pub signature: Signature,
}

/// Parsed view of an on-disk envelope. The raw byte slices for each
/// section are retained so AAD and signature inputs can be reconstructed
/// byte-exact without re-serializing.
pub(crate) struct ParsedEnvelope<'a> {
    pub meta_bytes: &'a [u8],
    pub body_bytes: &'a [u8],
    // Retained for future use (e.g. tooling that wants to round-trip the
    // signature without re-serializing). Callers today read the parsed
    // `Signature` value returned alongside this struct.
    #[allow(dead_code)]
    pub sig_bytes: Option<&'a [u8]>,
}

impl<'a> ParsedEnvelope<'a> {
    /// Parse the framing only. Returns the section slices and a fully
    /// decoded [`Meta`] / [`Body`] for caller convenience.
    pub fn parse(sealed: &'a [u8]) -> Result<(Self, Meta, Body, Option<Signature>), Error> {
        if sealed.len() < MAGIC.len() {
            return Err(Error::SecretCryptoFailed("not sealed: too short".into()));
        }
        if &sealed[..MAGIC.len()] != MAGIC {
            return Err(Error::SecretCryptoFailed(
                "not sealed: magic mismatch".into(),
            ));
        }

        let mut cur = MAGIC.len();
        let (meta_bytes, after_meta) = read_section(sealed, cur, "meta")?;
        cur = after_meta;

        let (body_bytes, after_body) = read_section(sealed, cur, "body")?;
        cur = after_body;

        let (sig_bytes, _after_sig) = if cur < sealed.len() {
            let (s, n) = read_section(sealed, cur, "signature")?;
            (Some(s), n)
        } else {
            (None, cur)
        };

        let meta_doc: MetaDoc = toml::from_str(
            std::str::from_utf8(meta_bytes)
                .map_err(|e| Error::SecretCryptoFailed(format!("meta utf8: {e}")))?,
        )
        .map_err(|e| Error::SecretCryptoFailed(format!("meta toml: {e}")))?;

        let body_doc: BodyDoc = toml::from_str(
            std::str::from_utf8(body_bytes)
                .map_err(|e| Error::SecretCryptoFailed(format!("body utf8: {e}")))?,
        )
        .map_err(|e| Error::SecretCryptoFailed(format!("body toml: {e}")))?;

        let sig = if let Some(sb) = sig_bytes {
            let sig_doc: SignatureDoc = toml::from_str(
                std::str::from_utf8(sb)
                    .map_err(|e| Error::SecretCryptoFailed(format!("signature utf8: {e}")))?,
            )
            .map_err(|e| Error::SecretCryptoFailed(format!("signature toml: {e}")))?;
            Some(sig_doc.signature)
        } else {
            None
        };

        Ok((
            Self {
                meta_bytes,
                body_bytes,
                sig_bytes,
            },
            meta_doc.meta,
            body_doc.body,
            sig,
        ))
    }
}

fn read_section<'a>(buf: &'a [u8], at: usize, name: &str) -> Result<(&'a [u8], usize), Error> {
    if buf.len() < at + 4 {
        return Err(Error::SecretCryptoFailed(format!(
            "truncated envelope: missing {name} length prefix"
        )));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[at..at + 4]);
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_SECTION_LEN {
        return Err(Error::SecretCryptoFailed(format!(
            "{name} section length {len} exceeds max {MAX_SECTION_LEN}"
        )));
    }
    let start = at + 4;
    let end = start
        .checked_add(len)
        .ok_or_else(|| Error::SecretCryptoFailed(format!("{name} length overflow")))?;
    if buf.len() < end {
        return Err(Error::SecretCryptoFailed(format!(
            "truncated envelope: {name} section wants {len} bytes, have {}",
            buf.len().saturating_sub(start)
        )));
    }
    Ok((&buf[start..end], end))
}

/// Serialize an envelope to bytes given the canonical TOML chunks. Pass
/// the already-serialized meta / body / optional signature bytes.
pub(crate) fn write_envelope(
    meta_bytes: &[u8],
    body_bytes: &[u8],
    sig_bytes: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if meta_bytes.len() > MAX_SECTION_LEN
        || body_bytes.len() > MAX_SECTION_LEN
        || sig_bytes.is_some_and(|s| s.len() > MAX_SECTION_LEN)
    {
        return Err(Error::SecretCryptoFailed(
            "envelope section exceeds 16 MiB cap".into(),
        ));
    }
    let total = MAGIC.len()
        + 4
        + meta_bytes.len()
        + 4
        + body_bytes.len()
        + sig_bytes.map_or(0, |s| 4 + s.len());
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(meta_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(meta_bytes);
    out.extend_from_slice(&(body_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(body_bytes);
    if let Some(sb) = sig_bytes {
        out.extend_from_slice(&(sb.len() as u32).to_be_bytes());
        out.extend_from_slice(sb);
    }
    Ok(out)
}

/// Helper: serialize a [`Meta`] to its on-disk byte form.
pub(crate) fn meta_to_bytes(meta: &Meta) -> Result<Vec<u8>, Error> {
    let doc = MetaDoc { meta: meta.clone() };
    toml::to_string(&doc)
        .map(String::into_bytes)
        .map_err(|e| Error::SecretCryptoFailed(format!("meta serialize: {e}")))
}

pub(crate) fn body_to_bytes(body: &Body) -> Result<Vec<u8>, Error> {
    let doc = BodyDoc { body: body.clone() };
    toml::to_string(&doc)
        .map(String::into_bytes)
        .map_err(|e| Error::SecretCryptoFailed(format!("body serialize: {e}")))
}

pub(crate) fn signature_to_bytes(sig: &Signature) -> Result<Vec<u8>, Error> {
    let doc = SignatureDoc {
        signature: sig.clone(),
    };
    toml::to_string(&doc)
        .map(String::into_bytes)
        .map_err(|e| Error::SecretCryptoFailed(format!("signature serialize: {e}")))
}
