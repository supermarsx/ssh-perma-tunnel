//! Ed25519 detached signature support for `SPTENC1` envelopes.
//!
//! The signature covers `magic || meta_bytes || body_bytes` — i.e. the
//! exact on-disk bytes of those three sections. This lets verifiers
//! reject envelopes where any of meta, body, or magic has been tampered
//! with, independently of the body AEAD.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature as EdSig, Signer, Verifier};
use spt_core::audit::{record_audit, AuditEvent, AuditSeverity};
use spt_core::Error;
use subtle::ConstantTimeEq;

use crate::envelope::{signature_to_bytes, write_envelope, ParsedEnvelope, Signature, MAGIC};

/// Re-export Ed25519 signing key (32-byte seed → ed25519 keypair).
pub use ed25519_dalek::SigningKey;
/// Re-export Ed25519 verifying key.
pub use ed25519_dalek::VerifyingKey;

fn signing_input(meta_bytes: &[u8], body_bytes: &[u8]) -> Vec<u8> {
    let mut input = Vec::with_capacity(MAGIC.len() + meta_bytes.len() + body_bytes.len());
    input.extend_from_slice(MAGIC);
    input.extend_from_slice(meta_bytes);
    input.extend_from_slice(body_bytes);
    input
}

/// Sign an existing sealed envelope, appending (or replacing) the
/// `[signature]` section.
///
/// Returns a fresh envelope byte vector. The original input is not
/// modified. If a signature block was already present, it is replaced.
pub fn sign(sealed: &[u8], signing_key: &SigningKey) -> Result<Vec<u8>, Error> {
    let (parsed, meta, _body, _existing) = ParsedEnvelope::parse(sealed)?;

    // Audit at entry. Recipients_count is included for symmetry with
    // the seal/unseal events — useful for correlating a sign call to a
    // particular envelope without leaking the public key bytes.
    record_audit(
        AuditEvent::new("audit.config_crypt.sign", AuditSeverity::Info)
            .with_field("kdf", meta.kdf.clone())
            .with_field("recipients_count", meta.recipients.len().to_string()),
    );

    let input = signing_input(parsed.meta_bytes, parsed.body_bytes);
    let sig = signing_key.sign(&input);

    let sig_block = Signature {
        pubkey_b64: B64.encode(signing_key.verifying_key().as_bytes()),
        sig_b64: B64.encode(sig.to_bytes()),
    };
    let sig_bytes = signature_to_bytes(&sig_block)?;
    write_envelope(parsed.meta_bytes, parsed.body_bytes, Some(&sig_bytes))
}

/// Verify the `[signature]` block against `allowed_keys`.
///
/// Returns `Ok(())` iff a `[signature]` block is present, the embedded
/// public key matches one of `allowed_keys` (constant-time compare), and
/// the Ed25519 signature is valid over `magic || meta || body`.
///
/// # Empty allow-list is a hard error (fail-closed)
///
/// If `allowed_keys` is empty this returns
/// `Error::TrustFailed("no trust anchors configured")`. "The envelope is
/// signed at all" is **not** "the envelope is signed by someone I trust" —
/// a call site that derives `allowed_keys` from config and gets an empty
/// list (mis-set / cleared) must not silently downgrade to no trust root.
///
/// If you genuinely want any-key gating (accept any valid self-embedded
/// signature, ignoring the trust root), call [`verify_with_options`] with
/// `any_signed_ok = true`.
pub fn verify(sealed: &[u8], allowed_keys: &[VerifyingKey]) -> Result<(), Error> {
    verify_with_options(sealed, allowed_keys, false)
}

/// Verify the `[signature]` block against `allowed_keys`, with an explicit
/// opt-in for accepting any self-embedded signing key.
///
/// Behaves like [`verify`], except that when `allowed_keys` is empty:
///
/// * `any_signed_ok == false` → `Error::TrustFailed("no trust anchors
///   configured")` (the safe default).
/// * `any_signed_ok == true`  → the trust-anchor check is skipped and the
///   call succeeds for *any* valid self-embedded signature. Use only when
///   the caller deliberately wants "is this signed at all" gating.
///
/// When `allowed_keys` is non-empty, `any_signed_ok` has no effect: the
/// embedded key must still be in the allow-list.
pub fn verify_with_options(
    sealed: &[u8],
    allowed_keys: &[VerifyingKey],
    any_signed_ok: bool,
) -> Result<(), Error> {
    if allowed_keys.is_empty() && !any_signed_ok {
        return Err(Error::TrustFailed(
            "no trust anchors configured (empty allowed-keys list)".into(),
        ));
    }
    let (parsed, meta, _body, sig_opt) = ParsedEnvelope::parse(sealed)?;

    // Audit at entry — verify is called on every load of a signed
    // envelope, so an audit record here is the single best signal that
    // someone exercised a trust path.
    record_audit(
        AuditEvent::new("audit.config_crypt.verify", AuditSeverity::Info)
            .with_field("kdf", meta.kdf.clone())
            .with_field("recipients_count", meta.recipients.len().to_string()),
    );

    let sig = sig_opt.ok_or_else(|| Error::TrustFailed("envelope is not signed".into()))?;

    let embedded_pub_bytes = B64
        .decode(&sig.pubkey_b64)
        .map_err(|e| Error::TrustFailed(format!("signature pubkey b64: {e}")))?;
    if embedded_pub_bytes.len() != 32 {
        return Err(Error::TrustFailed(format!(
            "signature pubkey must be 32 bytes, got {}",
            embedded_pub_bytes.len()
        )));
    }
    let mut embedded_pub_arr = [0u8; 32];
    embedded_pub_arr.copy_from_slice(&embedded_pub_bytes);
    let embedded_vk = VerifyingKey::from_bytes(&embedded_pub_arr)
        .map_err(|e| Error::TrustFailed(format!("signature pubkey parse: {e}")))?;

    if !allowed_keys.is_empty() {
        // Constant-time compare against each allowed key. We do not
        // short-circuit on the byte level (subtle::ConstantTimeEq) but we
        // *do* on the loop level — the sensitive material here is the
        // outcome of "is this key trusted", and an attacker can already
        // observe per-byte match positions via re-running with crafted
        // envelopes.
        let mut matched = false;
        for allowed in allowed_keys {
            if bool::from(allowed.as_bytes().ct_eq(embedded_vk.as_bytes())) {
                matched = true;
                break;
            }
        }
        if !matched {
            return Err(Error::TrustFailed(
                "signature key not in allowed-keys list".into(),
            ));
        }
    }

    let sig_bytes_raw = B64
        .decode(&sig.sig_b64)
        .map_err(|e| Error::TrustFailed(format!("signature b64: {e}")))?;
    if sig_bytes_raw.len() != 64 {
        return Err(Error::TrustFailed(format!(
            "signature must be 64 bytes, got {}",
            sig_bytes_raw.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(&sig_bytes_raw);
    let ed_sig = EdSig::from_bytes(&sig_arr);

    let input = signing_input(parsed.meta_bytes, parsed.body_bytes);
    embedded_vk
        .verify(&input, &ed_sig)
        .map_err(|e| Error::TrustFailed(format!("ed25519 verify: {e}")))?;

    Ok(())
}
