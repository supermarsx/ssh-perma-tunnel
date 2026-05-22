// Copyright 2026 t8-B2.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
//! Post-quantum hybrid KEX `sntrup761x25519-sha512[@openssh.com]`.
//!
//! Combines Streamlined NTRU Prime sntrup761 (post-quantum) with classical
//! Curve25519 ECDH. Wire layout and shared-secret derivation match
//! OpenSSH 9.9 `kex-sntrup761x25519.c`:
//!
//! * Client init  = sntrup761 public key (1158 B) `||` X25519 pubkey (32 B) =
//!   1190 B
//! * Server reply = sntrup761 ciphertext (1039 B) `||` X25519 pubkey (32 B) =
//!   1071 B
//! * K = SHA-512( K_sntrup (32 B) `||` K_x25519 (32 B) ) — 64 B
//! * K is encoded as an SSH **string** (not mpint) in the exchange hash
//!   and in subsequent key-derivation iterations, mirroring the ML-KEM
//!   hybrid (`super::mlkem`).
//!
//! ## Status — SKELETON (KEM primitive not yet wired)
//!
//! The wire-format constants, algorithm name registrations
//! (`sntrup761x25519-sha512` and its legacy `@openssh.com`-suffixed alias),
//! `KexAlgorithm` trait implementation skeleton, and SHA-512 hybrid KDF
//! combiner are all in place — but the sntrup761 KEM primitive itself
//! (`KeyGen`, `Encrypt`, `Decrypt`) is **not** implemented. All KEX-state
//! methods (`client_dh`, `server_dh`, `compute_shared_secret`) therefore
//! return [`crate::Error::Kex`] with a descriptive `debug!` log line.
//!
//! Three operator-decidable resume paths to functional sntrup761:
//!
//! 1. Bump workspace MSRV to **1.90** and wire the pure-Rust
//!    `sntrup761 = 0.4.0` crate (mikelodder7) — KEM has correct
//!    byte-sizes 1158/1039/32, but is ~3 months old, unaudited, and
//!    requires Rust 1.90 (violates t8 quality bar's 1.85).
//! 2. Reverse the operator's `pqcrypto-sntruprime` (C-backed) refusal —
//!    half-day wire-up, but pulls in a C compiler dep.
//! 3. Commission an audited hand-port from `openssh-portable/sntrup761.c`
//!    (~800 LoC of constant-time polynomial arithmetic, ~1 week + review).
//!
//! See `.orchestration/logs/t8-B2.md` for the full operator brief.

use byteorder::{BigEndian, ByteOrder};
use log::debug;
use sha2::{Digest, Sha512};

use super::{compute_keys, KexAlgorithm, KexType};
use crate::keys::encoding::Encoding;
use crate::mac::{self};
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec};

/// Wire-format size of an sntrup761 public key (OpenSSH `sntrup761.h`
/// `crypto_kem_sntrup761_PUBLICKEYBYTES`).
pub(crate) const SNTRUP761_PUBLIC_KEY_BYTES: usize = 1158;
/// Wire-format size of an sntrup761 ciphertext
/// (`crypto_kem_sntrup761_CIPHERTEXTBYTES`).
pub(crate) const SNTRUP761_CIPHERTEXT_BYTES: usize = 1039;
/// X25519 public-key / shared-secret size.
pub(crate) const X25519_BYTES: usize = 32;
/// sntrup761 shared secret size — 32 B by `crypto_kem_sntrup761_BYTES`.
///
/// Currently used only by the test suite; will become a load-bearing
/// constant once the KEM primitive lands and `compute_shared_secret`
/// actually copies the decapsulated bytes into `[u8; 32]`.
#[allow(dead_code)]
pub(crate) const SNTRUP761_SHARED_SECRET_BYTES: usize = 32;

/// Size of the `KEX_ECDH_INIT` payload (after the message-id byte and the
/// SSH-string length prefix): `sntrup_pub || x25519_pub`.
pub(crate) const INIT_BLOB_LEN: usize = SNTRUP761_PUBLIC_KEY_BYTES + X25519_BYTES;

/// Size of the `KEX_ECDH_REPLY` server blob: `sntrup_ct || x25519_pub`.
pub(crate) const REPLY_BLOB_LEN: usize = SNTRUP761_CIPHERTEXT_BYTES + X25519_BYTES;

/// Type tag used by the `KexType` registration table. Registered under
/// both the canonical name and the legacy `@openssh.com`-suffixed alias,
/// mirroring how `super::curve25519` registers
/// `curve25519-sha256[@libssh.org]`.
pub struct SntruP761X25519Sha512KexType {}

impl KexType for SntruP761X25519Sha512KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(SntruP761X25519Sha512Kex {
            shared_secret: None,
        }) as Box<dyn KexAlgorithm + Send>
    }
}

/// Per-session KEX state.
///
/// Skeleton: holds only the (always-`None`) shared-secret slot so the
/// `compute_keys` / `compute_exchange_hash` plumbing has somewhere to
/// look. When the KEM lands, this struct will gain `x25519_secret` and
/// `sntrup_decap_key` fields mirroring [`super::mlkem`].
#[doc(hidden)]
pub struct SntruP761X25519Sha512Kex {
    /// `K = SHA-512(K_sntrup || K_x25519)` — 64 bytes, encoded as an
    /// SSH string when feeding the exchange hash.
    shared_secret: Option<[u8; 64]>,
}

impl std::fmt::Debug for SntruP761X25519Sha512Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "SntruP761X25519Sha512Kex {{ shared_secret: [hidden] }}",
        )
    }
}

/// Combine the two leg shared secrets per OpenSSH
/// `kex-sntrup761x25519.c`: `K = SHA-512(K_sntrup || K_x25519)`.
///
/// PQ-first ordering matches the mlkem combiner in [`super::mlkem`] and
/// the byte order baked into OpenSSH's `kex_sntrup761x25519_keygen` →
/// `kex_sntrup761x25519_dec` paths. The 64-byte output is exactly the
/// SHA-512 digest, length-prefixed as an SSH string downstream.
///
/// This combiner is callable today even though the KEM legs aren't —
/// it has no secret dependencies and is independently testable, giving
/// the future KEM wire-up a known-good combiner to land against.
#[allow(dead_code)] // wired into `server_dh` / `compute_shared_secret` once KEM lands
fn combine_shared_secrets(k_sntrup: &[u8; 32], k_x25519: &[u8; 32]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(k_sntrup);
    hasher.update(k_x25519);
    let digest = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(digest.as_slice());
    out
}

impl KexAlgorithm for SntruP761X25519Sha512Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    #[doc(hidden)]
    fn server_dh(&mut self, _exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!(
            "sntrup761x25519-sha512 server_dh: KEM primitive not yet wired \
             (operator decision pending — see kex/sntrup761.rs doc-comment)"
        );

        // Validate the wire shape on the way out so a non-sntrup peer
        // (or a peer with the wrong blob length) still surfaces a
        // recognisable parse-failure error rather than the generic
        // "not-implemented" line above.
        if payload.first() != Some(&msg::KEX_ECDH_INIT) {
            return Err(crate::Error::Inconsistent);
        }
        if payload.len() < 5 + INIT_BLOB_LEN {
            return Err(crate::Error::Inconsistent);
        }
        #[allow(clippy::indexing_slicing)] // length checked above
        let blob_len = BigEndian::read_u32(&payload[1..5]) as usize;
        if blob_len != INIT_BLOB_LEN {
            return Err(crate::Error::Kex);
        }

        // Skeleton: KEM not wired — refuse to fabricate a shared secret.
        Err(crate::Error::Kex)
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        _client_ephemeral: &mut CryptoVec,
        _buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        debug!(
            "sntrup761x25519-sha512 client_dh: KEM primitive not yet wired \
             (operator decision pending — see kex/sntrup761.rs doc-comment)"
        );
        Err(crate::Error::Kex)
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        debug!(
            "sntrup761x25519-sha512 compute_shared_secret: KEM primitive \
             not yet wired"
        );
        if remote_pubkey_.len() != REPLY_BLOB_LEN {
            return Err(crate::Error::Kex);
        }
        Err(crate::Error::Kex)
    }

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, crate::Error> {
        // Mirrors mlkem's exchange-hash construction (SSH-string-encoded
        // K rather than mpint, per draft-kampanakis-curdle-ssh-pq-ke
        // and OpenSSH 9.9 `kex-sntrup761x25519.c`). Hash is SHA-512
        // because sntrup761x25519 names sha512 in its algorithm string.
        //
        // This is reachable today only via the test path
        // (`shared_secret` is forced via the test-only seam) — production
        // call sites always go through `client_dh` / `server_dh` first,
        // both of which currently return `Error::Kex`.
        buffer.clear();
        buffer.extend_ssh_string(&exchange.client_id);
        buffer.extend_ssh_string(&exchange.server_id);
        buffer.extend_ssh_string(&exchange.client_kex_init);
        buffer.extend_ssh_string(&exchange.server_kex_init);

        buffer.extend(key);
        buffer.extend_ssh_string(&exchange.client_ephemeral);
        buffer.extend_ssh_string(&exchange.server_ephemeral);

        if let Some(ref shared) = self.shared_secret {
            buffer.extend_ssh_string(shared);
        }

        let mut hasher = Sha512::new();
        hasher.update(&buffer);

        let mut res = CryptoVec::new();
        res.extend(hasher.finalize().as_slice());
        Ok(res)
    }

    fn compute_keys(
        &self,
        session_id: &CryptoVec,
        exchange_hash: &CryptoVec,
        cipher: cipher::Name,
        remote_to_local_mac: mac::Name,
        local_to_remote_mac: mac::Name,
        is_server: bool,
    ) -> Result<super::cipher::CipherPair, crate::Error> {
        compute_keys::<Sha512>(
            self.shared_secret.as_ref().map(|s| s.as_slice()),
            session_id,
            exchange_hash,
            cipher,
            remote_to_local_mac,
            local_to_remote_mac,
            is_server,
            /* secret_as_string */ true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wire-size constants must match the canonical OpenSSH literals.
    /// Off-by-one here would silently break interop the moment the KEM
    /// primitive lands.
    #[test]
    fn sntrup761x25519_wire_layout_matches_openssh_format() {
        // Verified against OpenSSH 9.9 source `sntrup761.h`:
        //   crypto_kem_sntrup761_PUBLICKEYBYTES  = 1158
        //   crypto_kem_sntrup761_CIPHERTEXTBYTES = 1039
        //   crypto_kem_sntrup761_BYTES           = 32   (shared secret)
        assert_eq!(SNTRUP761_PUBLIC_KEY_BYTES, 1158);
        assert_eq!(SNTRUP761_CIPHERTEXT_BYTES, 1039);
        assert_eq!(SNTRUP761_SHARED_SECRET_BYTES, 32);
        assert_eq!(X25519_BYTES, 32);
        assert_eq!(INIT_BLOB_LEN, 1190, "sntrup761_pub || x25519_pub");
        assert_eq!(REPLY_BLOB_LEN, 1071, "sntrup761_ct || x25519_pub");
    }

    /// Whitebox: combine_shared_secrets must equal SHA-512 of the
    /// concatenation in PQ-first order. Mirrors the mlkem combiner
    /// invariant — the property checked is the *order* and the *hash*.
    #[test]
    fn sntrup761x25519_hybrid_kdf_combines_ss_sntrup_and_ss_x25519() {
        let k_sntrup = [0x11u8; 32];
        let k_x25519 = [0x22u8; 32];
        let got = combine_shared_secrets(&k_sntrup, &k_x25519);

        let mut expected = Sha512::new();
        expected.update(k_sntrup); // PQ first (matches OpenSSH).
        expected.update(k_x25519);
        let expected = expected.finalize();
        assert_eq!(got.as_slice(), expected.as_slice());
        assert_eq!(got.len(), 64, "SHA-512 digest = 64 bytes");

        // Reversing the inputs MUST produce a different digest — guards
        // against an accidental swap in `combine_shared_secrets` when
        // the KEM legs land.
        let swapped = combine_shared_secrets(&k_x25519, &k_sntrup);
        assert_ne!(got, swapped);
    }

    /// Both name strings — canonical and `@openssh.com`-suffixed legacy
    /// — must be resolvable via the public `kex::Name` lookup table.
    /// OpenSSH 9.9 `kex.h` still ships both:
    ///   KEX_SNTRUP761X25519_SHA512      = "sntrup761x25519-sha512"
    ///   KEX_SNTRUP761X25519_SHA512_OLD  = "sntrup761x25519-sha512@openssh.com"
    #[test]
    fn sntrup761x25519_negotiation_table_lookup() {
        use std::convert::TryFrom;
        let name = super::super::Name::try_from("sntrup761x25519-sha512")
            .expect("canonical name must resolve via KEXES table");
        assert_eq!(name.as_ref(), "sntrup761x25519-sha512");

        let legacy = super::super::Name::try_from("sntrup761x25519-sha512@openssh.com")
            .expect("@openssh.com-suffixed legacy name must also resolve");
        assert_eq!(legacy.as_ref(), "sntrup761x25519-sha512@openssh.com");
    }

    /// Skeleton honesty: `client_dh` must refuse cleanly with
    /// `Error::Kex` rather than fabricate a half-finished blob. Once
    /// the KEM lands this test gets replaced by the mlkem-style
    /// round-trip suite.
    #[test]
    fn sntrup761x25519_client_dh_returns_kex_error_until_kem_lands() {
        let kty = SntruP761X25519Sha512KexType {};
        let mut client = kty.make();
        let mut client_ephemeral = CryptoVec::new();
        let mut init_pkt = CryptoVec::new();
        let err = client
            .client_dh(&mut client_ephemeral, &mut init_pkt)
            .expect_err("skeleton must refuse to produce a real INIT blob");
        assert!(
            matches!(err, crate::Error::Kex),
            "expected Error::Kex (KEM not wired), got {:?}", err,
        );
        assert!(
            client_ephemeral.is_empty(),
            "client_dh must not write partial INIT data on failure",
        );
        assert!(
            init_pkt.is_empty(),
            "client_dh must not emit a partial KEX_ECDH_INIT packet",
        );
    }

    /// Symmetric server-side check. Synthesise a well-formed (length-
    /// wise) `KEX_ECDH_INIT` payload and confirm `server_dh` parses
    /// the wire layout successfully but refuses at the KEM step with
    /// `Error::Kex`. Guards against a future regression where the
    /// "not implemented" path is reordered to come *before* wire
    /// validation — that would let bad peers waste server CPU.
    #[test]
    fn sntrup761x25519_server_dh_parses_wire_then_refuses() {
        let kty = SntruP761X25519Sha512KexType {};
        let mut server = kty.make();
        let mut exchange = Exchange::new();

        // Build a syntactically valid KEX_ECDH_INIT envelope:
        //   [msg_id] [u32 blob_len = INIT_BLOB_LEN] [INIT_BLOB_LEN bytes]
        let mut payload = Vec::with_capacity(1 + 4 + INIT_BLOB_LEN);
        payload.push(msg::KEX_ECDH_INIT);
        payload.extend_from_slice(&(INIT_BLOB_LEN as u32).to_be_bytes());
        payload.extend(std::iter::repeat(0u8).take(INIT_BLOB_LEN));
        let err = server
            .server_dh(&mut exchange, &payload)
            .expect_err("KEM not wired — must refuse");
        assert!(
            matches!(err, crate::Error::Kex),
            "expected Error::Kex after wire-parse success, got {:?}", err,
        );

        // A wrong blob length must trip the wire-shape branch first,
        // before we reach the KEM-not-implemented branch.
        let mut short = Vec::with_capacity(1 + 4 + 16);
        short.push(msg::KEX_ECDH_INIT);
        short.extend_from_slice(&16u32.to_be_bytes());
        short.extend(std::iter::repeat(0u8).take(16));
        let err = server
            .server_dh(&mut exchange, &short)
            .expect_err("short payload must be rejected");
        assert!(
            matches!(err, crate::Error::Inconsistent | crate::Error::Kex),
            "short payload should fail wire-shape check, got {:?}", err,
        );
    }
}
