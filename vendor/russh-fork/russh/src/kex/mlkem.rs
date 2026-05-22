// Copyright 2026 t8-B1.
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
//! Post-quantum hybrid KEX `mlkem768x25519-sha256`.
//!
//! Combines NIST FIPS 203 ML-KEM-768 (post-quantum) with classical
//! Curve25519 ECDH. Wire format and shared-secret derivation match
//! OpenSSH 9.9 `kexmlkem768x25519.c`:
//!
//! * Client init  = ML-KEM-768 public key (1184 B) `||` X25519 pubkey (32 B)
//! * Server reply = ML-KEM-768 ciphertext (1088 B) `||` X25519 pubkey (32 B)
//! * K = SHA-256( K_mlkem (32 B) `||` K_x25519 (32 B) )
//! * K is encoded as an SSH **string** (not mpint) in the exchange hash
//!   and in subsequent key-derivation iterations.
//!
//! The post-quantum component (ML-KEM-768) is provided by the pure-Rust
//! [`ml-kem`](https://crates.io/crates/ml-kem) crate (RustCrypto). The
//! classical Curve25519 leg reuses [`curve25519_dalek`] exactly as in
//! [`super::curve25519`].

use std::convert::TryFrom;

use byteorder::{BigEndian, ByteOrder};
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use log::debug;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{
    EncapsulationKey, MlKem768,
    kem::{Kem, KeyExport},
};
use sha2::{Digest, Sha256};

use super::{compute_keys, KexAlgorithm, KexType};
use crate::keys::encoding::Encoding;
use crate::mac::{self};
use crate::session::Exchange;
use crate::{cipher, msg, CryptoVec};

/// Wire-format size of an ML-KEM-768 public key (FIPS 203 §7).
pub(crate) const MLKEM768_PUBLIC_KEY_BYTES: usize = 1184;
/// Wire-format size of an ML-KEM-768 ciphertext (FIPS 203 §7).
pub(crate) const MLKEM768_CIPHERTEXT_BYTES: usize = 1088;
/// X25519 public-key / shared-secret size.
pub(crate) const X25519_BYTES: usize = 32;
/// ML-KEM shared secret size (FIPS 203 §6: 32 bytes for all parameter sets).
pub(crate) const MLKEM_SHARED_SECRET_BYTES: usize = 32;

/// Size of the `KEX_ECDH_INIT` payload (after the message-id byte and the
/// SSH-string length prefix): `mlkem_pub || x25519_pub`.
pub(crate) const INIT_BLOB_LEN: usize = MLKEM768_PUBLIC_KEY_BYTES + X25519_BYTES;

/// Size of the `KEX_ECDH_REPLY` server blob: `mlkem_ct || x25519_pub`.
pub(crate) const REPLY_BLOB_LEN: usize = MLKEM768_CIPHERTEXT_BYTES + X25519_BYTES;

/// Type tag used by the `KexType` registration table.
pub struct MlKem768X25519Sha256KexType {}

impl KexType for MlKem768X25519Sha256KexType {
    fn make(&self) -> Box<dyn KexAlgorithm + Send> {
        Box::new(MlKem768X25519Sha256Kex {
            x25519_secret: None,
            mlkem_decap_key: None,
            shared_secret: None,
        }) as Box<dyn KexAlgorithm + Send>
    }
}

/// Per-session KEX state.
///
/// On the client we hold the ephemeral X25519 scalar and the ML-KEM
/// decapsulation key until `compute_shared_secret` consumes them. On the
/// server we never need long-lived state: both shared-secret halves are
/// derived synchronously inside `server_dh`.
#[doc(hidden)]
pub struct MlKem768X25519Sha256Kex {
    x25519_secret: Option<Scalar>,
    mlkem_decap_key: Option<ml_kem::DecapsulationKey<MlKem768>>,
    /// `K = SHA-256(K_mlkem || K_x25519)` — already 32 bytes, ready to
    /// length-prefix as an SSH string when feeding the exchange hash.
    shared_secret: Option<[u8; 32]>,
}

impl std::fmt::Debug for MlKem768X25519Sha256Kex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "MlKem768X25519Sha256Kex {{ x25519_secret: [hidden], \
             mlkem_decap_key: [hidden], shared_secret: [hidden] }}",
        )
    }
}

/// Combine the two leg shared secrets per OpenSSH `kexmlkem768x25519.c`:
/// `K = SHA-256(K_mlkem || K_x25519)`.
fn combine_shared_secrets(k_mlkem: &[u8; 32], k_x25519: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(k_mlkem);
    hasher.update(k_x25519);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_slice());
    out
}

impl KexAlgorithm for MlKem768X25519Sha256Kex {
    fn skip_exchange(&self) -> bool {
        false
    }

    #[doc(hidden)]
    fn server_dh(&mut self, exchange: &mut Exchange, payload: &[u8]) -> Result<(), crate::Error> {
        debug!("mlkem768x25519 server_dh");

        // Layout of `payload`:
        //   [0]      = SSH_MSG_KEX_ECDH_INIT
        //   [1..5]   = u32 blob length (must equal INIT_BLOB_LEN)
        //   [5..]    = mlkem_pub || x25519_pub
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
        #[allow(clippy::indexing_slicing)] // length checked above
        let mlkem_pub_bytes = &payload[5..5 + MLKEM768_PUBLIC_KEY_BYTES];
        #[allow(clippy::indexing_slicing)] // length checked above
        let x25519_pub_bytes =
            &payload[5 + MLKEM768_PUBLIC_KEY_BYTES..5 + INIT_BLOB_LEN];

        // Parse ML-KEM public key.
        let ek_bytes = ml_kem::array::Array::try_from(mlkem_pub_bytes)
            .map_err(|_| crate::Error::Kex)?;
        let ek = EncapsulationKey::<MlKem768>::new(&ek_bytes)
            .map_err(|_| crate::Error::Kex)?;

        // Parse X25519 client pubkey.
        let mut client_x25519_pub = MontgomeryPoint([0u8; X25519_BYTES]);
        client_x25519_pub.0.copy_from_slice(x25519_pub_bytes);

        // Server X25519 ephemeral keypair.
        let server_x25519_secret =
            Scalar::from_bytes_mod_order(rand::random::<[u8; 32]>());
        let server_x25519_pub =
            (ED25519_BASEPOINT_TABLE * &server_x25519_secret).to_montgomery();

        // ML-KEM encapsulation against the client's encapsulation key.
        // `Encapsulate::encapsulate()` (via the `getrandom` feature) sources
        // its own OS RNG and is infallible.
        let (mlkem_ct, mlkem_shared) = ek.encapsulate();

        // X25519 ECDH.
        let x25519_shared = server_x25519_secret * client_x25519_pub;

        // Build server reply blob: ml-kem ciphertext || server x25519 pubkey.
        exchange.server_ephemeral.clear();
        exchange.server_ephemeral.extend(mlkem_ct.as_ref());
        exchange.server_ephemeral.extend(&server_x25519_pub.0);

        // Combine into K = SHA-256(K_mlkem || K_x25519).
        let mut k_mlkem = [0u8; MLKEM_SHARED_SECRET_BYTES];
        k_mlkem.copy_from_slice(mlkem_shared.as_ref());
        self.shared_secret = Some(combine_shared_secrets(&k_mlkem, &x25519_shared.0));
        Ok(())
    }

    #[doc(hidden)]
    fn client_dh(
        &mut self,
        client_ephemeral: &mut CryptoVec,
        buf: &mut CryptoVec,
    ) -> Result<(), crate::Error> {
        // Generate ML-KEM keypair (RustCrypto sources its own OS RNG via the
        // `getrandom` feature on the `kem`/`ml-kem` crates).
        let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
        let ek_bytes = ek.to_bytes();
        debug_assert_eq!(ek_bytes.len(), MLKEM768_PUBLIC_KEY_BYTES);

        // Generate X25519 ephemeral keypair.
        let x25519_secret =
            Scalar::from_bytes_mod_order(rand::random::<[u8; X25519_BYTES]>());
        let x25519_pub = (ED25519_BASEPOINT_TABLE * &x25519_secret).to_montgomery();

        // Stash the private halves until `compute_shared_secret` runs.
        self.mlkem_decap_key = Some(dk);
        self.x25519_secret = Some(x25519_secret);

        // Build the client init blob: ml-kem pubkey || x25519 pubkey.
        client_ephemeral.clear();
        client_ephemeral.extend(ek_bytes.as_ref());
        client_ephemeral.extend(&x25519_pub.0);

        // Wire-encode the SSH_MSG_KEX_ECDH_INIT packet.
        buf.push(msg::KEX_ECDH_INIT);
        buf.extend_ssh_string(client_ephemeral);
        Ok(())
    }

    fn compute_shared_secret(&mut self, remote_pubkey_: &[u8]) -> Result<(), crate::Error> {
        if remote_pubkey_.len() != REPLY_BLOB_LEN {
            return Err(crate::Error::Kex);
        }
        #[allow(clippy::indexing_slicing)] // length checked
        let mlkem_ct_bytes = &remote_pubkey_[..MLKEM768_CIPHERTEXT_BYTES];
        #[allow(clippy::indexing_slicing)] // length checked
        let server_x25519_pub_bytes = &remote_pubkey_[MLKEM768_CIPHERTEXT_BYTES..];

        // ML-KEM decapsulation. FIPS 203 deliberately produces a
        // deterministic pseudo-random shared secret on invalid ciphertexts
        // (implicit rejection), so `decapsulate` itself is infallible — a
        // malformed ciphertext shows up downstream as an exchange-hash
        // mismatch.
        let dk = self.mlkem_decap_key.take().ok_or(crate::Error::KexInit)?;
        let ct_array = ml_kem::array::Array::try_from(mlkem_ct_bytes)
            .map_err(|_| crate::Error::Kex)?;
        let mlkem_shared = dk.decapsulate(&ct_array);

        // X25519 ECDH.
        let x25519_secret = self.x25519_secret.take().ok_or(crate::Error::KexInit)?;
        let mut server_x25519_pub = MontgomeryPoint([0u8; X25519_BYTES]);
        server_x25519_pub.0.copy_from_slice(server_x25519_pub_bytes);
        let x25519_shared = x25519_secret * server_x25519_pub;

        // Combine.
        let mut k_mlkem = [0u8; MLKEM_SHARED_SECRET_BYTES];
        k_mlkem.copy_from_slice(mlkem_shared.as_ref());
        self.shared_secret = Some(combine_shared_secrets(&k_mlkem, &x25519_shared.0));
        Ok(())
    }

    fn compute_exchange_hash(
        &self,
        key: &CryptoVec,
        exchange: &Exchange,
        buffer: &mut CryptoVec,
    ) -> Result<CryptoVec, crate::Error> {
        // Mirrors curve25519's `compute_exchange_hash` except K is encoded
        // as an SSH string (length-prefixed) rather than an mpint — per
        // OpenSSH 9.9 `kexmlkem768x25519.c` and draft-kampanakis-curdle-
        // ssh-pq-ke section 2.
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

        let mut hasher = Sha256::new();
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
        compute_keys::<Sha256>(
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

    /// Independently produce a fresh ML-KEM-768 keypair via the public
    /// `Generate`/`Kem` API. Verifies our dependency on the `getrandom`
    /// feature compiles & runs end-to-end.
    #[test]
    fn mlkem768x25519_keygen_round_trip() {
        let (dk, ek) = <MlKem768 as Kem>::generate_keypair();
        // Public keys serialize to the canonical FIPS-203 size.
        assert_eq!(ek.to_bytes().len(), MLKEM768_PUBLIC_KEY_BYTES);
        // Round-trip a known ciphertext (Encapsulate/Decapsulate are
        // infallible in the ml-kem implementation).
        let (ct, k_send) = ek.encapsulate();
        let k_recv = dk.decapsulate(&ct);
        assert_eq!(k_send, k_recv);
    }

    /// End-to-end client⇄server hybrid handshake using the `KexAlgorithm`
    /// trait, simulating both halves in-process. Confirms the derived
    /// shared secret matches on both sides.
    #[test]
    fn mlkem768x25519_encaps_decaps_shared_secret_matches() {
        let kty = MlKem768X25519Sha256KexType {};
        let mut client = kty.make();
        let mut server = kty.make();

        // 1. Client builds INIT blob.
        let mut client_ephemeral = CryptoVec::new();
        let mut init_pkt = CryptoVec::new();
        client.client_dh(&mut client_ephemeral, &mut init_pkt).unwrap();
        assert_eq!(client_ephemeral.len(), INIT_BLOB_LEN);

        // 2. Server consumes INIT, produces REPLY blob in `exchange`.
        let mut exchange = Exchange::new();
        server.server_dh(&mut exchange, &init_pkt).unwrap();
        assert_eq!(exchange.server_ephemeral.len(), REPLY_BLOB_LEN);

        // 3. Client decapsulates the server reply.
        client
            .compute_shared_secret(&exchange.server_ephemeral)
            .unwrap();

        // Both sides must now derive identical 32-byte K — but K is
        // hidden behind the trait, so we test via the exchange-hash
        // pathway, which depends on K.
        let key = CryptoVec::new();
        // Server-side computes its own hash inputs into `exchange`; we
        // populate the rest with stable test fixtures so client and
        // server hash the same prefix.
        exchange.client_id.clear();
        exchange.client_id.extend(b"SSH-2.0-client");
        exchange.server_id.clear();
        exchange.server_id.extend(b"SSH-2.0-server");
        exchange.client_kex_init.clear();
        exchange.client_kex_init.extend(b"cki");
        exchange.server_kex_init.clear();
        exchange.server_kex_init.extend(b"ski");
        exchange.client_ephemeral.clear();
        exchange.client_ephemeral.extend(client_ephemeral.as_ref());

        let mut buf = CryptoVec::new();
        let h_client = client
            .compute_exchange_hash(&key, &exchange, &mut buf)
            .unwrap();
        let mut buf2 = CryptoVec::new();
        let h_server = server
            .compute_exchange_hash(&key, &exchange, &mut buf2)
            .unwrap();
        assert_eq!(
            h_client.as_ref(),
            h_server.as_ref(),
            "exchange-hash mismatch implies shared-secret disagreement",
        );
    }

    /// Whitebox: combine_shared_secrets must equal SHA-256 of the
    /// concatenation in PQ-first order. Vectors are arbitrary distinct
    /// 32-byte values; the property checked is the *order* of inputs.
    #[test]
    fn mlkem768x25519_hybrid_kdf_combines_ss_x25519_and_ss_mlkem() {
        let k_mlkem = [0x11u8; 32];
        let k_x25519 = [0x22u8; 32];
        let got = combine_shared_secrets(&k_mlkem, &k_x25519);

        let mut expected = Sha256::new();
        expected.update(k_mlkem); // PQ first (matches OpenSSH).
        expected.update(k_x25519);
        let expected = expected.finalize();
        assert_eq!(got.as_slice(), expected.as_slice());

        // Reversing the inputs MUST produce a different digest — guards
        // against an accidental swap in `combine_shared_secrets`.
        let swapped = combine_shared_secrets(&k_x25519, &k_mlkem);
        assert_ne!(got, swapped);
    }

    /// Wire layout must hit the exact canonical FIPS 203 sizes —
    /// 1216 B init, 1120 B reply. Off-by-one here would silently break
    /// interop.
    #[test]
    fn mlkem768x25519_wire_layout_matches_openssh_format() {
        let kty = MlKem768X25519Sha256KexType {};
        let mut client = kty.make();
        let mut server = kty.make();

        let mut client_ephemeral = CryptoVec::new();
        let mut init_pkt = CryptoVec::new();
        client.client_dh(&mut client_ephemeral, &mut init_pkt).unwrap();

        // init_pkt = [msg_id (1 B)] || [u32 len = 1216] || [blob 1216 B]
        assert_eq!(init_pkt.len(), 1 + 4 + INIT_BLOB_LEN);
        assert_eq!(init_pkt[0], msg::KEX_ECDH_INIT);
        let len_field = BigEndian::read_u32(&init_pkt[1..5]) as usize;
        assert_eq!(len_field, INIT_BLOB_LEN);
        assert_eq!(INIT_BLOB_LEN, 1184 + 32, "FIPS 203 ML-KEM-768 pubkey size");

        let mut exchange = Exchange::new();
        server.server_dh(&mut exchange, &init_pkt).unwrap();
        assert_eq!(exchange.server_ephemeral.len(), REPLY_BLOB_LEN);
        assert_eq!(REPLY_BLOB_LEN, 1088 + 32, "FIPS 203 ML-KEM-768 ct size");
    }

    /// Corrupting the ML-KEM ciphertext must NOT cause an error (the
    /// FIPS 203 design intentionally returns a deterministic pseudo-
    /// random shared secret on invalid ciphertexts to resist Bleichen-
    /// bacher-style attacks), but the resulting shared secret MUST
    /// differ from the server's, so the exchange-hash check on the
    /// next round-trip will fail.
    #[test]
    fn mlkem768x25519_rejects_corrupted_ciphertext() {
        let kty = MlKem768X25519Sha256KexType {};
        let mut client = kty.make();
        let mut server = kty.make();

        let mut client_ephemeral = CryptoVec::new();
        let mut init_pkt = CryptoVec::new();
        client.client_dh(&mut client_ephemeral, &mut init_pkt).unwrap();

        let mut exchange = Exchange::new();
        server.server_dh(&mut exchange, &init_pkt).unwrap();

        // Flip a byte in the middle of the ML-KEM ciphertext.
        let mut corrupted = exchange.server_ephemeral.as_ref().to_vec();
        corrupted[100] ^= 0xff;
        // Decapsulation succeeds (implicit rejection) but yields a
        // different shared secret.
        client.compute_shared_secret(&corrupted).unwrap();

        // Stable test fixtures for the rest of the exchange hash.
        exchange.client_id.clear();
        exchange.client_id.extend(b"SSH-2.0-client");
        exchange.server_id.clear();
        exchange.server_id.extend(b"SSH-2.0-server");
        exchange.client_kex_init.clear();
        exchange.client_kex_init.extend(b"cki");
        exchange.server_kex_init.clear();
        exchange.server_kex_init.extend(b"ski");
        exchange.client_ephemeral.clear();
        exchange.client_ephemeral.extend(client_ephemeral.as_ref());

        let key = CryptoVec::new();
        let mut buf = CryptoVec::new();
        let h_client = client
            .compute_exchange_hash(&key, &exchange, &mut buf)
            .unwrap();
        let mut buf2 = CryptoVec::new();
        let h_server = server
            .compute_exchange_hash(&key, &exchange, &mut buf2)
            .unwrap();
        assert_ne!(
            h_client.as_ref(),
            h_server.as_ref(),
            "corrupted-ciphertext path must yield disagreeing exchange hashes",
        );
    }

    /// The algorithm string must be resolvable through the public
    /// `kex::Name` lookup table.
    #[test]
    fn mlkem768x25519_negotiation_table_lookup() {
        use std::convert::TryFrom;
        let name = super::super::Name::try_from("mlkem768x25519-sha256")
            .expect("must resolve via KEXES table");
        assert_eq!(name.as_ref(), "mlkem768x25519-sha256");
    }
}
