//! CI-runnable randomized decoder-fuzz harnesses for the SNMP wire decoders.
//!
//! These replace the deleted `fuzz/fuzz_targets/{ber_decode,snmpv3_message,
//! usm_authenticate}.rs` cargo-fuzz targets (removed in commit fb2631d) with
//! deterministic, `cargo test`-runnable equivalents. Each test hammers a wire
//! decoder with tens of thousands of random and malformed byte strings using a
//! FIXED seed (no wall-clock / no OS entropy) and asserts the decoder handles
//! every input gracefully: no panic, no arithmetic overflow (release builds run
//! with `overflow-checks = true`), no unbounded allocation. A returned `Err` is
//! the expected outcome for garbage; the point is that it never crashes.
//!
//! Run under `--release` too to exercise the overflow-checks path:
//!
//! ```text
//! cargo test -p spt-snmp --release --test fuzz_decoders
//! ```

use spt_snmp::ber::{decode_oid, Decoder, Tag};
use spt_snmp::message::{Message, ScopedPdu, SecurityParameters};
use spt_snmp::usm::{
    auth_digest, derive_keys, digests_match, localize_key, password_to_key, AuthProtocol,
    SecretBytes, UsmUser,
};

// Deterministic SplitMix64 PRNG. Seeded from a constant so every run produces
// the identical input stream — no `Instant`/`SystemTime`/`getrandom` anywhere.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    // A pseudo-random length in `0..=max`.
    fn len(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % (max + 1)
    }

    // A fresh byte vector of pseudo-random length (`0..=max`) and content.
    fn bytes(&mut self, max: usize) -> Vec<u8> {
        let n = self.len(max);
        let mut v = vec![0u8; n];
        for chunk in v.chunks_mut(8) {
            let r = self.next_u64().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(r.iter()) {
                *dst = *src;
            }
        }
        v
    }
}

// Hand-picked malformed edge cases mirroring the deleted corpus boundary
// files (empty, single byte, huge length prefix, indefinite form, all-0xFF).
const BER_EDGE_CASES: &[&[u8]] = &[
    &[],
    &[0x00],
    &[0xFF],
    &[0x30, 0x80], // SEQUENCE, indefinite length (must be rejected)
    &[0x02, 0x7F], // INTEGER, length 127, no body
    &[0x04, 0x84, 0xFF, 0xFF, 0xFF, 0xFF], // OCTET STRING, 4 GiB length prefix
    &[0x06, 0x00], // OID, empty
    &[0x30, 0x03, 0x02, 0x01], // SEQUENCE claiming 3 bytes, truncated INTEGER
    &[0xFF; 32],
    &[0x00; 32],
];

// Feed one byte slice through every BER decode entry point. No panics allowed.
fn hammer_ber(data: &[u8]) {
    let _ = decode_oid(data);

    let mut d = Decoder::new(data);
    let mut steps = 0;
    while !d.is_empty() && steps < 64 {
        if d.read_tlv().is_err() {
            break;
        }
        steps += 1;
    }

    let _ = Decoder::new(data).read_i64();
    let _ = Decoder::new(data).read_u32();
    let _ = Decoder::new(data).read_octet_string();
    let _ = Decoder::new(data).read_null();
    let _ = Decoder::new(data).read_oid();
    let _ = Decoder::new(data).read_counter64();
    let _ = Decoder::new(data).read_app_u32(Tag::COUNTER32);
    if let Ok(mut sub) = Decoder::new(data).read_sequence() {
        let _ = sub.read_tlv();
    }
}

// Feed one byte slice through the SNMPv3 envelope decoders. No panics allowed.
fn hammer_message(data: &[u8]) {
    if let Ok(msg) = Message::from_bytes(data) {
        // A successfully parsed message must re-encode without panicking.
        let _ = msg.to_bytes();
    }
    let _ = SecurityParameters::decode_inner(data);
    let _ = ScopedPdu::from_bytes(data);
}

#[test]
fn ber_decoder_survives_random_and_malformed_input() {
    for case in BER_EDGE_CASES {
        hammer_ber(case);
    }
    let mut rng = Rng::new(0x5350_545F_4245_5200); // "SPT_BER\0"
    for _ in 0..30_000 {
        let data = rng.bytes(300);
        hammer_ber(&data);
    }
}

#[test]
fn snmpv3_message_decoder_survives_random_and_malformed_input() {
    for case in BER_EDGE_CASES {
        hammer_message(case);
    }
    let mut rng = Rng::new(0x5350_545F_4D53_4700); // "SPT_MSG\0"
    for _ in 0..30_000 {
        let data = rng.bytes(400);
        hammer_message(&data);
    }
}

fn pick_auth(c: u64) -> AuthProtocol {
    match c % 3 {
        0 => AuthProtocol::HmacMd5,
        1 => AuthProtocol::HmacSha1,
        _ => AuthProtocol::HmacSha256,
    }
}

#[test]
fn usm_auth_primitives_survive_random_input_cheap_paths() {
    // The cheap HMAC / constant-time-compare / key-localization paths run at a
    // high iteration count; they do not touch the 1 MiB key-expansion loop.
    let mut rng = Rng::new(0x5350_545F_5553_4D00); // "SPT_USM\0"
    for _ in 0..30_000 {
        let auth = pick_auth(rng.next_u64());
        let key = rng.bytes(80);
        let message = rng.bytes(300);
        let other = rng.bytes(64);
        let ku = rng.bytes(48);
        let engine_id = rng.bytes(40);

        // HMAC over arbitrary key/message length must never panic.
        if let Ok(digest) = auth_digest(auth, &key, &message) {
            let _ = digests_match(&digest, &other);
            // Self-comparison is always true (constant-time path sanity).
            assert!(digests_match(&digest, &digest));
        }
        // Key localization accepts any ku / engine-id length.
        let _ = localize_key(auth, &ku, &engine_id);
    }
}

#[test]
fn usm_password_derivation_survives_random_input_expensive_paths() {
    // password_to_key / derive_keys each hash 1 MiB per call (RFC 3414 key
    // expansion), so this expensive path runs at a deliberately low count —
    // enough to surface a panic without slowing the CI gate.
    let mut rng = Rng::new(0x5350_545F_5057_4400); // "SPT_PWD\0"
    for _ in 0..256 {
        let auth = pick_auth(rng.next_u64());
        let password = rng.bytes(64);
        let engine_id = rng.bytes(40);

        let _ku = password_to_key(auth, &password);

        let user = UsmUser::auth_only("fuzz", auth, SecretBytes::new(password));
        let _ = derive_keys(&user, &engine_id);
    }
}
