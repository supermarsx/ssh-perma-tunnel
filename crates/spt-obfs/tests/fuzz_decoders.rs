//! CI-runnable randomized decoder-fuzz harnesses for the obfuscation-transport
//! frame decoders.
//!
//! Replaces the deleted `fuzz/fuzz_targets/{obfs4_frame_decode,
//! shadowsocks_aead_decrypt}.rs` cargo-fuzz targets (removed in commit fb2631d)
//! with deterministic, `cargo test`-runnable equivalents. Both decoders ingest
//! attacker-controlled ciphertext off the wire and must reject any malformed
//! bytes without panicking, overflowing, or over-allocating. A fixed seed keeps
//! the input stream reproducible (no wall-clock / no OS entropy).
//!
//! Run under `--release` too to exercise the overflow-checks path:
//!
//! ```text
//! cargo test -p spt-obfs --release --test fuzz_decoders
//! ```

use std::sync::{Arc, OnceLock};

use spt_obfs::audit::NoopAuditHook;
use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::obfs4::open_frame;
use spt_obfs::shadowsocks::ShadowsocksTransport;
use spt_secrets::SecretRef;

// Deterministic SplitMix64 PRNG (see spt-snmp fuzz harness for rationale).
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

    fn len(&mut self, max: usize) -> usize {
        (self.next_u64() as usize) % (max + 1)
    }

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

const FRAME_EDGE_CASES: &[&[u8]] = &[
    &[],
    &[0x00],
    &[0xFF],
    &[0x00, 0x00],
    &[0xFF; 16],
    &[0x00; 64],
    &[0xAB; 300],
];

// A fixed all-zero key so the fuzzer explores framing / tag shape rather than
// re-discovering a key.
const OBFS4_KEY: [u8; 32] = [0u8; 32];

fn hammer_obfs4(data: &[u8]) {
    // A few nonce counters exercise the AAD/nonce path without ballooning
    // per-input runtime.
    for ctr in [0u64, 1, u64::MAX] {
        let _ = open_frame(&OBFS4_KEY, ctr, data);
    }
}

static SS_TRANSPORT: OnceLock<ShadowsocksTransport> = OnceLock::new();

fn ss_transport() -> &'static ShadowsocksTransport {
    SS_TRANSPORT.get_or_init(|| {
        let password = SecretRef::new("fuzz", "ss").expect("valid SecretRef");
        let cfg = ObfsConfig::Shadowsocks {
            method: SsMethod::ChaCha20Poly1305,
            password,
        };
        ShadowsocksTransport::new(cfg, Arc::new(NoopAuditHook))
            .expect("ss transport constructs")
            .with_direct_password(b"fuzz-fixed-password".to_vec())
    })
}

#[test]
fn obfs4_frame_decoder_survives_random_and_malformed_input() {
    for case in FRAME_EDGE_CASES {
        hammer_obfs4(case);
    }
    let mut rng = Rng::new(0x5350_545F_4F42_3400); // "SPT_OB4\0"
    for _ in 0..15_000 {
        let data = rng.bytes(600);
        hammer_obfs4(&data);
    }
}

#[test]
fn shadowsocks_aead_decoder_survives_random_and_malformed_input() {
    let t = ss_transport();
    for case in FRAME_EDGE_CASES {
        let _ = t.open(case);
    }
    let mut rng = Rng::new(0x5350_545F_5353_0000); // "SPT_SS\0\0"
    for _ in 0..15_000 {
        let data = rng.bytes(600);
        let _ = t.open(&data);
    }
}
