//! CI-runnable randomized fuzz harness for the `known_hosts` parser.
//!
//! Replaces the deleted `fuzz/fuzz_targets/known_hosts.rs` cargo-fuzz target
//! (removed in commit fb2631d) with a deterministic, `cargo test`-runnable
//! equivalent. `KnownHosts::parse` ingests untrusted on-disk text and must
//! never panic on arbitrary input. A fixed seed keeps the input stream
//! reproducible (no wall-clock / no OS entropy).
//!
//! Run under `--release` too to exercise the overflow-checks path:
//!
//! ```text
//! cargo test -p spt-trust --release --test fuzz_known_hosts
//! ```

use spt_trust::KnownHosts;

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

    // Random bytes, lossily decoded to a `String` (the parser takes `&str`).
    fn text(&mut self, max: usize) -> String {
        let n = self.len(max);
        let mut v = vec![0u8; n];
        for chunk in v.chunks_mut(8) {
            let r = self.next_u64().to_le_bytes();
            for (dst, src) in chunk.iter_mut().zip(r.iter()) {
                *dst = *src;
            }
        }
        String::from_utf8_lossy(&v).into_owned()
    }

    // Random text drawn from a known_hosts-flavoured alphabet, so the parser
    // reaches its field-splitting / base64 / marker branches far more often
    // than uniform-random bytes would.
    fn structured_line(&mut self, max: usize) -> String {
        const ALPHABET: &[u8] =
            b"ssh-ed25519 ssh-rsa ecdsa-sha2-nistp256 |1|@revoked @cert-authority \
              0123456789abcdefABCDEF+/=. :[]*?,\n host.example.com AAAA";
        let n = self.len(max);
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            let idx = (self.next_u64() as usize) % ALPHABET.len();
            s.push(ALPHABET[idx] as char);
        }
        s
    }
}

const EDGE_CASES: &[&str] = &[
    "",
    "\n",
    " ",
    "|1|",
    "|1|abc|def",
    "@revoked",
    "@cert-authority host ssh-ed25519",
    "host.example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5",
    "host ssh-rsa !!!!not-base64!!!!",
    "[::1]:22 ssh-ed25519 AAAA",
    "\0\0\0\0",
];

#[test]
fn known_hosts_parser_survives_random_and_malformed_input() {
    for case in EDGE_CASES {
        let _ = KnownHosts::parse(case);
    }
    let mut rng = Rng::new(0x5350_545F_4B48_5300); // "SPT_KHS\0"
    for _ in 0..15_000 {
        let raw = rng.text(400);
        let _ = KnownHosts::parse(&raw);
        let structured = rng.structured_line(400);
        let _ = KnownHosts::parse(&structured);
    }
}
