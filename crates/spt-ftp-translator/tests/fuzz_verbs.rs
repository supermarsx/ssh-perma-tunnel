//! CI-runnable randomized fuzz harness for the FTP verb-line parser.
//!
//! Replaces the deleted `fuzz/fuzz_targets/ftp_verb_parse.rs` cargo-fuzz target
//! (removed in commit fb2631d) with a deterministic, `cargo test`-runnable
//! equivalent. `parse_command` (and the secondary `parse_eprt`) ingest
//! untrusted control-channel lines and must never panic on arbitrary bytes. A
//! fixed seed keeps the input stream reproducible (no wall-clock / no OS
//! entropy).
//!
//! Run under `--release` too to exercise the overflow-checks path:
//!
//! ```text
//! cargo test -p spt-ftp-translator --release --test fuzz_verbs
//! ```

use spt_ftp_translator::verbs::{parse_command, parse_eprt, Verb};

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

    // Random text drawn from an FTP-flavoured alphabet so the parser reaches
    // its verb-dispatch, EPRT and argument branches far more often than
    // uniform-random bytes would.
    fn structured_line(&mut self, max: usize) -> String {
        const ALPHABET: &[u8] = b"EPRT EPSV PORT PASV RETR STOR LIST TYPE AUTH \
              |1|2|3|127.0.0.1|::1|22|65535| \0\r\n abcABC/.:";
        let n = self.len(max);
        let mut s = String::with_capacity(n);
        for _ in 0..n {
            let idx = (self.next_u64() as usize) % ALPHABET.len();
            s.push(ALPHABET[idx] as char);
        }
        s
    }
}

fn hammer(line: &str) {
    let v = parse_command(line);
    // Re-feed any captured EPRT args through the secondary parser so it also
    // sees fuzzer-derived bytes.
    if let Verb::Eprt(args) = v {
        let _ = parse_eprt(&args);
    }
}

#[test]
fn ftp_verb_parser_survives_random_and_malformed_input() {
    let edge_cases = [
        "",
        " ",
        "\r\n",
        "EPRT",
        "EPRT |||",
        "EPRT |1|127.0.0.1|22|",
        "EPRT |2|::1|65535|",
        "PORT ,,,,,",
        "\0\0\0",
        "RETR ",
    ];
    for case in edge_cases {
        hammer(case);
    }
    let mut rng = Rng::new(0x5350_545F_4654_5000); // "SPT_FTP\0"
    for _ in 0..15_000 {
        let raw = rng.text(300);
        hammer(&raw);
        let structured = rng.structured_line(300);
        hammer(&structured);
    }
}
