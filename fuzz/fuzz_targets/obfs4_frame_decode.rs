#![no_main]
//! Fuzz the obfs4 ChaCha20-Poly1305 frame decoder — must reject any
//! malformed bytes without panicking.
//!
//! The plan target name is `Frame::decode`; the equivalent in the current
//! source is the free function `spt_obfs::obfs4::open_frame`. A fixed
//! zero key + zero counter is used so the fuzzer focuses on framing /
//! ciphertext shape rather than re-discovering the key.
use libfuzzer_sys::fuzz_target;

use spt_obfs::obfs4::open_frame;

const KEY: [u8; 32] = [0u8; 32];

fuzz_target!(|data: &[u8]| {
    // Try a handful of nonce counters to exercise the AAD/nonce path
    // without ballooning runtime per input.
    for ctr in [0u64, 1, u64::MAX] {
        let _ = open_frame(&KEY, ctr, data);
    }
});
