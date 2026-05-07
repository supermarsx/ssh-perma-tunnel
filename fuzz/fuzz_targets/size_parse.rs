#![no_main]
//! Fuzz parse_size — must never panic on arbitrary UTF-8 input.
use libfuzzer_sys::fuzz_target;

use spt_core::size::parse_size;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = parse_size(s);
});
