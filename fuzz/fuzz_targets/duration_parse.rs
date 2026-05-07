#![no_main]
//! Fuzz parse_duration — must never panic on arbitrary UTF-8 input.
use libfuzzer_sys::fuzz_target;

use spt_core::duration::parse_duration;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = parse_duration(s);
});
