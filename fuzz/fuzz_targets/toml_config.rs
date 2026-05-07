#![no_main]
//! Fuzz the TOML config loader. Goal: never panic on arbitrary text input.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    // Try both strict and lenient — strict has the extra unknown-key promotion path.
    let _ = spt_config::load::load_str(s, false);
    let _ = spt_config::load::load_str(s, true);
});
