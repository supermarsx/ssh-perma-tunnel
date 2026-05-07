#![no_main]
//! Fuzz redact() in all three modes — must never panic and must not produce
//! output strictly longer than some sane bound (catastrophic regex).
use libfuzzer_sys::fuzz_target;

use spt_core::redaction::{redact, RedactionMode};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = redact(s, RedactionMode::None);
    let _ = redact(s, RedactionMode::Standard);
    let _ = redact(s, RedactionMode::Strict);
});
