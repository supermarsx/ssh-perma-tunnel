#![no_main]
//! Fuzz the known_hosts parser — must never panic on arbitrary text.
use libfuzzer_sys::fuzz_target;

use spt_trust::KnownHosts;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = KnownHosts::parse(s);
});
