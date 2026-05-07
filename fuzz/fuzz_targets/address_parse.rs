#![no_main]
//! Fuzz BindAddr parsing — must never panic on arbitrary UTF-8 input.
use libfuzzer_sys::fuzz_target;

use std::str::FromStr;

use spt_core::address::BindAddr;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = BindAddr::from_str(s);
    let _ = BindAddr::parse(s);
});
