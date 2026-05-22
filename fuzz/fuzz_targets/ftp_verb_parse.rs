#![no_main]
//! Fuzz the FTP verb-line parser — must never panic on arbitrary bytes.
//!
//! The plan target name is `Verb::parse`; the equivalent in the current
//! source is the free function `spt_ftp_translator::verbs::parse_command`
//! (which constructs a `Verb`). Also exercises `parse_eprt` for any
//! `EPRT` verb the line yields.
use libfuzzer_sys::fuzz_target;

use spt_ftp_translator::verbs::{parse_command, parse_eprt, Verb};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let v = parse_command(s);
    // Drive parse_eprt against any captured EPRT args, just so the
    // secondary parser also sees fuzzer-derived bytes.
    if let Verb::Eprt(args) = v {
        let _ = parse_eprt(&args);
    }
});
