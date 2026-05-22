#![no_main]
//! Fuzz the OpenSSH `~/.ssh/config` parser — must never panic.
//!
//! The plan target name is `parse_openssh_config_str`; the equivalent in
//! the current source is `spt_config::openssh_config::parse`. We also
//! call `resolve_host` against a fixed name so the lookup path is
//! exercised against fuzzer-derived `HostBlock` shapes.
use libfuzzer_sys::fuzz_target;

use spt_config::openssh_config::{parse, parse_user_host_port, resolve_host};

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let blocks = parse(s);
    let _ = resolve_host(&blocks, "fuzz.invalid");
    // Re-feed the input through the user@host:port helper, which is the
    // sibling parser used while walking ProxyJump chains.
    let _ = parse_user_host_port(s);
});
