#![no_main]
//! Fuzz the SNMPv3 message envelope decoder.
use libfuzzer_sys::fuzz_target;

#[allow(unused_imports)]
use spt_snmp::message::{Message, ScopedPdu, SecurityParameters};

fuzz_target!(|data: &[u8]| {
    // Top-level: full Message::from_bytes.
    if let Ok(msg) = Message::from_bytes(data) {
        // Round-trip should not panic, even if it fails.
        let _ = msg.to_bytes();
    }
    // Inner shapes — exercised independently so the fuzzer can find issues
    // even without crafting a valid outer envelope.
    // SecurityParameters: parsed via its inner BER SEQUENCE bytes.
    let _ = SecurityParameters::decode_inner(data);
    // ScopedPdu: parsed via its outer SEQUENCE bytes.
    let _ = ScopedPdu::from_bytes(data);
});
