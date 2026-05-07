#![no_main]
//! Fuzz the BER decoder. We exercise multiple decode paths so the fuzzer
//! explores tag/length/payload edge cases rather than only the OID one.
use libfuzzer_sys::fuzz_target;

use spt_snmp::ber::{decode_oid, Decoder, Tag};

fuzz_target!(|data: &[u8]| {
    // Path 1: raw OID decoder.
    let _ = decode_oid(data);

    // Path 2: walk a stream of TLVs.
    let mut d = Decoder::new(data);
    let mut steps = 0;
    while !d.is_empty() && steps < 64 {
        if d.read_tlv().is_err() {
            break;
        }
        steps += 1;
    }

    // Path 3: try the typed readers from the start.
    let mut d = Decoder::new(data);
    let _ = d.read_i64();
    let mut d = Decoder::new(data);
    let _ = d.read_u32();
    let mut d = Decoder::new(data);
    let _ = d.read_octet_string();
    let mut d = Decoder::new(data);
    let _ = d.read_null();
    let mut d = Decoder::new(data);
    let _ = d.read_oid();
    let mut d = Decoder::new(data);
    let _ = d.read_counter64();
    let mut d = Decoder::new(data);
    let _ = d.read_app_u32(Tag::COUNTER32);
    let mut d = Decoder::new(data);
    if let Ok(mut sub) = d.read_sequence() {
        let _ = sub.read_tlv();
    }
});
