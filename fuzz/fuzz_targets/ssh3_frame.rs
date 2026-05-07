#![no_main]
//! Fuzz the SSH3 frame envelope decoder and the typed payload decoders.
use bytes::Bytes;
use libfuzzer_sys::fuzz_target;

use spt_ssh3::frame::{
    ChannelOpenPayload, ForwardOpenResponse, Ssh3Frame, Ssh3Settings, UdpAssociatePayload,
};

fuzz_target!(|data: &[u8]| {
    // Outer frame envelope — possibly multiple frames concatenated.
    let mut buf = Bytes::copy_from_slice(data);
    let mut steps = 0;
    while !buf.is_empty() && steps < 16 {
        match Ssh3Frame::decode(&mut buf) {
            Ok(_) => steps += 1,
            Err(_) => break,
        }
    }

    // Each typed payload decoder, with the raw bytes as the payload.
    let payload = Bytes::copy_from_slice(data);
    let _ = Ssh3Settings::decode_payload(payload.clone());
    let _ = ChannelOpenPayload::decode(payload.clone());
    let _ = ForwardOpenResponse::decode(payload.clone());
    let _ = UdpAssociatePayload::decode(payload);
});
