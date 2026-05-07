//! Emit USM-shaped seed inputs for the `usm_authenticate` fuzz target.
//!
//! The fuzz harness consumes `arbitrary` bytes (Unstructured) — each input
//! decodes into auth_choice/key/message/engine_id/password/other_digest. We
//! seed with byte buffers that drive every interesting branch: each auth
//! protocol, short / typical / long keys, empty inputs, and aligned-len edge
//! cases (16/20/32 = MD5/SHA-1/SHA-256 digest lengths).

use spt_fuzz_generators::{out_dir_from_args, write_file};

/// Encode a `&[u8]` field as `arbitrary` does for `&'a [u8]` borrows
/// (length consumed from the *back* of the buffer with `arbitrary_take_rest`
/// rules — so we just append the raw bytes; the trailing field swallows them).
fn build(auth_choice: u8, key: &[u8], message: &[u8], engine_id: &[u8], password: &[u8], other_digest: &[u8]) -> Vec<u8> {
    // The `arbitrary` derive for a struct with multiple `&[u8]` fields
    // allocates each from the front using a length prefix consumed via
    // `usize::arbitrary` (varint-ish 8-byte little-endian masked length).
    // We don't need to round-trip; we just need diverse byte buffers.
    // We layout: [auth_choice][len_varint key][key][len_varint msg][msg]...
    // and pad with extra bytes so Unstructured has plenty to consume.
    let mut out = Vec::new();
    out.push(auth_choice);
    for f in [key, message, engine_id, password, other_digest] {
        out.extend_from_slice(&(f.len() as u32).to_le_bytes());
        out.extend_from_slice(f);
    }
    // Padding so the last `&[u8]` field's `arbitrary_take_rest` has bytes
    // even after Unstructured's length-consumption overhead.
    out.extend(std::iter::repeat(0u8).take(16));
    out
}

fn main() {
    let dir = out_dir_from_args();

    // Each auth protocol × short/typical/long combinations.
    for (i, auth) in [0u8, 1, 2].iter().enumerate() {
        let name = ["md5", "sha1", "sha256"][i];
        write_file(&dir, &format!("valid_{name}_empty.bin"),
            &build(*auth, b"", b"", b"", b"", b""));
        write_file(&dir, &format!("valid_{name}_short.bin"),
            &build(*auth, b"key", b"msg", b"engine", b"pw", b"d"));
        write_file(&dir, &format!("valid_{name}_typical.bin"),
            &build(*auth, &[0x42u8; 20], b"the quick brown fox", b"\x80\x00\x1f\x88\x80spt", b"correct horse battery staple", &[0u8; 12]));
    }

    // Digest-length-aligned other_digest values for each protocol.
    write_file(&dir, "valid_md5_digestlen.bin",
        &build(0, b"k", b"m", b"e", b"pw", &[0u8; 16]));
    write_file(&dir, "valid_sha1_digestlen.bin",
        &build(1, b"k", b"m", b"e", b"pw", &[0u8; 20]));
    write_file(&dir, "valid_sha256_digestlen.bin",
        &build(2, b"k", b"m", b"e", b"pw", &[0u8; 32]));

    // Long key (HMAC: keys longer than block size go through key-hashing).
    write_file(&dir, "valid_long_key_md5.bin",
        &build(0, &[0xAA; 64], b"m", b"e", b"pw", b"d"));
    write_file(&dir, "valid_long_key_sha256.bin",
        &build(2, &[0x55; 128], &[0xFFu8; 256], b"engine-id", &[b'p'; 64], &[0u8; 32]));

    // Long message — exercises HMAC streaming.
    write_file(&dir, "valid_long_message.bin",
        &build(2, b"key", &[0x01u8; 4096], b"e", b"pw", b"d"));

    // Empty engine_id (corner case for key localization).
    write_file(&dir, "valid_empty_engine.bin",
        &build(1, b"k", b"m", b"", b"pw", b"d"));

    // Long engine_id (max RFC: 32 bytes).
    write_file(&dir, "valid_max_engine.bin",
        &build(1, b"k", b"m", &[0xCC; 32], b"pw", b"d"));

    // Boundaries --------------------------------------------------------
    write_file(&dir, "boundary_empty.bin", b"");
    write_file(&dir, "boundary_one_byte.bin", b"\x00");
    write_file(&dir, "boundary_all_zero.bin", &[0u8; 64]);
    write_file(&dir, "boundary_all_ff.bin", &[0xFFu8; 64]);
    write_file(&dir, "boundary_auth_choice_overflow.bin", &[0xFFu8; 32]);
    {
        // Tiny: just the discriminator and not enough bytes for any field.
        write_file(&dir, "boundary_truncated.bin", &[0x01, 0x00]);
    }

    println!("usm_authenticate: corpus generated under {}", dir.display());
}
