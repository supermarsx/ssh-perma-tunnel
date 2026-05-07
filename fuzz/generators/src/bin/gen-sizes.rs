//! Emit size strings for the `size_parse` fuzz target.

use spt_core::size::parse_size;
use spt_fuzz_generators::{out_dir_from_args, write_file};

fn try_emit(dir: &std::path::Path, name: &str, s: &str) {
    if parse_size(s).is_err() {
        eprintln!("  ! {name}: parse failed — committing as boundary seed");
    }
    write_file(dir, name, s.as_bytes());
}

fn main() {
    let dir = out_dir_from_args();

    // Bare bytes
    try_emit(&dir, "valid_zero.txt", "0");
    try_emit(&dir, "valid_one.txt", "1");
    try_emit(&dir, "valid_512.txt", "512");
    try_emit(&dir, "valid_with_b.txt", "1024B");
    try_emit(&dir, "valid_with_b_lower.txt", "1024b");

    // SI (decimal)
    try_emit(&dir, "valid_kb.txt", "1KB");
    try_emit(&dir, "valid_mb.txt", "10MB");
    try_emit(&dir, "valid_gb.txt", "5GB");
    try_emit(&dir, "valid_tb.txt", "2TB");
    try_emit(&dir, "valid_pb.txt", "1PB");

    // IEC (binary)
    try_emit(&dir, "valid_kib.txt", "1KiB");
    try_emit(&dir, "valid_mib.txt", "10MiB");
    try_emit(&dir, "valid_gib.txt", "1GiB");
    try_emit(&dir, "valid_tib.txt", "1TiB");
    try_emit(&dir, "valid_pib.txt", "1PiB");

    // Spacing & case
    try_emit(&dir, "valid_with_space.txt", "10 MiB");
    try_emit(&dir, "valid_lowercase.txt", "10mib");
    try_emit(&dir, "valid_mixed_case.txt", "10mIB");

    // Boundaries
    write_file(&dir, "boundary_empty.txt", b"");
    write_file(&dir, "boundary_only_unit.txt", b"MB");
    write_file(&dir, "boundary_negative.txt", b"-5MB");
    write_file(&dir, "boundary_unknown_unit.txt", b"5XB");
    write_file(&dir, "boundary_overflow.txt",
        b"99999999999999999999999999PB");
    write_file(&dir, "boundary_float.txt", b"1.5MB");
    write_file(&dir, "boundary_just_dot.txt", b".");
    write_file(&dir, "boundary_whitespace.txt", b"   ");
    write_file(&dir, "boundary_null_byte.txt", b"5MB\0");
    write_file(&dir, "boundary_two_units.txt", b"5MBKB");
    write_file(&dir, "boundary_unicode.txt", "５MB".as_bytes());
    write_file(&dir, "boundary_bom.txt", "\u{FEFF}1KB".as_bytes());
    write_file(&dir, "boundary_long.txt",
        format!("{}KB", "9".repeat(1024)).as_bytes());

    println!("size_parse: corpus generated under {}", dir.display());
}
