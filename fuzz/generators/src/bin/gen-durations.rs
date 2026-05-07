//! Emit duration strings for the `duration_parse` fuzz target.

use spt_core::duration::parse_duration;
use spt_fuzz_generators::{out_dir_from_args, write_file};

fn try_emit(dir: &std::path::Path, name: &str, s: &str) {
    if parse_duration(s).is_err() {
        eprintln!("  ! {name}: parse failed — committing as boundary seed");
    }
    write_file(dir, name, s.as_bytes());
}

fn main() {
    let dir = out_dir_from_args();

    // Valid simple units
    try_emit(&dir, "valid_zero_s.txt", "0s");
    try_emit(&dir, "valid_one_ns.txt", "1ns");
    try_emit(&dir, "valid_one_us.txt", "1us");
    try_emit(&dir, "valid_one_ms.txt", "1ms");
    try_emit(&dir, "valid_one_s.txt", "1s");
    try_emit(&dir, "valid_one_m.txt", "1m");
    try_emit(&dir, "valid_one_h.txt", "1h");
    try_emit(&dir, "valid_one_d.txt", "1d");

    // Typical values
    try_emit(&dir, "valid_30s.txt", "30s");
    try_emit(&dir, "valid_5m.txt", "5m");
    try_emit(&dir, "valid_15m.txt", "15m");
    try_emit(&dir, "valid_2h.txt", "2h");
    try_emit(&dir, "valid_24h.txt", "24h");
    try_emit(&dir, "valid_7d.txt", "7d");
    try_emit(&dir, "valid_500ms.txt", "500ms");
    try_emit(&dir, "valid_100us.txt", "100us");

    // Compound forms (humantime accepts these)
    try_emit(&dir, "valid_compound_hms.txt", "1h30m45s");
    try_emit(&dir, "valid_compound_dh.txt", "2d12h");
    try_emit(&dir, "valid_compound_full.txt", "1d2h3m4s5ms");

    // Boundaries
    write_file(&dir, "boundary_empty.txt", b"");
    write_file(&dir, "boundary_no_unit.txt", b"42");
    write_file(&dir, "boundary_only_unit.txt", b"s");
    write_file(&dir, "boundary_negative.txt", b"-5s");
    write_file(&dir, "boundary_huge_value.txt",
        b"99999999999999999999999999999999s");
    write_file(&dir, "boundary_unit_unknown.txt", b"5xyz");
    write_file(&dir, "boundary_float.txt", b"1.5s");
    write_file(&dir, "boundary_space.txt", b"5 s");
    write_file(&dir, "boundary_whitespace_only.txt", b"   ");
    write_file(&dir, "boundary_null_byte.txt", b"5s\0");
    write_file(&dir, "boundary_unicode_digits.txt",
        "５s".as_bytes()); // fullwidth 5
    write_file(&dir, "boundary_bom.txt", "\u{FEFF}5s".as_bytes());
    write_file(&dir, "boundary_long.txt",
        format!("{}s", "9".repeat(1024)).as_bytes());

    println!("duration_parse: corpus generated under {}", dir.display());
}
