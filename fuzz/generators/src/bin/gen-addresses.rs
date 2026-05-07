//! Emit address strings for the `address_parse` fuzz target.

use spt_core::address::BindAddr;
use spt_fuzz_generators::{out_dir_from_args, write_file};

fn try_emit(dir: &std::path::Path, name: &str, s: &str) {
    if BindAddr::parse(s).is_err() {
        eprintln!("  ! {name}: parse failed — committing as boundary seed");
    }
    write_file(dir, name, s.as_bytes());
}

fn main() {
    let dir = out_dir_from_args();

    // Valid IPv4
    try_emit(&dir, "valid_ipv4_loopback.txt", "127.0.0.1:53");
    try_emit(&dir, "valid_ipv4_zero.txt", "0.0.0.0:80");
    try_emit(&dir, "valid_ipv4_high.txt", "255.255.255.255:65535");
    try_emit(&dir, "valid_ipv4_low_port.txt", "1.2.3.4:1");

    // Valid IPv6 (square-bracketed required by the parser)
    try_emit(&dir, "valid_ipv6_loopback.txt", "[::1]:8080");
    try_emit(&dir, "valid_ipv6_full.txt", "[2001:db8:85a3::8a2e:370:7334]:443");
    try_emit(&dir, "valid_ipv6_zero.txt", "[::]:0");
    try_emit(&dir, "valid_ipv6_v4mapped.txt", "[::ffff:192.0.2.1]:22");

    // Valid host:port
    try_emit(&dir, "valid_hostname.txt", "example.com:22");
    try_emit(&dir, "valid_subdomain.txt", "svc.internal.example.com:8443");
    try_emit(&dir, "valid_idn_punycode.txt", "xn--bcher-kva.example:80");
    try_emit(&dir, "valid_unicode_host.txt", "ホスト.example:443");
    try_emit(&dir, "valid_single_label.txt", "myhost:22");
    try_emit(&dir, "valid_underscore.txt", "my_host:22");

    // Unix
    try_emit(&dir, "valid_unix_simple.txt", "unix:///run/spt.sock");
    try_emit(&dir, "valid_unix_long.txt", "unix:///var/run/very/long/nested/path/file.sock");
    try_emit(&dir, "valid_unix_relative_like.txt", "unix:///./.hidden.sock");

    // Boundaries — invalid by spec, harness must not panic
    write_file(&dir, "boundary_empty.txt", b"");
    write_file(&dir, "boundary_one_byte.txt", b"x");
    write_file(&dir, "boundary_only_colon.txt", b":");
    write_file(&dir, "boundary_no_port.txt", b"host");
    write_file(&dir, "boundary_empty_host.txt", b":80");
    write_file(&dir, "boundary_port_overflow.txt", b"host:99999");
    write_file(&dir, "boundary_negative_port.txt", b"host:-1");
    write_file(&dir, "boundary_unbalanced_bracket.txt", b"[::1:80");
    write_file(&dir, "boundary_bracket_no_port.txt", b"[::1]");
    write_file(&dir, "boundary_bracket_bad_v6.txt", b"[gggg::]:22");
    write_file(&dir, "boundary_unix_no_path.txt", b"unix://");
    write_file(&dir, "boundary_unix_only_scheme.txt", b"unix:");
    write_file(&dir, "boundary_whitespace.txt", b"   ");
    write_file(&dir, "boundary_null_byte.txt", b"host\0:22");
    write_file(&dir, "boundary_long.txt",
        format!("{}:443", "a".repeat(4096)).as_bytes());
    write_file(&dir, "boundary_many_colons.txt", b"a:b:c:d:e:f");
    write_file(&dir, "boundary_bom.txt",
        "\u{FEFF}127.0.0.1:80".as_bytes());
    write_file(&dir, "boundary_rtl_mark.txt",
        "host\u{200F}:22".as_bytes());

    println!("address_parse: corpus generated under {}", dir.display());
}
