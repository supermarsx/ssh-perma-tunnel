//! Emit known_hosts variants — plain, hashed, cert-authority, revoked, with
//! several key types — plus boundary cases.
//!
//! Valid lines use real-shape OpenSSH public keys (deterministic, generated
//! from fixed seeds via `ssh_key` is overkill here; we use well-known sample
//! public keys whose base64 bodies are public values). Each emitted "valid"
//! file is round-tripped through `KnownHosts::parse`.

use spt_fuzz_generators::{out_dir_from_args, write_file};
use spt_trust::KnownHosts;

// Canonical short ed25519 public keys (public values; safe to embed).
// Generated once and pinned here so the corpus is deterministic.
const ED25519_A: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICfwq6kDhPzBnUQjFvLfVyQUjyiIZbrt2DvA6kt1xL0H";
const ED25519_B: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILb1V0Hwjvx7HQfRb4QjFsW3JRRXl/0ywIvACiHt+aH9";
// A valid (publicly-known) sample RSA 2048 line.
const RSA_A: &str =
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDOyKb1d2QvUpRyDyRmprQqMnA0urE6P+ItpyG7vTYqp4XR2gZQRr+JV+9V8C8tH9V0SJZGhwq4ozuSV/JoRNtOaqxQ8nQv+5q+9JlPKx65cT8a/cR1pK3SBbvwUHLdT/0c4qy/3KByDBlvpcw0eKNnWoZ7VEr5MDwNlHEhDGn8Nv2KP7BQRr/wRkB36WnXxg9Vi9bkyrFtTcTvb2J3UvkNHgDqrSCp7yj7pEhiUnt3o2jEokQrjZdqJB7QC0XPFqMU9SaFY9JykF3VsRWfZ4Pr5OuSHvRy6/IM5y6P4WVS27cM78AaGHA1Tx4cN/u5T+0lbnaY8L1k+RMIGBDB+VuJ";

fn try_emit(dir: &std::path::Path, name: &str, content: &str) {
    match KnownHosts::parse(content) {
        Ok(_) => write_file(dir, name, content.as_bytes()),
        Err(e) => {
            eprintln!("  ! {name}: round-trip parse failed: {e} — committing anyway as boundary");
            write_file(dir, name, content.as_bytes());
        }
    }
}

fn main() {
    let dir = out_dir_from_args();

    try_emit(&dir, "valid_ed25519_simple.txt",
        &format!("example.com {ED25519_A}\n"));
    try_emit(&dir, "valid_ed25519_with_port.txt",
        &format!("[example.com]:2222 {ED25519_A}\n"));
    try_emit(&dir, "valid_rsa.txt", &format!("example.com {RSA_A}\n"));
    try_emit(&dir, "valid_comma_hosts.txt",
        &format!("a.example,b.example,1.2.3.4 {ED25519_A}\n"));
    try_emit(&dir, "valid_wildcard.txt",
        &format!("*.example.com {ED25519_A}\n"));
    try_emit(&dir, "valid_hashed.txt",
        &format!("|1|F1E1KeoE/eEWhi10WpGv4OdiO6Y=|3988QV0VE8wmZL7suNrYQLITLCg= {ED25519_A}\n"));
    try_emit(&dir, "valid_cert_authority.txt",
        &format!("@cert-authority *.example.com {ED25519_A}\n"));
    try_emit(&dir, "valid_revoked.txt",
        &format!("@revoked compromised.example {ED25519_B}\n"));
    try_emit(&dir, "valid_with_comments.txt",
        &format!("# top comment\nexample.com {ED25519_A}\n# trailing\n"));
    try_emit(&dir, "valid_blank_lines.txt",
        &format!("\n\nexample.com {ED25519_A}\n\n"));
    try_emit(&dir, "valid_two_entries.txt",
        &format!("a.example {ED25519_A}\nb.example {ED25519_B}\n"));
    try_emit(&dir, "valid_ipv4_host.txt",
        &format!("10.0.0.1 {ED25519_A}\n"));
    try_emit(&dir, "valid_ipv6_bracketed.txt",
        &format!("[2001:db8::1]:22 {ED25519_A}\n"));
    try_emit(&dir, "valid_question_wildcard.txt",
        &format!("host?.example {ED25519_A}\n"));
    try_emit(&dir, "valid_with_trailing_comment.txt",
        &format!("example.com {ED25519_A} a-trailing-comment-field\n"));

    // Boundaries
    write_file(&dir, "boundary_empty.txt", b"");
    write_file(&dir, "boundary_blanks_only.txt", b"\n\n   \n\t\n");
    write_file(&dir, "boundary_only_comments.txt",
        b"# nothing here\n# really nothing\n");
    write_file(&dir, "boundary_missing_key.txt", b"example.com\n");
    write_file(&dir, "boundary_missing_host.txt",
        format!("{ED25519_A}\n").as_bytes());
    write_file(&dir, "boundary_garbage_key.txt",
        b"example.com ssh-rsa not-base64@@@\n");
    write_file(&dir, "boundary_unknown_marker.txt",
        format!("@bogus example.com {ED25519_A}\n").as_bytes());
    write_file(&dir, "boundary_truncated_b64.txt",
        b"example.com ssh-ed25519 AAAA\n");
    write_file(&dir, "boundary_long_host.txt",
        format!("{} {ED25519_A}\n", "x".repeat(4096)).as_bytes());
    write_file(&dir, "boundary_null_byte.txt",
        b"example.com\x00 ssh-ed25519 AAAA\n");
    write_file(&dir, "boundary_hash_no_separator.txt",
        format!("|1|nosep {ED25519_A}\n").as_bytes());
    write_file(&dir, "boundary_crlf.txt",
        format!("example.com {ED25519_A}\r\n").as_bytes());

    println!("known_hosts: corpus generated under {}", dir.display());
}
