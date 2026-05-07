//! Emit strings for the `redaction` fuzz target — secrets in various
//! positions, plus IP/email/PEM/structural inputs.

use spt_core::redaction::{redact, RedactionMode};
use spt_fuzz_generators::{out_dir_from_args, write_file};

fn try_emit(dir: &std::path::Path, name: &str, s: &str) {
    // The fuzz target only checks for panics; a "valid" seed for redact is
    // anything well-formed UTF-8. Sanity-call all three modes here so a
    // future change that panics from a generator-shaped input is caught.
    let _ = redact(s, RedactionMode::None);
    let _ = redact(s, RedactionMode::Standard);
    let _ = redact(s, RedactionMode::Strict);
    write_file(dir, name, s.as_bytes());
}

fn main() {
    let dir = out_dir_from_args();

    // Bearer / Basic
    try_emit(&dir, "valid_bearer.txt",
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig");
    try_emit(&dir, "valid_basic.txt",
        "Authorization: Basic dXNlcjpwYXNz");
    try_emit(&dir, "valid_bearer_lower.txt",
        "authorization: bearer abc.def.ghi");
    try_emit(&dir, "valid_bearer_in_url.txt",
        "GET /x HTTP/1.1\nAuthorization: Bearer xxx-yyy-zzz_aaa\n");

    // KV secrets
    try_emit(&dir, "valid_password_quoted.txt",
        r#"password = "hunter2""#);
    try_emit(&dir, "valid_password_single.txt",
        "password = 'hunter2'");
    try_emit(&dir, "valid_password_bare.txt",
        "password=hunter2 next=ok");
    try_emit(&dir, "valid_apikey.txt", "api_key = sk_live_abc123");
    try_emit(&dir, "valid_token.txt", "token: tk-xxxxxxxxxxx");
    try_emit(&dir, "valid_passphrase.txt",
        r#"passphrase = "correct horse battery staple""#);
    try_emit(&dir, "valid_secret.txt", "secret=topsecret");
    try_emit(&dir, "valid_key_eq.txt", "key=do-not-share");

    // PEM private keys
    try_emit(&dir, "valid_pem_rsa.txt",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEvQ\n-----END RSA PRIVATE KEY-----");
    try_emit(&dir, "valid_pem_openssh.txt",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAA==\n-----END OPENSSH PRIVATE KEY-----");
    try_emit(&dir, "valid_pem_encrypted.txt",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIB\n-----END ENCRYPTED PRIVATE KEY-----");

    // IPv4/IPv6/email (Strict mode)
    try_emit(&dir, "valid_ipv4.txt", "client connected from 192.168.1.42");
    try_emit(&dir, "valid_ipv6.txt", "src=2001:db8::1 dst=fe80::1");
    try_emit(&dir, "valid_email.txt", "user@example.com sent it");
    try_emit(&dir, "valid_mixed.txt",
        "User user@example.com from 10.0.0.5 used token=abc");

    // Plain (no secrets)
    try_emit(&dir, "valid_plain_short.txt", "hello world");
    try_emit(&dir, "valid_plain_long.txt", &"lorem ipsum ".repeat(64));

    // Catastrophic-regex hunting fodder
    try_emit(&dir, "valid_repeating_bearer.txt",
        &"Bearer ".repeat(100));
    try_emit(&dir, "valid_long_pem_body.txt", &format!(
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        "A".repeat(4096)
    ));
    try_emit(&dir, "valid_many_kv.txt",
        &"password=x ".repeat(50));

    // Unicode / boundary
    try_emit(&dir, "valid_unicode_password.txt",
        "password=パスワード");
    try_emit(&dir, "valid_rtl.txt",
        "password=\u{202E}reversed\u{202C}");
    write_file(&dir, "boundary_empty.txt", b"");
    write_file(&dir, "boundary_one_byte.txt", b"a");
    write_file(&dir, "boundary_null.txt", b"a\0b");
    write_file(&dir, "boundary_only_bom.txt", "\u{FEFF}".as_bytes());
    write_file(&dir, "boundary_pem_unmatched_begin.txt",
        b"-----BEGIN PRIVATE KEY-----\nno end marker\n");
    write_file(&dir, "boundary_pem_unmatched_end.txt",
        b"only -----END PRIVATE KEY----- here\n");
    write_file(&dir, "boundary_long_input.txt",
        "x".repeat(8192).as_bytes());

    println!("redaction: corpus generated under {}", dir.display());
}
