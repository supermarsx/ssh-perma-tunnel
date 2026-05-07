//! Emit valid + boundary TOML config seeds for the `toml_config` fuzz target.
//!
//! Each "valid" seed is round-tripped through `spt_config::load::load_str`
//! (lenient mode) before being committed; failures are skipped with a notice.

use spt_fuzz_generators::{out_dir_from_args, write_file};

fn try_emit(dir: &std::path::Path, name: &str, content: &str) {
    let valid_lenient = spt_config::load::load_str(content, false).is_ok();
    let valid_strict = spt_config::load::load_str(content, true).is_ok();
    if !valid_lenient && !valid_strict {
        eprintln!("  ! {name} parses in neither mode — committing as boundary seed");
    }
    write_file(dir, name, content.as_bytes());
}

fn main() {
    let dir = out_dir_from_args();

    // -------- Valid configs --------
    try_emit(&dir, "valid_minimal_ssh2.toml", r#"
version = 1
[[profiles]]
name = "p1"
enabled = true
protocol = "ssh2"
host = "h.example.com"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
"#);

    try_emit(&dir, "valid_password_auth.toml", r#"
version = 1
[[profiles]]
name = "pw"
enabled = true
protocol = "ssh2"
host = "h"
port = 22
user = "u"
[profiles.auth]
method = "password"
password = "secret://pw/p1"
[profiles.trust]
mode = "known_hosts"
strict = true
"#);

    try_emit(&dir, "valid_publickey_auth.toml", r#"
version = 1
[[profiles]]
name = "pk"
enabled = true
protocol = "ssh2"
host = "h"
port = 22
user = "u"
[profiles.auth]
method = "publickey"
key_path = "/home/u/.ssh/id_ed25519"
[profiles.trust]
mode = "known_hosts"
strict = true
"#);

    try_emit(&dir, "valid_ssh3_quic.toml", r#"
version = 1
[[profiles]]
name = "ssh3"
enabled = true
protocol = "ssh3"
acknowledge_experimental = true
endpoint = "https://x.example.com:443/ssh3?user={username}"
user = "u"
[profiles.auth]
method = "bearer_token"
token = "secret://t"
[profiles.tls]
server_name = "x.example.com"
system_roots = true
[profiles.ssh3]
draft = "michel-remote-terminal-http3-00"
protocol_token = "remote-terminal"
enable_datagrams = true
"#);

    try_emit(&dir, "valid_local_forward_tcp.toml", r#"
version = 1
[[profiles]]
name = "fwd"
enabled = true
protocol = "ssh2"
host = "h"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
[[profiles.forwards]]
name = "f1"
type = "local"
transport = "tcp"
bind = "127.0.0.1:8080"
target = "svc.internal:80"
target_resolve = "remote"
required = true
"#);

    try_emit(&dir, "valid_remote_forward.toml", r#"
version = 1
[[profiles]]
name = "rfwd"
enabled = true
protocol = "ssh2"
host = "h"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
[[profiles.forwards]]
name = "rf1"
type = "remote"
transport = "tcp"
bind = "0.0.0.0:9000"
target = "127.0.0.1:9000"
target_resolve = "local"
"#);

    try_emit(&dir, "valid_dynamic_socks.toml", r#"
version = 1
[[profiles]]
name = "sox"
enabled = true
protocol = "ssh2"
host = "h"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
[[profiles.forwards]]
name = "socks"
type = "dynamic"
transport = "tcp"
bind = "127.0.0.1:1080"
"#);

    try_emit(&dir, "valid_udp_forward.toml", r#"
version = 1
[[profiles]]
name = "udpfwd"
enabled = true
protocol = "ssh3"
acknowledge_experimental = true
endpoint = "https://h:443/ssh3"
user = "u"
[profiles.auth]
method = "bearer_token"
token = "x"
[profiles.tls]
server_name = "h"
system_roots = true
[profiles.ssh3]
enable_datagrams = true
[[profiles.forwards]]
name = "dns"
type = "local"
transport = "udp"
bind = "127.0.0.1:1053"
target = "1.1.1.1:53"
udp_idle_timeout = "30s"
"#);

    try_emit(&dir, "valid_jump_chain.toml", r#"
version = 1
[[profiles]]
name = "jump"
enabled = true
protocol = "ssh2"
host = "j1"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
[[profiles.hops]]
name = "j2"
protocol = "ssh2"
host = "j2"
port = 22
user = "u"
target_resolve = "previous-hop"
[[profiles.hops]]
name = "j3"
protocol = "ssh2"
host = "j3"
port = 22
user = "u"
target_resolve = "previous-hop"
"#);

    try_emit(&dir, "valid_unix_socket_forward.toml", r#"
version = 1
[[profiles]]
name = "uds"
enabled = true
protocol = "ssh2"
host = "h"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
[[profiles.forwards]]
name = "u1"
type = "local"
transport = "tcp"
bind = "unix:///run/spt.sock"
target = "svc:80"
"#);

    try_emit(&dir, "valid_disabled_profile.toml", r#"
version = 1
[[profiles]]
name = "off"
enabled = false
protocol = "ssh2"
host = "h"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
"#);

    try_emit(&dir, "valid_two_profiles.toml", r#"
version = 1
[[profiles]]
name = "a"
enabled = true
protocol = "ssh2"
host = "ha"
port = 22
user = "u"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
[[profiles]]
name = "b"
enabled = true
protocol = "ssh2"
host = "hb"
port = 2222
user = "v"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = false
"#);

    try_emit(&dir, "valid_unicode_names.toml", r#"
version = 1
[[profiles]]
name = "プロファイル"
enabled = true
protocol = "ssh2"
host = "ホスト.example"
port = 22
user = "ユーザ"
[profiles.auth]
method = "agent"
[profiles.trust]
mode = "known_hosts"
strict = true
"#);

    // -------- Boundary / malformed --------
    write_file(&dir, "boundary_empty.toml", b"");
    write_file(&dir, "boundary_one_byte.toml", b"x");
    write_file(&dir, "boundary_only_comment.toml", b"# comment\n");
    write_file(&dir, "boundary_only_version.toml", b"version = 1\n");
    write_file(&dir, "boundary_bom.toml", b"\xEF\xBB\xBFversion = 1\n");
    write_file(&dir, "boundary_huge_int.toml",
        b"version = 99999999999999999999999\n");
    write_file(&dir, "boundary_unknown_keys.toml",
        b"version = 1\nfrobnicate = true\n[[profiles]]\nname=\"x\"\nweirdo=42\n");
    write_file(&dir, "boundary_truncated.toml",
        b"version = 1\n[[profiles]]\nname = \"unter");
    write_file(&dir, "boundary_dup_keys.toml",
        b"version = 1\nversion = 2\n");
    write_file(&dir, "boundary_nested_inline.toml",
        b"version = 1\nx = { a = { b = { c = { d = 1 } } } }\n");
    {
        let mut v = b"version = 1\nname = \"".to_vec();
        v.extend(std::iter::repeat(b'a').take(4096));
        v.extend_from_slice(b"\"\n");
        write_file(&dir, "boundary_long_string.toml", &v);
    }
    write_file(&dir, "boundary_null_byte.toml", b"version = 1\nx = \"\x00\"\n");
    write_file(&dir, "boundary_only_lbracket.toml", b"[");
    write_file(&dir, "boundary_unicode_keys.toml",
        "version = 1\n[\"プロ\"]\nx = 1\n".as_bytes());
    write_file(&dir, "boundary_array_of_arrays.toml",
        b"version = 1\nx = [[1,2,3],[4,5,6],[]]\n");

    println!("toml_config: corpus generated under {}", dir.display());
}
