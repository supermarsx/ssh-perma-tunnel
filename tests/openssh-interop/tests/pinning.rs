//! Host-key pinning: success and failure.
//!
//! * Success: read the actual ED25519 host-key fingerprint via
//!   `ssh-keygen -lf`, configure it as the only `pin_sha256`, assert
//!   the forward comes up.
//!
//! * Failure: configure a syntactically valid but wrong fingerprint;
//!   assert `spt` exits non-zero with stderr mentioning `pin` or
//!   `host key` (we deliberately accept either substring rather than
//!   pinning to an exact diagnostic, since the wording belongs to the
//!   error layer).

use std::time::Duration;

use openssh_interop::{
    default_client_key, fingerprint_sha256, fixtures_dir, gated, run_once, spawn_echo_server,
    wait_for_port, SpawnedSpt,
};

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn cfg(listen_port: u16, echo_port: u16, pin: &str, key: &str) -> String {
    let host_key_algorithms = pinned_host_key_algorithms();
    format!(
        r#"
version = 1

[runtime]
state_dir = "${{STATE_DIR}}"
file_lock = false

[secrets]
backend = "env"

[logging]
level = "info"
format = "json"
destinations = ["stderr"]

[dns]
enabled = false
mode = "disabled"

[firewall]
enabled = false

[mcp]
enabled = false

[[profiles]]
name = "pin"
enabled = true
protocol = "ssh2"
host = "127.0.0.1"
port = 2222
user = "interop"
startup = "eager"

[profiles.auth]
method = "public_key"
identity_file = "{key}"

[profiles.crypto]
host_key_algorithms = {host_key_algorithms}

[profiles.trust]
mode = "pinned"
strict = true
pin_sha256 = ["{pin}"]

[profiles.reconnect]
initial_delay = "200ms"
max_delay = "1s"
jitter = "0%"
max_attempts = 1
retry_auth_failures = false

[[profiles.forwards]]
name = "echo"
type = "local"
transport = "tcp"
bind = "127.0.0.1:{listen_port}"
target = "127.0.0.1:{echo_port}"
target_resolve = "local"
required = true
"#
    )
}

fn pinned_host_key_algorithms() -> &'static str {
    if cfg!(windows) {
        r#"["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]"#
    } else {
        r#"["ssh-ed25519"]"#
    }
}

fn pinned_host_key_fixture() -> &'static str {
    if cfg!(windows) {
        "host_keys/ssh_host_rsa_key.pub"
    } else {
        "host_keys/ssh_host_ed25519_key.pub"
    }
}

#[tokio::test]
#[ignore]
async fn pin_correct_fingerprint_accepted() {
    if !gated() {
        return;
    }

    let echo = spawn_echo_server().await.expect("echo");
    let listen_port = pick_free_port().await;
    let key = default_client_key().to_string_lossy().replace('\\', "/");
    let pin = fingerprint_sha256(&fixtures_dir().join(pinned_host_key_fixture()))
        .await
        .expect("read fingerprint");

    let body = cfg(listen_port, echo.port(), &pin, &key);
    let mut spt = SpawnedSpt::spawn_tunnel_run(&body).await.expect("spawn");

    let listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_port(listen_addr, Duration::from_secs(30))
        .await
        .expect("forward bind — pin should have been accepted");

    spt.shutdown().await;
}

#[tokio::test]
#[ignore]
async fn pin_wrong_fingerprint_rejected() {
    if !gated() {
        return;
    }

    // Validate failure via `spt config validate` first — wrong-pin
    // string still has to parse. Then run `tunnel run --once` so the
    // process exits on its own (rather than supervising forever) and we
    // can inspect the exit code + stderr.
    let echo = spawn_echo_server().await.expect("echo");
    let listen_port = pick_free_port().await;
    let key = default_client_key().to_string_lossy().replace('\\', "/");
    // Valid SHA256 shape, deliberately wrong content.
    let bad_pin = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let body = cfg(listen_port, echo.port(), bad_pin, &key);
    let tmp = tempfile::tempdir().expect("tempdir");
    let state = tmp.path().join("state");
    std::fs::create_dir_all(&state).unwrap();
    let body = body.replace("${STATE_DIR}", &state.to_string_lossy().replace('\\', "/"));
    let cfg_path = tmp.path().join("spt.toml");
    std::fs::write(&cfg_path, &body).unwrap();

    let out = run_once(
        Some(&cfg_path),
        &["tunnel", "run", "--foreground", "--once"],
    )
    .await
    .expect("run spt tunnel run --once");

    assert_ne!(
        out.status,
        Some(0),
        "spt should exit non-zero on pin mismatch; stdout=`{}` stderr=`{}`",
        out.stdout,
        out.stderr
    );
    let combined = format!("{}\n{}", out.stdout, out.stderr).to_lowercase();
    assert!(
        combined.contains("pin")
            || combined.contains("host key")
            || combined.contains("hostkey")
            || combined.contains("trust")
            || combined.contains("fingerprint"),
        "expected stderr to mention pin/host-key/trust; got stdout=`{}` stderr=`{}`",
        out.stdout,
        out.stderr
    );
}
