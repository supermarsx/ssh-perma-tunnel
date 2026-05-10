//! Remote-forward 1 MiB roundtrip.
//!
//! Topology:
//!
//! ```text
//!   container client ── TCP ──> sshd-ed25519:REMOTE_PORT
//!                                            │ remote-forward
//!                                            ▼
//!                                test process echo server (on host)
//! ```
//!
//! We can't easily "be a client inside the container" without exec-ing
//! into it, so the assertion is two-step:
//!
//! 1. Bring up `spt` with a remote-forward that listens on
//!    `0.0.0.0:REMOTE_PORT` inside the sshd container.
//! 2. Use `docker exec sshd-ed25519 sh -c 'cat </dev/tcp/127.0.0.1/REMOTE_PORT'`
//!    style probe via `nc` (preinstalled in the image).
//!
//! The 1 MiB roundtrip is driven by a `docker exec` command pipe.

use std::process::Stdio;
use std::time::Duration;

use openssh_interop::{fixtures_dir, gated, spawn_echo_server, SpawnedSpt};
use tokio::process::Command;
use tokio::time::sleep;

#[tokio::test]
#[ignore]
async fn remote_forward_one_mib_roundtrip() {
    if !gated() {
        return;
    }

    let echo = spawn_echo_server().await.expect("echo");
    let host_gw = std::env::var("SPT_HOST_GATEWAY").unwrap_or_else(|_| "172.17.0.1".to_string());
    let remote_port = 18_000_u16; // arbitrary, container-internal only.

    let key = fixtures_dir()
        .join("keys/test_ed25519")
        .to_string_lossy()
        .replace('\\', "/");

    let cfg = format!(
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
name = "fwd-remote"
enabled = true
protocol = "ssh2"
host = "127.0.0.1"
port = 2222
user = "interop"
startup = "eager"

[profiles.auth]
method = "public_key"
identity_file = "{key}"

[profiles.trust]
mode = "known_hosts"
strict = false
accept_new = true

[profiles.reconnect]
initial_delay = "200ms"
max_delay = "1s"
jitter = "0%"
max_attempts = 3

[[profiles.forwards]]
name = "rev"
type = "remote"
transport = "tcp"
bind = "0.0.0.0:{remote_port}"
target = "{host_gw}:{ep}"
target_resolve = "local"
required = true
"#,
        ep = echo.port(),
    );

    let mut spt = SpawnedSpt::spawn_tunnel_run(&cfg).await.expect("spawn");

    // Give the remote-forward request time to be accepted by sshd. We
    // can't poll-connect from the host (the listener is inside the
    // container), so a brief sleep is the simplest cross-platform thing.
    sleep(Duration::from_secs(5)).await;

    // Drive the 1 MiB roundtrip from inside the container with `nc`.
    // Image is alpine-based; busybox nc is present.
    let payload_hex = hex_megabyte(0x42);
    let child = Command::new("docker")
        .args([
            "exec",
            "-i",
            "spt-interop-sshd-ed25519",
            "sh",
            "-c",
            &format!(
                "head -c $((1024*1024)) /dev/zero | nc -w 5 127.0.0.1 {remote_port} | wc -c"
            ),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("docker exec");

    let out = child.wait_with_output().await.expect("docker exec wait");
    let _ = payload_hex; // payload variant not needed; nc + zero stream suffices.
    let received = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(
        received,
        format!("{}", 1024 * 1024),
        "echoed byte count mismatch (got `{received}`); status={:?} -- remote-forward roundtrip failed",
        out.status.code()
    );

    spt.shutdown().await;
}

/// Produce a 1 MiB hex payload (kept around in case the nc-zero variant
/// proves flaky and we want to substitute a known-pattern stream).
fn hex_megabyte(byte: u8) -> Vec<u8> {
    vec![byte; 1024 * 1024]
}
