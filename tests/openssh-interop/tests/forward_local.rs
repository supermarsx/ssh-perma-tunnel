//! Local-forward 1 MiB roundtrip.
//!
//! Topology:
//!
//! ```text
//!   test process ── TCP ──> 127.0.0.1:LISTEN_PORT (spt local-forward)
//!                                        │
//!                            SSH channel │
//!                                        ▼
//!                             container resolves to host echo server
//! ```
//!
//! The forward target is set to `host.docker.internal:<echo_port>` if
//! that resolves; otherwise we use the host gateway IP via the
//! `HOST_GATEWAY` env var (CI sets this). For the default Docker
//! Desktop / Linux bridge case the helper falls back to
//! `172.17.0.1` which is the conventional bridge gateway.

use std::time::Duration;

use openssh_interop::{
    default_client_key, gated, host_gateway, roundtrip, spawn_echo_server, wait_for_port,
    SpawnedSpt,
};

#[tokio::test]
#[ignore]
async fn local_forward_one_mib_roundtrip() {
    if !gated() {
        return;
    }

    let echo = spawn_echo_server().await.expect("echo");
    let listen_port = pick_free_port().await;
    let host_gw = host_gateway();

    let key = default_client_key().to_string_lossy().replace('\\', "/");

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
name = "fwd-local"
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
name = "echo"
type = "local"
transport = "tcp"
bind = "127.0.0.1:{listen_port}"
target = "{host_gw}:{ep}"
target_resolve = "remote"
required = true
"#,
        ep = echo.port(),
    );

    let mut spt = SpawnedSpt::spawn_tunnel_run(&cfg).await.expect("spawn");

    let listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_port(listen_addr, Duration::from_secs(30))
        .await
        .expect("forward bind");

    // 1 MiB pseudo-random payload (deterministic seed for reproducibility).
    let payload = make_payload(1024 * 1024, 0xA5);
    roundtrip(listen_addr, &payload)
        .await
        .expect("1 MiB roundtrip");

    spt.shutdown().await;
}

fn make_payload(len: usize, seed: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = seed;
    for _ in 0..len {
        // xorshift8-ish; we don't need cryptographic quality, just
        // non-trivial repeating content.
        x = x.wrapping_mul(31).wrapping_add(7);
        v.push(x);
    }
    v
}

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}
