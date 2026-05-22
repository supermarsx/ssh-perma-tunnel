//! Post-quantum hybrid KEX (`mlkem768x25519-sha256`) interop against
//! a live OpenSSH 9.9+ container.
//!
//! Gated by:
//! * `SPT_OPENSSH_INTEROP=1` — the standard interop harness opt-in,
//! * `SPT_PQ_INTEROP_LIVE=1`  — additional opt-in because the docker
//!   image must ship OpenSSH ≥ 9.9 (the first release with the
//!   `mlkem768x25519-sha256` IETF name). Older images will negotiate-
//!   fail and the test would be a flake. Default CI does not yet
//!   guarantee the bump; opt-in keeps the lane green.
//!
//! `#[ignore]` by default — run with:
//!     SPT_OPENSSH_INTEROP=1 SPT_PQ_INTEROP_LIVE=1 \
//!     cargo test -p openssh-interop --test pq_mlkem -- --ignored

use std::time::Duration;

use openssh_interop::{default_client_key, gated, spawn_echo_server, wait_for_port, SpawnedSpt};

/// Secondary gate specifically for live PQ-capable sshd images.
fn pq_live() -> bool {
    std::env::var("SPT_PQ_INTEROP_LIVE").ok().as_deref() == Some("1")
}

#[tokio::test]
#[ignore]
async fn mlkem768x25519_sha256_handshake() {
    if !gated() || !pq_live() {
        return;
    }

    let echo = spawn_echo_server().await.expect("echo server");
    let listen_port = pick_free_port().await;
    let key = default_client_key().to_string_lossy().replace('\\', "/");

    // Pin the KEX allow-list to the hybrid PQ algorithm only — if the
    // server doesn't speak it, negotiation fails immediately and the
    // test surfaces a clear error rather than silently downgrading.
    let cfg = format!(
        r#"
version = 1

[runtime]
state_dir = "${{STATE_DIR}}"
file_lock = false

[runtime.threads]
model = "multi_thread"

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
name = "interop-pq"
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

[profiles.crypto]
kex = ["mlkem768x25519-sha256"]

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
target = "{echo_host}:{echo_port}"
target_resolve = "local"
required = true
"#,
        echo_host = echo.ip(),
        echo_port = echo.port(),
    );

    let mut spt = SpawnedSpt::spawn_tunnel_run(&cfg)
        .await
        .expect("spawn spt tunnel run");

    let listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_port(listen_addr, Duration::from_secs(30))
        .await
        .expect(
            "forward listener never bound — mlkem768x25519-sha256 \
             handshake likely failed against the live sshd",
        );

    spt.shutdown().await;
}

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}
