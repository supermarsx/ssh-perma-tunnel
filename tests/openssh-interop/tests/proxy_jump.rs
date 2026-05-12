//! Multi-hop ProxyJump: client → sshd-ed25519 → sshd-rsa.
//!
//! The profile endpoint is the final SSH server (`sshd-rsa`) and
//! `[[profiles.hops]]` contains the jump server (`sshd-ed25519`). The final
//! hostname is resolved by the jump server on the Docker interop network.
//!
//! The forward target on the *final* hop points at the host echo
//! server via the docker bridge gateway.

use std::time::Duration;

use openssh_interop::{
    default_client_key, fixtures_dir, gated, host_gateway, roundtrip, spawn_echo_server,
    wait_for_port, SpawnedSpt,
};

#[tokio::test]
#[ignore]
async fn two_hop_proxy_jump_local_forward() {
    if !gated() {
        return;
    }

    let echo = spawn_echo_server().await.expect("echo");
    let listen_port = pick_free_port().await;
    let host_gw = host_gateway();
    let hop_key = default_client_key().to_string_lossy().replace('\\', "/");
    let rsa_key = fixtures_dir()
        .join("keys/test_rsa")
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
name = "proxy-jump"
enabled = true
protocol = "ssh2"
host = "sshd-rsa"
port = 2222
user = "interop"
startup = "eager"

[profiles.auth]
method = "public_key"
identity_file = "{rsa_key}"

[profiles.trust]
mode = "known_hosts"
strict = false
accept_new = true

[profiles.reconnect]
initial_delay = "200ms"
max_delay = "1s"
jitter = "0%"
max_attempts = 3

[[profiles.hops]]
name = "ed25519"
protocol = "ssh2"
host = "127.0.0.1"
port = 2222
user = "interop"
target_resolve = "previous-hop"

[profiles.hops.auth]
method = "public_key"
identity_file = "{hop_key}"

[profiles.hops.trust]
mode = "known_hosts"
strict = false
accept_new = true

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
    wait_for_port(listen_addr, Duration::from_secs(45))
        .await
        .expect("forward bind — two-hop chain should establish");

    roundtrip(listen_addr, b"hello-via-two-hops")
        .await
        .expect("roundtrip across the chain");

    spt.shutdown().await;
}

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}
