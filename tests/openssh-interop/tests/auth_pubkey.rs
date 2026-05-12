//! Public-key authentication against the ED25519-host openssh-server
//! container.
//!
//! Boots `spt tunnel run --foreground` with a profile pointing at the
//! `sshd-ed25519` container (port 2222), authed with the test ED25519
//! client key. Asserts the local-forward listener comes up — which is
//! only possible after a successful SSH session.
//!
//! Gated on `SPT_OPENSSH_INTEROP=1` and `#[ignore]`d by default.

use std::time::Duration;

use openssh_interop::{default_client_key, gated, spawn_echo_server, wait_for_port, SpawnedSpt};

#[tokio::test]
#[ignore]
async fn pubkey_ed25519_local_forward_handshake() {
    if !gated() {
        return;
    }

    // Echo server stands in for an "internal" target the forward points to.
    let echo = spawn_echo_server().await.expect("echo server");
    let listen_port = pick_free_port().await;

    let key = default_client_key().to_string_lossy().replace('\\', "/");

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
name = "interop"
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

    // Forward listener bind is the first observable side effect of a
    // successful SSH handshake + channel open.
    let listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_port(listen_addr, Duration::from_secs(30))
        .await
        .expect("forward listener never bound — handshake likely failed");

    spt.shutdown().await;
}

/// Bind a fresh ephemeral port, drop the listener, return the port.
/// Race-prone in the abstract but fine for the test stack: the
/// supervisor binds within a few hundred ms and the test runs serial
/// per-file.
async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}
