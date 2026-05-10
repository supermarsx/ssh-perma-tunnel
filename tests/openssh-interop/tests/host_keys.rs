//! Host-key algorithm coverage: connect to both sshd containers, one
//! with an ED25519 host key (port 2222), one with an RSA host key
//! (port 2223). Each is a separate `#[tokio::test]` so a failure on
//! one side doesn't mask the other.

use std::time::Duration;

use openssh_interop::{fixtures_dir, gated, spawn_echo_server, wait_for_port, SpawnedSpt};

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

async fn run_with_host_key(port: u16, key_basename: &str) {
    let echo = spawn_echo_server().await.expect("echo");
    let listen_port = pick_free_port().await;
    let key = fixtures_dir()
        .join("keys")
        .join(key_basename)
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
name = "hostkey-{port}"
enabled = true
protocol = "ssh2"
host = "127.0.0.1"
port = {port}
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
target = "{eh}:{ep}"
target_resolve = "local"
required = true
"#,
        eh = echo.ip(),
        ep = echo.port(),
    );

    let mut spt = SpawnedSpt::spawn_tunnel_run(&cfg).await.expect("spawn");
    let listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_port(listen_addr, Duration::from_secs(30))
        .await
        .expect("forward bind");
    spt.shutdown().await;
}

#[tokio::test]
#[ignore]
async fn ed25519_host_key_accepted() {
    if !gated() {
        return;
    }
    run_with_host_key(2222, "test_ed25519").await;
}

#[tokio::test]
#[ignore]
async fn rsa_host_key_accepted() {
    if !gated() {
        return;
    }
    run_with_host_key(2223, "test_rsa").await;
}
