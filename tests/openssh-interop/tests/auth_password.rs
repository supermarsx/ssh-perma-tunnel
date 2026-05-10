//! Password authentication against the ED25519-host container, which
//! advertises `PASSWORD_ACCESS=true` and `USER_PASSWORD=interop-pw`.
//!
//! Uses the `secret://env/...` indirection: the literal password lives
//! in `SPT_SECRET_SSH__INTEROP_PW` so it never appears in the rendered
//! config nor in `ps`/`/proc/<pid>/cmdline`.

use std::time::Duration;

use openssh_interop::{gated, spawn_echo_server, wait_for_port, SpawnedSpt};

#[tokio::test]
#[ignore]
async fn password_auth_handshake_succeeds() {
    if !gated() {
        return;
    }

    // Push the password into the env-secrets backend before spawning the
    // child — `tokio::process::Command` inherits the parent env unless
    // `env_clear()` is called.
    std::env::set_var("SPT_SECRET_SSH__INTEROP_PW", "interop-pw");

    let echo = spawn_echo_server().await.expect("echo server");
    let listen_port = pick_free_port().await;

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
name = "interop-pw"
enabled = true
protocol = "ssh2"
host = "127.0.0.1"
port = 2222
user = "interop"
startup = "eager"

[profiles.auth]
method = "password"
password = "secret://env/ssh/interop_pw"

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

    let mut spt = SpawnedSpt::spawn_tunnel_run(&cfg)
        .await
        .expect("spawn spt tunnel run");

    let listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    wait_for_port(listen_addr, Duration::from_secs(30))
        .await
        .expect("forward listener never bound — password auth likely failed");

    spt.shutdown().await;
}

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}
