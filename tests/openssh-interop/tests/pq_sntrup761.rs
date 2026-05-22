//! Post-quantum hybrid KEX (`sntrup761x25519-sha512[@openssh.com]`)
//! interop against a live OpenSSH 9.9+ container.
//!
//! Gated by:
//! * `SPT_OPENSSH_INTEROP=1` — the standard interop harness opt-in,
//! * `SPT_PQ_INTEROP_LIVE=1`  — additional opt-in because the docker
//!   image must ship OpenSSH ≥ 9.9 (sntrup761x25519 has shipped since
//!   OpenSSH 8.0 as the `@openssh.com`-suffixed form, but the
//!   un-suffixed IETF name only became standard in 9.9).
//!
//! ## Status — SKELETON (will not pass until the KEM primitive lands)
//!
//! The russh-fork side of this algorithm is currently skeleton-only —
//! `vendor/russh-fork/russh/src/kex/sntrup761.rs` registers the algorithm
//! name in the negotiation table but every `KexAlgorithm` method returns
//! `russh::Error::Kex` because the sntrup761 KEM primitive is not yet
//! wired (operator-decision pending — see the module doc-comment and
//! `.orchestration/logs/t8-B2.md`).
//!
//! This test file is included in the build so the interop harness keeps
//! compiling, and the `#[ignore]` plus double-gating keeps it from
//! flapping CI today. When the KEM lands, drop the doc-comment caveat
//! and remove the `pending_kem_wire_up` early-return; everything else
//! is wired and ready.
//!
//! `#[ignore]` by default — run with:
//!     SPT_OPENSSH_INTEROP=1 SPT_PQ_INTEROP_LIVE=1 \
//!     cargo test -p openssh-interop --test pq_sntrup761 -- --ignored

use std::time::Duration;

use openssh_interop::{default_client_key, gated, spawn_echo_server, wait_for_port, SpawnedSpt};

/// Secondary gate specifically for live PQ-capable sshd images.
fn pq_live() -> bool {
    std::env::var("SPT_PQ_INTEROP_LIVE").ok().as_deref() == Some("1")
}

/// Tertiary gate held *closed* until the sntrup761 KEM primitive lands
/// in the russh fork. Today this always returns true (= "still pending"),
/// causing the test to exit cleanly without spawning sshd. Flip to
/// `false` (or delete the gate entirely) once the KEM is wired and the
/// negotiation can actually complete.
fn pending_kem_wire_up() -> bool {
    true
}

#[tokio::test]
#[ignore]
async fn sntrup761x25519_sha512_handshake() {
    if !gated() || !pq_live() || pending_kem_wire_up() {
        return;
    }

    let echo = spawn_echo_server().await.expect("echo server");
    let listen_port = pick_free_port().await;
    let key = default_client_key().to_string_lossy().replace('\\', "/");

    // Pin the KEX allow-list to the canonical IETF name. The russh
    // fork registers both `sntrup761x25519-sha512` and the legacy
    // `@openssh.com`-suffixed alias; OpenSSH 9.9 advertises both, so
    // either pin should land on the same KexType.
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
name = "interop-pq-sntrup"
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
kex = ["sntrup761x25519-sha512"]

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
            "forward listener never bound — sntrup761x25519-sha512 \
             handshake likely failed against the live sshd",
        );

    spt.shutdown().await;
}

async fn pick_free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}
