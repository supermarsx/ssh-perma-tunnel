//! Gated interop test against the upstream `francoismichel/ssh3` Go reference
//! server.
//!
//! # When this test runs
//!
//! Both env vars must be set:
//!
//! * `SPT_SSH3_TEST_SERVER` — `host:port` of a running upstream server (e.g.
//!   `ssh3.example.com:443`).
//! * `SPT_SSH3_TEST_USER` — the username to authenticate as.
//!
//! Optional env vars:
//!
//! * `SPT_SSH3_TEST_URL_PATH` — Extended-CONNECT `:path` (defaults to
//!   `/ssh3-term`, the upstream default).
//! * `SPT_SSH3_TEST_BEARER` — if set, used as a `Bearer` token for the
//!   `Authorization` header (skips the pubkey-JWT path).
//! * `SPT_SSH3_TEST_IDENTITY_FILE` — path to an OpenSSH private key registered
//!   with the upstream server's `authorized_identities`. Required for the
//!   pubkey-JWT branch when `SPT_SSH3_TEST_BEARER` is unset.
//! * `SPT_SSH3_TEST_IDENTITY_PASSPHRASE` — passphrase for the key, if any.
//! * `SPT_SSH3_TEST_ALLOW_SELF_SIGNED` — `1`/`true` to disable cert validation
//!   (lab use only). Otherwise system roots + optional CA bundle apply.
//! * `SPT_SSH3_TEST_CA_FILE` — path to a PEM CA bundle replacing system roots.
//! * `SPT_SSH3_TEST_ECHO_TARGET` — `host:port` of an echo server reachable from
//!   the upstream SSH3 server (defaults to `127.0.0.1:7`). The forward-target
//!   semantics match `ssh -L LPORT:host:port` so the upstream box must be able
//!   to connect to this target.
//!
//! # Why gated
//!
//! The upstream reference is a heavy Go binary that we will not stand up in
//! CI. When the env vars are unset, the test prints a notice via `eprintln!`
//! and returns successfully — by design, this test never fails the default
//! `cargo test` run.
//!
//! # Coverage
//!
//! When enabled the test exercises:
//!
//! 1. QUIC + rustls + HTTP/3 Extended CONNECT bootstrap against the upstream
//!    server (validates the `:method`/`:authority`/`:path` + custom
//!    `X-Ssh3-Protocol` header path documented in `transport.rs`).
//! 2. Pubkey-JWT auth handshake (Ed25519 / ECDSA via the existing
//!    `auth_header.rs` PublicKey branch) **or** Bearer-token auth, selected by
//!    env-var presence.
//! 3. TCP local-forward open + 64 KiB random-payload echo round-trip.
//! 4. Channel close on drop + clean session shutdown.

#![cfg(not(miri))]
#![allow(
    clippy::needless_pass_by_value,
    clippy::manual_let_else,
    clippy::ignored_unit_patterns,
    clippy::doc_markdown,
    clippy::match_wild_err_arm,
    clippy::used_underscore_binding
)]

use std::env;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_core::BindAddr;
use spt_protocol::endpoint::TargetAddr;
use spt_protocol::forward::{BindConflictPolicy, ForwardRateLimits, LocalForwardSpec};
use spt_protocol::session::TunnelSession;
use spt_ssh3::{Ssh3Config, Ssh3Session, Ssh3TlsConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SKIP_NOTICE: &str =
    "interop_reference: SPT_SSH3_TEST_SERVER and SPT_SSH3_TEST_USER not both set — \
     skipping upstream francoismichel/ssh3 interop test (this is the default).";

/// Shape of the interop input read from env vars.
struct InteropEnv {
    host: String,
    port: u16,
    user: String,
    url_path: String,
    bearer: Option<String>,
    identity_file: Option<PathBuf>,
    identity_passphrase: Option<SecretRef>,
    allow_self_signed: bool,
    ca_file: Option<PathBuf>,
    echo_target: SocketAddr,
}

fn parse_env() -> Option<InteropEnv> {
    let server = env::var("SPT_SSH3_TEST_SERVER").ok()?;
    let user = env::var("SPT_SSH3_TEST_USER").ok()?;
    let (host, port_s) = match server.rsplit_once(':') {
        Some(v) => v,
        None => {
            eprintln!(
                "interop_reference: SPT_SSH3_TEST_SERVER must be `host:port`, got `{server}` — skipping"
            );
            return None;
        }
    };
    let port: u16 = match port_s.parse() {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "interop_reference: SPT_SSH3_TEST_SERVER port `{port_s}` not a u16 — skipping"
            );
            return None;
        }
    };
    let url_path = env::var("SPT_SSH3_TEST_URL_PATH").unwrap_or_else(|_| "/ssh3-term".to_string());
    let bearer = env::var("SPT_SSH3_TEST_BEARER").ok();
    let identity_file = env::var("SPT_SSH3_TEST_IDENTITY_FILE")
        .ok()
        .map(PathBuf::from);
    let identity_passphrase = env::var("SPT_SSH3_TEST_IDENTITY_PASSPHRASE")
        .ok()
        .and_then(|raw| {
            // Pass it through the env: SecretRef indirection so the
            // PublicKey branch can resolve it the same way prod does.
            std::env::set_var("SPT_SSH3_INTEROP_PASS", raw);
            SecretRef::parse("env:SPT_SSH3_INTEROP_PASS").ok()
        });
    let allow_self_signed = matches!(
        env::var("SPT_SSH3_TEST_ALLOW_SELF_SIGNED")
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes"
    );
    let ca_file = env::var("SPT_SSH3_TEST_CA_FILE").ok().map(PathBuf::from);
    let echo_target =
        env::var("SPT_SSH3_TEST_ECHO_TARGET").unwrap_or_else(|_| "127.0.0.1:7".to_string());
    let echo_target: SocketAddr = match echo_target.parse() {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "interop_reference: SPT_SSH3_TEST_ECHO_TARGET `{echo_target}` not a SocketAddr ({e}) — skipping"
            );
            return None;
        }
    };

    Some(InteropEnv {
        host: host.to_string(),
        port,
        user,
        url_path,
        bearer,
        identity_file,
        identity_passphrase,
        allow_self_signed,
        ca_file,
        echo_target,
    })
}

fn build_auth(env: &InteropEnv) -> Option<AuthConfig> {
    if let Some(bearer) = env.bearer.clone() {
        std::env::set_var("SPT_SSH3_INTEROP_BEARER", bearer);
        let token = SecretRef::parse("env:SPT_SSH3_INTEROP_BEARER").ok()?;
        return Some(AuthConfig::new(
            env.user.clone(),
            vec![AuthMethod::Bearer { token }],
        ));
    }
    let identity_file = env.identity_file.clone()?;
    Some(AuthConfig::new(
        env.user.clone(),
        vec![AuthMethod::PublicKey {
            identity_file,
            passphrase: env.identity_passphrase.clone(),
            allow_ssh_rsa_sha1: false,
        }],
    ))
}

fn install_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn upstream_reference_local_forward_echo() {
    install_ring();
    let env = match parse_env() {
        Some(v) => v,
        None => {
            eprintln!("{SKIP_NOTICE}");
            return;
        }
    };

    let auth = match build_auth(&env) {
        Some(v) => v,
        None => {
            eprintln!(
                "interop_reference: SPT_SSH3_TEST_BEARER unset AND SPT_SSH3_TEST_IDENTITY_FILE \
                 unset — cannot build an auth method, skipping."
            );
            return;
        }
    };

    let cfg = Ssh3Config {
        url_path: env.url_path.clone(),
        acknowledge_experimental: true,
        tls: Ssh3TlsConfig {
            allow_self_signed: env.allow_self_signed,
            ca_file: env.ca_file.clone(),
            ..Ssh3TlsConfig::default()
        },
        ..Ssh3Config::default()
    };

    eprintln!(
        "interop_reference: connecting to {}:{}{} as {}",
        env.host, env.port, env.url_path, env.user
    );

    // 1) Bootstrap (covers QUIC + TLS + HTTP/3 Extended CONNECT + auth header).
    let bs = match tokio::time::timeout(
        Duration::from_secs(20),
        spt_ssh3::bootstrap(&env.host, env.port, &cfg, &auth),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => panic!("interop_reference: bootstrap against upstream failed: {e}"),
        Err(_) => panic!("interop_reference: bootstrap timed out after 20s"),
    };

    let mut session: Box<dyn TunnelSession> = Box::new(Ssh3Session::from_bootstrap(bs));

    // 2) Pick a local listener port for the forward (bind, read addr, drop —
    //    open_local_forward will rebind it).
    let probe = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let listen_addr = probe.local_addr().unwrap();
    drop(probe);

    let spec = LocalForwardSpec {
        name: "interop-tcp".into(),
        listen: BindAddr::Tcp(listen_addr),
        target: TargetAddr::new(env.echo_target.ip().to_string(), env.echo_target.port()),
        max_connections: None,
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: BindConflictPolicy::default(),
        required: false,
    };
    let _handle = match tokio::time::timeout(
        Duration::from_secs(10),
        session.open_local_forward(&spec),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => panic!("interop_reference: open_local_forward failed: {e}"),
        Err(_) => panic!("interop_reference: open_local_forward timed out"),
    };

    // 3) 64 KiB pseudo-random payload, full round-trip via local listener →
    //    upstream SSH3 → echo target → back. xorshift PRNG (no extra crate).
    let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut payload = vec![0u8; 64 * 1024];
    for b in &mut payload {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = state.wrapping_mul(0x2545_F491_4F6C_DD1D) as u8;
    }

    let mut sock = match tokio::time::timeout(
        Duration::from_secs(10),
        TcpStream::connect(listen_addr),
    )
    .await
    {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => panic!("interop_reference: connect to local listener failed: {e}"),
        Err(_) => panic!("interop_reference: TcpStream::connect timed out"),
    };
    sock.write_all(&payload).await.expect("write payload");
    sock.shutdown().await.expect("shutdown writer");
    let mut got = Vec::with_capacity(payload.len());
    match tokio::time::timeout(Duration::from_secs(30), sock.read_to_end(&mut got)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => panic!("interop_reference: read_to_end failed: {e}"),
        Err(_) => panic!("interop_reference: echo read timed out (30s)"),
    }
    assert_eq!(
        got.len(),
        payload.len(),
        "echo length mismatch (sent {}, got {})",
        payload.len(),
        got.len()
    );
    assert_eq!(got, payload, "echo body mismatch");

    // 4) Close the channel + session cleanly.
    drop(_handle);
    session.close().await.expect("session close");
    eprintln!("interop_reference: PASS");
}
