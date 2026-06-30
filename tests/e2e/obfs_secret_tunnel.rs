//! e2e (Wave E): obfuscation-over-SSH byte round-trip + secret-resolution
//! through a tunnel.
//!
//! ## Obfuscation-over-SSH (hermetic where a loopback server exists)
//!
//! Of the four obfs transports, only **shadowsocks** has a framing that can be
//! mirrored by an in-process loopback acceptor with no external reference tool:
//! the client writes a per-session salt, derives an AEAD subkey, and frames
//! everything through [`spt_obfs::shadowsocks::AeadStream`]. We stand up a
//! loopback SS acceptor that mirrors exactly that (read salt → derive the same
//! subkey → wrap the socket in an `AeadStream`) and bridges the de-obfuscated
//! plaintext to a real [`RusshTestServer`]. A shadowsocks CLIENT (driven via
//! its `with_direct_password` test seam) dials the acceptor; the real SSH
//! server's wire banner round-trips back **through the obfuscation layer**,
//! proving the SSH-over-obfs byte path against a real SSH server. A negative
//! test flips the SS password so AEAD de-obfuscation fails closed.
//!
//! (The production `Ssh2Protocol` obfs-dial builder does NOT resolve the
//! shadowsocks `password` `SecretRef` into the transport, so a builder-driven
//! SS-over-SSH dial currently fails with "password not resolved" — a real,
//! unwired spt-ssh2 gap flagged for follow-up, not faked here.)
//!
//! The other three transports (`meek-http`, `websocket`, `obfs4`) have **no
//! self-contained hermetic loopback server** in `spt-obfs`'s `testing` surface:
//!
//! * `meek-http` needs an HTTPS origin that speaks the meek session protocol
//!   (`X-Session-Id` POST-chaining) — there is no in-process meek server.
//! * `websocket` needs a real RFC-6455 server performing the upgrade +
//!   binary-frame relay — there is no in-process WS server fixture.
//! * `obfs4` frames XOR-mask their length prefix and require a full obfs4
//!   server (NTOR + framing) — only the *handshake* half is exercisable
//!   hermetically (see `crates/spt-obfs/tests/contract.rs`), not an SSH relay.
//!
//! Those three are covered by `#[ignore]`d placeholders with a clear
//! live-tool-gated reason rather than faked.
//!
//! ## Secret-resolution through a tunnel
//!
//! A tunnel is brought up where the SSH password is supplied via a `SecretRef`
//! resolved through the **real** `spt-secrets` chain wired into the
//! `Ssh2Protocol` builder (`.backend(...)`) — covering a `file://` ref, a
//! `secret://` (vault-shaped) ref, and the keychain-fallthrough (a missing
//! keychain falls through to the file backend). Each asserts a forward
//! round-trips, proving the resolved secret authenticated against
//! `RusshTestServer::with_password`.
//!
//! All hermetic: loopback `127.0.0.1:0`, in-process acceptor/bridge, bounded
//! waits. cfg(unix)-gated: the `file://` secret's 0600 mode (the Windows mode
//! check is best-effort and never rejects) — the Linux gate confirms the
//! 0600-perms path.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::sync::Arc;
use std::time::Duration;

use spt_auth::{AuthConfig, AuthMethod, SecretRef};
use spt_core::BindAddr;
use spt_obfs::config::{ObfsConfig, SsMethod};
use spt_obfs::shadowsocks::{direction_keys, salt_len, AeadStream, ShadowsocksTransport, SsRole};
use spt_obfs::transport::ObfsTransport;
use spt_obfs::NoopAuditHook;
use spt_protocol::{
    BindConflictPolicy, Endpoint, ForwardRateLimits, LocalForwardSpec, TargetAddr, TunnelProtocol,
};
use spt_secrets::testing::MemoryBackend;
use spt_secrets::{FileBackend, SecretBackend};
use spt_ssh2::testing::{tofu_trust_verifier, RusshTestServer};
use spt_ssh2::Ssh2Protocol;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

const SS_PASSWORD: &[u8] = b"ss-shared-secret-32-bytes-pad!!!";
const SS_METHOD: SsMethod = SsMethod::Aead2022Blake3Aes256Gcm;

fn scratch(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "spt-e2e-{tag}-{}-{}-{n}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

async fn free_loopback_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral");
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

/// The local-forward spec used by every obfs/secret round-trip: a fresh
/// loopback listener forwarding to the server's sentinel echo backend.
fn echo_forward(port: u16) -> LocalForwardSpec {
    LocalForwardSpec {
        name: "lf-echo".into(),
        listen: BindAddr::parse(&format!("127.0.0.1:{port}")).unwrap(),
        target: TargetAddr::new("server-side-echo", 7),
        max_connections: Some(4),
        limits: ForwardRateLimits::default(),
        idle_timeout: None,
        on_bind_conflict: BindConflictPolicy::default(),
        required: false,
    }
}

/// Drive a 4 KiB payload through an opened local forward and assert it echoes
/// byte-for-byte.
async fn assert_roundtrip(port: u16) {
    let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
    let mut sock = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect local forward listener");
    sock.write_all(&payload)
        .await
        .expect("write through forward");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), sock.read_exact(&mut echoed))
        .await
        .expect("timely echo")
        .expect("read echo");
    assert_eq!(echoed, payload, "bytes must round-trip through the forward");
}

// ---------------------------------------------------------------------------
// Shadowsocks loopback acceptor (de-obfuscation bridge)
// ---------------------------------------------------------------------------

/// A loopback shadowsocks "server" that mirrors the client framing: for each
/// inbound connection it reads the per-session salt, derives the SAME AEAD
/// subkey from `password`, wraps the socket in an [`AeadStream`], and bridges
/// the de-obfuscated plaintext to `upstream` (the russh server). Returns the
/// acceptor's loopback address; the bridge runs until the process exits.
async fn spawn_ss_acceptor(
    password: Vec<u8>,
    upstream: std::net::SocketAddr,
) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ss acceptor");
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut client, _)) = listener.accept().await else {
                break;
            };
            let password = password.clone();
            tokio::spawn(async move {
                // 1. Read the per-session salt the client pre-writes.
                let sl = salt_len(SS_METHOD);
                let mut salt = vec![0u8; sl];
                if client.read_exact(&mut salt).await.is_err() {
                    return;
                }
                // 2. Derive the same subkey via a mirror transport.
                let Ok(mirror) = ShadowsocksTransport::new(ss_cfg(), Arc::new(NoopAuditHook))
                    .map(|t| t.with_direct_password(password))
                else {
                    return;
                };
                let Ok(session_key) = mirror.derive_key(&salt) else {
                    return;
                };
                // Acceptor = server role: the mirror of the client's per-
                // direction subkeys (transmit on s2c, receive on c2s).
                let (tx, rx) = direction_keys(&session_key, SS_METHOD, SsRole::Server);
                // 3. Wrap the framed socket; everything past the salt is AEAD.
                let mut deobf = AeadStream::new(Box::new(client), SS_METHOD, tx, rx);

                // 4. Dial the upstream russh server and bridge plaintext both
                //    ways. Bytes the client AEAD-framed are decrypted here and
                //    forwarded verbatim to the russh server (and vice versa).
                let Ok(up) = TcpStream::connect(upstream).await else {
                    return;
                };
                let (mut up_rd, mut up_wr) = tokio::io::split(up);
                let mut a = vec![0u8; 16 * 1024];
                let mut b = vec![0u8; 16 * 1024];
                loop {
                    tokio::select! {
                        r = deobf.read(&mut a) => match r {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if up_wr.write_all(&a[..n]).await.is_err() { break; }
                            }
                        },
                        r = up_rd.read(&mut b) => match r {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if deobf.write_all(&b[..n]).await.is_err() { break; }
                            }
                        },
                    }
                }
            });
        }
    });
    addr
}

fn ss_cfg() -> ObfsConfig {
    ObfsConfig::Shadowsocks {
        method: SS_METHOD,
        // The password ref is unused on the direct-password test path; the
        // value is injected via `with_direct_password` on both ends.
        password: spt_secrets::SecretRef::new("ns", "ss").unwrap(),
    }
}

// ===========================================================================
// Wave E — obfuscation-over-SSH (shadowsocks, hermetic)
// ===========================================================================
//
// NOTE on scope: the production `Ssh2Protocol` obfs-dial path
// (`connect_to_endpoint` → `spt_obfs::transport_for_with_audit`) builds the
// shadowsocks transport WITHOUT resolving its `password` SecretRef into the
// transport's `direct_password`, so `ShadowsocksTransport::connect` fails with
// "password not resolved". That is a real, currently-unwired gap in spt-ssh2's
// obfs dial (the SS password is never injected) — NOT faked here. We therefore
// assert the obfs round-trip against a real SSH server by driving the
// `ShadowsocksTransport` CLIENT directly with its documented `with_direct_password`
// test seam (the same seam the obfs crate's own contract tests use), tunnelling
// the SSH server's wire bytes through the obfuscation layer. This proves the
// "SSH-over-obfs" byte path end-to-end; the spt-ssh2 builder wiring of the SS
// password is flagged for a follow-up.

/// Read the leading bytes off `stream` until at least `min` bytes arrive or the
/// deadline elapses.
async fn read_some(
    stream: &mut Box<dyn spt_obfs::transport::AsyncReadWrite>,
    min: usize,
) -> Vec<u8> {
    let mut buf = vec![0u8; 256];
    let mut got = Vec::new();
    while got.len() < min {
        match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await {
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(n)) => got.extend_from_slice(&buf[..n]),
        }
    }
    got
}

/// obfs-over-SSH e2e: a shadowsocks CLIENT dials a loopback SS acceptor that
/// de-obfuscates and bridges to a real `RusshTestServer`. The SSH server's wire
/// banner (`SSH-2.0-...`) must round-trip back **through the shadowsocks
/// obfuscation layer**, proving the SSH-over-obfs byte path against a real SSH
/// server.
#[tokio::test]
async fn shadowsocks_over_ssh_byte_roundtrip() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    // SS acceptor in front of the russh server, sharing the SS password.
    let ss_addr = spawn_ss_acceptor(SS_PASSWORD.to_vec(), server.addr).await;

    // The SS client uses the matching password (direct seam) and dials the
    // acceptor; the acceptor de-obfuscates and bridges to the russh server.
    let mut client = ShadowsocksTransport::new(ss_cfg(), Arc::new(NoopAuditHook))
        .unwrap()
        .with_direct_password(SS_PASSWORD.to_vec())
        .with_server(ss_addr.to_string());
    let mut stream = client
        .connect(&ss_addr.to_string())
        .await
        .expect("shadowsocks client connects to acceptor");

    // The russh server emits its SSH identification banner immediately on
    // connect; it travels back through the SS AEAD layer to us.
    let banner = read_some(&mut stream, 4).await;
    assert!(
        banner.starts_with(b"SSH-"),
        "SSH banner must round-trip through the shadowsocks obfuscation layer; got {:?}",
        String::from_utf8_lossy(&banner)
    );

    // Drive a client identification line back through the obfs layer too — a
    // full bidirectional exercise of the AEAD framing against the real server.
    stream
        .write_all(b"SSH-2.0-spt-e2e-obfs\r\n")
        .await
        .expect("write client banner through obfs");
    stream.flush().await.ok();

    drop(stream);
    server.shutdown().await;
}

/// Negative (mismatched obfs key): the SS client uses the WRONG password, so
/// the acceptor derives a different subkey and AEAD de-obfuscation fails — no
/// SSH banner round-trips (the bytes don't decrypt). Fail-closed, no panic.
#[tokio::test]
async fn shadowsocks_over_ssh_wrong_key_fails_closed() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    // Acceptor expects the real SS password.
    let ss_addr = spawn_ss_acceptor(SS_PASSWORD.to_vec(), server.addr).await;

    // Client uses a DIFFERENT SS password → subkey mismatch on the acceptor.
    let mut client = ShadowsocksTransport::new(ss_cfg(), Arc::new(NoopAuditHook))
        .unwrap()
        .with_direct_password(b"WRONG-ss-password-different-32by".to_vec())
        .with_server(ss_addr.to_string());
    let mut stream = client
        .connect(&ss_addr.to_string())
        .await
        .expect("tcp connect to acceptor succeeds (handshake mismatch is later)");

    // The acceptor cannot decrypt our (wrong-key) frames, so it never forwards
    // anything to the russh server and the server's banner never decodes back
    // to us: we must NOT observe a valid `SSH-` banner.
    let banner = read_some(&mut stream, 4).await;
    assert!(
        !banner.starts_with(b"SSH-"),
        "a mismatched obfs key must NOT yield a valid SSH banner; got {:?}",
        String::from_utf8_lossy(&banner)
    );

    drop(stream);
    server.shutdown().await;
}

// ===========================================================================
// Wave E — obfuscation-over-SSH (no hermetic server fixture → #[ignore]'d)
// ===========================================================================

#[tokio::test]
#[ignore = "meek-http has no in-process meek server fixture (needs an HTTPS origin \
            speaking the X-Session-Id POST-chaining meek protocol); live-tool-gated"]
async fn meek_http_over_ssh_roundtrip() {
    // Covered hermetically only at the handshake/error-surface layer in
    // crates/spt-obfs/tests/contract.rs. An SSH-over-meek relay needs a real
    // meek server, which is not available in-process.
}

#[tokio::test]
#[ignore = "websocket has no in-process RFC-6455 server fixture (needs a real WS \
            upgrade + binary-frame relay); live-tool-gated"]
async fn websocket_over_ssh_roundtrip() {
    // Upgrade-request construction + binary framing are unit-tested in
    // crates/spt-obfs/tests/contract.rs; an SSH relay needs a live WS server.
}

#[tokio::test]
#[ignore = "obfs4 has no in-process server fixture for an SSH relay (XOR-masked \
            length prefixes + full NTOR server); only the handshake half is \
            hermetic; live-tool-gated"]
async fn obfs4_over_ssh_roundtrip() {
    // The NTOR handshake against a mock acceptor + frame round-trip are
    // covered in crates/spt-obfs/tests/contract.rs; a full obfs4 server that
    // relays SSH is out of scope for a hermetic test.
}

// ===========================================================================
// Wave E — secret-resolution through a tunnel
// ===========================================================================

/// `file://` ref: the SSH password lives in a 0600 file (unix), resolved
/// through the real spt-secrets file path wired into the russh backend. A
/// forward round-trips, proving the resolved secret authenticated.
#[tokio::test]
async fn secret_file_ref_authenticates_tunnel() {
    let server = RusshTestServer::new()
        .with_password("tester", "filepw-secret")
        .start()
        .await
        .expect("start russh server");

    // Write the password to a file with owner-only perms on unix.
    let dir = scratch("secret-file");
    let pw_path = dir.join("ssh_password");
    std::fs::write(&pw_path, b"filepw-secret").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&pw_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    let proto = Ssh2Protocol::builder().trust(tofu_trust_verifier()).build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    // `SecretRef::File` resolves via the real file backend (mode-checked).
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::File(pw_path.to_string_lossy().into_owned()),
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("connect with file-ref-resolved password");

    let port = free_loopback_port().await;
    let handle = session
        .open_local_forward(&echo_forward(port))
        .await
        .expect("open local forward");
    assert_roundtrip(port).await;

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// `secret://` (vault-shaped) ref: the password is seeded in a real
/// `FileBackend` rooted at the `secret://ns/name` layout and resolved through
/// the backend chain wired into the russh `Ssh2Protocol`. A forward
/// round-trips, proving the resolved secret authenticated.
#[tokio::test]
async fn secret_vault_ref_authenticates_tunnel() {
    let server = RusshTestServer::new()
        .with_password("tester", "vaultpw-secret")
        .start()
        .await
        .expect("start russh server");

    // A FileBackend rooted at <dir> resolves `secret://ssh/password` from
    // <dir>/ssh/password — the same chain the rest of the binary uses.
    let dir = scratch("secret-vault");
    let backend = FileBackend::new(&dir);
    let secret_ref = spt_secrets::SecretRef::new("ssh", "password").unwrap();
    backend
        .set(&secret_ref, b"vaultpw-secret")
        .expect("seed secret into file-backed vault layout");

    let proto = Ssh2Protocol::builder()
        .trust(tofu_trust_verifier())
        .backend(Arc::new(backend) as Arc<dyn SecretBackend>)
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::Vault {
                namespace: "ssh".into(),
                name: "password".into(),
            },
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("connect with secret://-resolved password");

    let port = free_loopback_port().await;
    let handle = session
        .open_local_forward(&echo_forward(port))
        .await
        .expect("open local forward");
    assert_roundtrip(port).await;

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}

/// Keychain-fallthrough: the resolver chain is `[unavailable-keychain-shape,
/// file-backend]`. A missing keychain must fall through to the file backend
/// (the recently-fixed behaviour), so the password resolves and the tunnel
/// authenticates. Modeled with an empty in-memory backend (returns `Ok(None)`,
/// exactly like an unavailable keychain) followed by the file-backed secret.
#[tokio::test]
async fn keychain_fallthrough_authenticates_tunnel() {
    let server = RusshTestServer::new()
        .with_password("tester", "fallthru-secret")
        .start()
        .await
        .expect("start russh server");

    let dir = scratch("secret-fallthru");
    let file_backend = FileBackend::new(&dir);
    let secret_ref = spt_secrets::SecretRef::new("ssh", "password").unwrap();
    file_backend.set(&secret_ref, b"fallthru-secret").unwrap();

    // First backend resolves to None (the unavailable-keychain shape — a
    // missing keychain returns Ok(None) and must NOT abort the chain); the
    // file backend behind it supplies the value.
    let empty: Arc<dyn SecretBackend> = Arc::new(MemoryBackend::new());
    let proto = Ssh2Protocol::builder()
        .trust(tofu_trust_verifier())
        .backend(empty)
        .backend(Arc::new(file_backend) as Arc<dyn SecretBackend>)
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: SecretRef::Vault {
                namespace: "ssh".into(),
                name: "password".into(),
            },
        }],
    );
    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("connect after keychain-fallthrough to file backend");

    let port = free_loopback_port().await;
    let handle = session
        .open_local_forward(&echo_forward(port))
        .await
        .expect("open local forward");
    assert_roundtrip(port).await;

    handle.close().await;
    session.close().await.expect("close session");
    server.shutdown().await;
    let _ = std::fs::remove_dir_all(&dir);
}
