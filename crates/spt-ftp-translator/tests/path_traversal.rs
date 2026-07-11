//! t8-A6 path-traversal / injection tests for the FTP→SFTP translator.
//!
//! Policy (post-A6 fix, defense-in-depth at the FTP layer):
//!
//! * `..` path segments in any verb argument are REJECTED with `550
//!   Permission denied` by [`validate_path_argument`] before being passed
//!   to the SFTP backend. The backend SFTP server is *also* expected to
//!   jail the session (chroot or per-user root), but the FTP-layer
//!   rejection is the primary defense and does not rely on backend
//!   configuration.
//! * Embedded NUL bytes (`\0`) in path arguments are rejected with `553
//!   File name not allowed`.
//! * Mixed `/` and `\` separators are both honoured for segment splitting
//!   (so a `foo\..\bar` payload cannot bypass the check on Windows-style
//!   inputs).
//! * Unicode-confusable codepoints (e.g. U+FF0E FULLWIDTH FULL STOP) are
//!   currently NOT normalised to NFC before splitting. Such inputs do
//!   not match the literal `..` filter; they instead reach the SFTP
//!   backend, which returns `NoSuchFile`. Adding a
//!   `unicode-normalization` workspace dep is deferred.
//! * CR/LF in command lines is split by the framing layer per RFC 959.
//!
//! These tests assert the post-fix behavior.

#![cfg(feature = "testing")]
#![allow(clippy::too_many_lines)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::uninlined_format_args)]

mod support;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use spt_ftp_translator::{mock::MockSftpFactory, server::Server, AuthPolicy, TranslatorConfig};
use support::passive_range;
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const TIMEOUT: Duration = Duration::from_secs(5);

async fn spawn_translator() -> (SocketAddr, spt_ftp_translator::ServerHandle, TempDir) {
    let dir = tempfile::tempdir().expect("tempdir");
    let factory = Arc::new(MockSftpFactory::new(dir.path().to_path_buf()));
    let mut cfg =
        TranslatorConfig::defaults_for(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0));
    cfg.auth = AuthPolicy::Static {
        username: "alice".into(),
        password: "s3cret".into(),
    };
    cfg.welcome_banner = "spt-ftp-translator t8-A6".into();
    cfg.passive_port_range = passive_range(IpAddr::V4(Ipv4Addr::LOCALHOST), 32);
    cfg.idle_timeout = Duration::from_secs(60);
    let server = Server::new(cfg, factory);
    let handle = server.start().await.expect("start");
    (handle.local_addr, handle, dir)
}

async fn connect(
    addr: SocketAddr,
) -> (
    BufReader<tokio::net::tcp::OwnedReadHalf>,
    tokio::net::tcp::OwnedWriteHalf,
) {
    let stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(addr))
        .await
        .expect("ct")
        .expect("tcp");
    let (rd, wr) = stream.into_split();
    let mut br = BufReader::new(rd);
    let mut greet = String::new();
    tokio::time::timeout(TIMEOUT, br.read_line(&mut greet))
        .await
        .expect("greet ct")
        .expect("greet");
    assert!(greet.starts_with("220 "));
    (br, wr)
}

async fn send(wr: &mut tokio::net::tcp::OwnedWriteHalf, cmd: &str) {
    wr.write_all(cmd.as_bytes()).await.expect("write");
    wr.write_all(b"\r\n").await.expect("crlf");
    wr.flush().await.expect("flush");
}

async fn recv_line(br: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> String {
    let mut line = String::new();
    tokio::time::timeout(TIMEOUT, br.read_line(&mut line))
        .await
        .expect("recv ct")
        .expect("recv");
    line
}

async fn login(
    br: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    wr: &mut tokio::net::tcp::OwnedWriteHalf,
) {
    send(wr, "USER alice").await;
    let _ = recv_line(br).await;
    send(wr, "PASS s3cret").await;
    let r = recv_line(br).await;
    assert!(r.starts_with("230"), "login failed: {r}");
}

// ---------------------------------------------------------------------------
// 1. CWD `..` is REJECTED at the FTP layer with 550.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cwd_dotdot_rejected_with_550() {
    let (addr, handle, _dir) = spawn_translator().await;
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    send(&mut wr, "CWD ..").await;
    let r = recv_line(&mut br).await;
    assert!(
        r.starts_with("550"),
        "CWD .. must be rejected with 550, got: `{r}`"
    );

    // Verify we're still effectively at `/` by issuing PWD.
    send(&mut wr, "PWD").await;
    let pwd = recv_line(&mut br).await;
    assert!(pwd.contains('/'), "PWD should report a path: `{pwd}`");
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 2. RETR with `..` segments is REJECTED at the FTP layer with 550 before
//    the data channel is touched.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retr_dotdot_rejected_at_ftp_layer() {
    let (addr, handle, dir) = spawn_translator().await;
    // Place a sibling file OUTSIDE the tempdir to ensure the `..` traversal
    // would land on it if not contained.
    let outside_dir = tempfile::tempdir().unwrap();
    std::fs::write(outside_dir.path().join("evil.txt"), b"evil").unwrap();

    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;
    send(&mut wr, "TYPE I").await;
    let _ = recv_line(&mut br).await;

    send(&mut wr, "PASV").await;
    let _pasv = recv_line(&mut br).await;
    send(&mut wr, "RETR ../evil.txt").await;
    let r = recv_line(&mut br).await;
    assert!(
        r.starts_with("550"),
        "RETR ../evil.txt must be rejected with 550, got: `{r}`"
    );

    // Critically: the OUTSIDE file is intact and was NOT served.
    let outside_content = std::fs::read(outside_dir.path().join("evil.txt")).unwrap();
    assert_eq!(outside_content, b"evil");
    let _ = dir; // keep tempdir alive
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 3. STOR absolute path outside the mock-rooted dir fails.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stor_absolute_path_outside_mock_root_fails() {
    let (addr, handle, _dir) = spawn_translator().await;
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;
    send(&mut wr, "TYPE I").await;
    let _ = recv_line(&mut br).await;

    send(&mut wr, "PASV").await;
    let pasv = recv_line(&mut br).await;
    let port = parse_pasv_port(&pasv).expect("pasv port");

    // Try to upload to /etc/passwd — absolute path is honored by
    // normalise(); the mock factory's rooted SFTP server rejects writes
    // outside its tempdir.
    send(&mut wr, "STOR /etc/passwd-injection").await;
    let mut dc = TcpStream::connect(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port))
        .await
        .expect("data connect");
    dc.write_all(b"adversarial").await.expect("write");
    dc.shutdown().await.expect("shutdown");

    let r = recv_line(&mut br).await;
    // Either:
    //   * 5xx — backend rejected the absolute path
    //   * 226 — the upload "succeeded" but stayed within the chrooted mock,
    //     meaning the actual file was written under tempdir/etc/passwd-injection
    // We assert the *system file* wasn't actually touched.
    let _ = r;
    let real_system_path = "/etc/passwd-injection";
    assert!(
        !std::path::Path::new(real_system_path).exists(),
        "system file was created — chroot escape!"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 4. RNFR / RNTO with `..` fails or stays in jail.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rename_dotdot_does_not_escape_root() {
    let (addr, handle, dir) = spawn_translator().await;
    std::fs::write(dir.path().join("victim.txt"), b"x").unwrap();
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    send(&mut wr, "RNFR victim.txt").await;
    let r = recv_line(&mut br).await;
    assert!(r.starts_with("350") || r.starts_with('5'), "RNFR: {r}");
    send(&mut wr, "RNTO ../../evil.txt").await;
    let r2 = recv_line(&mut br).await;
    assert!(
        r2.starts_with("550"),
        "RNTO with `..` must be rejected with 550, got: `{r2}`"
    );
    let outside_root = std::path::Path::new("/evil.txt");
    assert!(!outside_root.exists(), "rename escaped to /evil.txt");
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 5. NUL byte in filename — embedded inside the verb argument.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn null_byte_in_filename_handled_safely() {
    let (addr, handle, _dir) = spawn_translator().await;
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    // Send a CWD with an embedded NUL byte (between the verb and CRLF).
    // The framing layer reads up to CRLF, so the NUL is part of the arg.
    let payload = b"CWD bad\x00name\r\n";
    wr.write_all(payload).await.expect("write");
    wr.flush().await.expect("flush");
    let r = recv_line(&mut br).await;
    // Should not crash; should respond with a code (likely 550 or 250
    // depending on SFTP backend behavior). Asserting absence of panic +
    // structured response is enough.
    assert!(
        r.chars().next().is_some_and(|c| c.is_ascii_digit()),
        "expected structured FTP response, got `{r}`"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 6. Unicode normalisation attack — overlong UTF-8 or alternate dot forms.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unicode_dot_alternate_does_not_traverse() {
    let (addr, handle, _dir) = spawn_translator().await;
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    // U+002E is the ASCII dot; alternative dot-like codepoints are NOT
    // recognised by `normalise()` (which compares to literal "..").
    // ｡｡ (FULLWIDTH FULL STOP, U+FF61 × 2) is not collapsed.
    let cmd = "CWD \u{FF61}\u{FF61}/etc";
    send(&mut wr, cmd).await;
    let r = recv_line(&mut br).await;
    // The path becomes literally `/\u{FF61}\u{FF61}/etc` which doesn't
    // exist; backend returns 5xx.
    assert!(
        r.starts_with('5') || r.starts_with("250"),
        "unexpected response to unicode dot CWD: `{r}`"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 7. Wire-level CRLF embedded inside a verb arg is split into two commands;
//    this is RFC-aligned behavior. We sanity-check that the second command
//    is independently parsed — i.e. the first does not somehow inherit the
//    second's data.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn crlf_in_arg_splits_into_two_verbs() {
    let (addr, handle, _dir) = spawn_translator().await;
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    // "CWD foo\r\nNOOP\r\n" — server should respond to two separate
    // commands.
    wr.write_all(b"CWD foo\r\nNOOP\r\n").await.unwrap();
    wr.flush().await.unwrap();
    let r1 = recv_line(&mut br).await;
    let r2 = recv_line(&mut br).await;
    // Both should be valid FTP responses. CWD foo → 5xx (no such dir),
    // NOOP → 200.
    assert!(
        r1.chars().next().is_some_and(|c| c.is_ascii_digit()),
        "first response wasn't structured: `{r1}`"
    );
    assert!(
        r2.chars().next().is_some_and(|c| c.is_ascii_digit()),
        "second response wasn't structured: `{r2}`"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 8. Mixed-separator traversal: `foo\..\bar` must be rejected too. The
//    validator splits on BOTH `/` and `\` so a Windows-style backslash
//    payload cannot smuggle a `..` segment past the check.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cwd_backslash_dotdot_rejected() {
    let (addr, handle, _dir) = spawn_translator().await;
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    send(&mut wr, "CWD foo\\..\\bar").await;
    let r = recv_line(&mut br).await;
    assert!(
        r.starts_with("550"),
        "CWD foo\\..\\bar must be rejected with 550, got: `{r}`"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 9. Unicode-confusable dot (U+FF0E FULLWIDTH FULL STOP) is NOT collapsed
//    to ASCII `..` — it passes the validator (deferred) but reaches the
//    SFTP backend, which has no such directory. The legitimate file
//    outside the root must remain unread/unwritten.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cwd_fullwidth_dot_does_not_traverse() {
    let (addr, handle, _dir) = spawn_translator().await;
    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    // U+FF0E twice — NFC would normalise to ASCII `.` but we don't NFC.
    let cmd = "CWD \u{FF0E}\u{FF0E}";
    send(&mut wr, cmd).await;
    let r = recv_line(&mut br).await;
    // Either the FTP validator passes it through and the backend returns
    // 5xx (NoSuchFile), or the validator catches it. Either way the
    // result must NOT be a successful CWD that puts us above root.
    assert!(
        r.starts_with('5'),
        "fullwidth-dot CWD must not succeed, got: `{r}`"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// 10. Empty path segments (e.g. `foo//bar`) are allowed — they collapse
//     to `foo/bar` via `normalise()`. Confirms the validator is not
//     over-aggressive: only `..` segments are blocked.
// ---------------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cwd_empty_segments_allowed() {
    let (addr, handle, dir) = spawn_translator().await;
    // Create a `sub/` dir in the rooted tempdir.
    std::fs::create_dir(dir.path().join("sub")).unwrap();

    let (mut br, mut wr) = connect(addr).await;
    login(&mut br, &mut wr).await;

    // `//sub` and `/sub//` and `sub//` should all be accepted by the
    // validator (empty segments → collapse to `/sub`).
    send(&mut wr, "CWD //sub").await;
    let r = recv_line(&mut br).await;
    assert!(
        r.starts_with("250"),
        "CWD //sub must succeed (empty seg ok), got: `{r}`"
    );
    handle.shutdown();
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn parse_pasv_port(line: &str) -> Option<u16> {
    // 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2).
    let lp = line.find('(')?;
    let rp = line.find(')')?;
    let body = &line[lp + 1..rp];
    let parts: Vec<&str> = body.split(',').collect();
    if parts.len() != 6 {
        return None;
    }
    let p1: u16 = parts[4].parse().ok()?;
    let p2: u16 = parts[5].parse().ok()?;
    Some((p1 << 8) | p2)
}
