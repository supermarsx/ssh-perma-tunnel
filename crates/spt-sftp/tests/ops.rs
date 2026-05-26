//! Integration tests for the SFTP operations exposed by `spt-sftp`.
//!
//! Each scenario uses [`MockSftpServer`] — an in-process SFTP server backed
//! by a real filesystem — wired to an [`SftpClient`] via `tokio::io::duplex`.
//! No SSH transport is required, so the tests run identically on
//! Linux/macOS/Windows CI.

#![cfg(feature = "testing")]

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use spt_sftp::error::SftpError;
use spt_sftp::mock::MockSftpServer;
#[cfg(unix)]
use spt_sftp::{get_recursive, put_recursive, ChecksumMode, RecursiveOptions};
use spt_sftp::{sha256_local_file, sha256_remote_file, TokenBucket};

async fn setup() -> (tempfile::TempDir, MockSftpServer, spt_sftp::SftpClient) {
    let dir = tempfile::tempdir().unwrap();
    let (server, client) = MockSftpServer::start(dir.path()).await;
    (dir, server, client)
}

fn write_local(root: &Path, rel: &str, body: &[u8]) -> PathBuf {
    let p = root.join(rel);
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&p, body).unwrap();
    p
}

#[tokio::test]
async fn cat_returns_remote_body_within_cap() {
    let (dir, _server, client) = setup().await;
    write_local(dir.path(), "hello.txt", b"hi");
    let got = client.cat("/hello.txt", 1024).await.unwrap();
    assert_eq!(got, b"hi");
}

#[tokio::test]
async fn cat_rejects_files_larger_than_cap() {
    let (dir, _server, client) = setup().await;
    write_local(dir.path(), "big.bin", &vec![0u8; 16 * 1024]);
    let err = client.cat("/big.bin", 1024).await.unwrap_err();
    assert!(matches!(err, SftpError::Local { .. }), "got {err:?}");
    assert!(err.to_string().contains("exceeds cap"));
}

#[tokio::test]
async fn tail_returns_last_n_bytes() {
    let (dir, _server, client) = setup().await;
    write_local(dir.path(), "log.txt", b"0123456789ABCDEF");
    let got = client.tail("/log.txt", 5).await.unwrap();
    assert_eq!(got, b"BCDEF");
}

#[tokio::test]
async fn tail_of_empty_file_returns_empty() {
    let (dir, _server, client) = setup().await;
    write_local(dir.path(), "empty.log", b"");
    let got = client.tail("/empty.log", 4096).await.unwrap();
    assert!(got.is_empty());
}

#[tokio::test]
async fn realpath_of_relative_produces_absolute_path() {
    let (_dir, _server, client) = setup().await;
    let p = client.realpath(".").await.unwrap();
    let s = p.to_string_lossy();
    assert!(
        s.starts_with('/') || s.contains(":\\"),
        "expected absolute path, got {s}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn chmod_on_directory_persists_mode() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, _server, client) = setup().await;
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    client.chmod("/subdir", 0o750).await.unwrap();
    let mode = std::fs::metadata(dir.path().join("subdir"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o7777, 0o750);
}

#[cfg(not(unix))]
#[tokio::test]
async fn chmod_on_directory_is_accepted_even_when_noop() {
    // On non-unix the mock skips the actual chmod but the request must
    // complete cleanly.
    let (dir, _server, client) = setup().await;
    std::fs::create_dir(dir.path().join("subdir")).unwrap();
    client.chmod("/subdir", 0o750).await.unwrap();
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_and_readlink_round_trip() {
    let (dir, _server, client) = setup().await;
    write_local(dir.path(), "target.txt", b"x");
    client.symlink("target.txt", "/link.txt").await.unwrap();
    let resolved = client.readlink("/link.txt").await.unwrap();
    assert_eq!(resolved, std::path::PathBuf::from("target.txt"));
}

#[cfg(unix)]
#[tokio::test]
async fn put_recursive_mirrors_three_level_tree() {
    let (dir, _server, client) = setup().await;
    let local_root = tempfile::tempdir().unwrap();
    write_local(local_root.path(), "a.txt", b"A");
    write_local(local_root.path(), "sub1/b.txt", b"BB");
    write_local(local_root.path(), "sub1/sub2/c.txt", b"CCC");

    let report = put_recursive(
        &client,
        local_root.path(),
        "/mirror",
        &RecursiveOptions::default(),
    )
    .await
    .unwrap();
    assert!(report.files >= 3);
    assert_eq!(report.bytes, 6);

    let mirrored = dir.path().join("mirror");
    assert_eq!(std::fs::read(mirrored.join("a.txt")).unwrap(), b"A");
    assert_eq!(std::fs::read(mirrored.join("sub1/b.txt")).unwrap(), b"BB");
    assert_eq!(
        std::fs::read(mirrored.join("sub1/sub2/c.txt")).unwrap(),
        b"CCC"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn get_recursive_pulls_three_level_tree() {
    let (dir, _server, client) = setup().await;
    // Build the source on the server's filesystem.
    std::fs::create_dir_all(dir.path().join("seed/sub1/sub2")).unwrap();
    std::fs::write(dir.path().join("seed/a.txt"), b"A").unwrap();
    std::fs::write(dir.path().join("seed/sub1/b.txt"), b"BB").unwrap();
    std::fs::write(dir.path().join("seed/sub1/sub2/c.txt"), b"CCC").unwrap();

    let dest = tempfile::tempdir().unwrap();
    let report = get_recursive(&client, "/seed", dest.path(), &RecursiveOptions::default())
        .await
        .unwrap();
    assert_eq!(report.files, 3);
    assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), b"A");
    assert_eq!(
        std::fs::read(dest.path().join("sub1/b.txt")).unwrap(),
        b"BB"
    );
    assert_eq!(
        std::fs::read(dest.path().join("sub1/sub2/c.txt")).unwrap(),
        b"CCC"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn resume_continues_from_existing_remote_size() {
    let (dir, _server, client) = setup().await;
    let local_root = tempfile::tempdir().unwrap();
    // 8-byte local file; remote already has the first 4 bytes.
    write_local(local_root.path(), "file.bin", b"ABCDEFGH");
    std::fs::create_dir_all(dir.path().join("mirror")).unwrap();
    std::fs::write(dir.path().join("mirror/file.bin"), b"ABCD").unwrap();
    let opts = RecursiveOptions {
        resume: true,
        ..Default::default()
    };
    let report = put_recursive(&client, local_root.path(), "/mirror", &opts)
        .await
        .unwrap();
    // Resumed bytes only — first 4 already present.
    assert_eq!(report.bytes, 4);
    let mirrored = std::fs::read(dir.path().join("mirror/file.bin")).unwrap();
    assert_eq!(mirrored, b"ABCDEFGH");
}

#[tokio::test]
async fn bandwidth_limiter_holds_target_rate() {
    // 5 MiB/s × 2s = 10 MiB ±15% in CI; measured against a real
    // tokio::sleep so we keep some slack.
    let rate = 5 * 1024 * 1024;
    let bucket = TokenBucket::new(rate);
    // Drain initial burst capacity.
    bucket.consume(rate).await;
    let start = Instant::now();
    let chunk = 64 * 1024u64;
    let mut delivered = 0u64;
    while start.elapsed() < Duration::from_secs(2) {
        bucket.consume(chunk).await;
        delivered += chunk;
    }
    let target = 2 * rate;
    let low = (target as f64 * 0.85) as u64;
    let high = (target as f64 * 1.15) as u64;
    assert!(
        delivered >= low && delivered <= high,
        "delivered {delivered} not within [{low}, {high}] for target {target}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn checksum_mismatch_is_detected() {
    let (dir, _server, client) = setup().await;
    // Stage local body that differs from the seeded remote body so a
    // resumed transfer produces a mismatch.
    let local_root = tempfile::tempdir().unwrap();
    write_local(local_root.path(), "f.bin", b"ABCDEFGH");
    std::fs::create_dir_all(dir.path().join("mirror")).unwrap();
    // Pre-seed remote with a contradictory prefix so the resumed (offset=4)
    // upload writes only the tail and the verifier sees the mismatch.
    std::fs::write(dir.path().join("mirror/f.bin"), b"WXYZ").unwrap();
    let opts = RecursiveOptions {
        resume: true,
        checksum: ChecksumMode::Sha256,
        ..Default::default()
    };
    let err = put_recursive(&client, local_root.path(), "/mirror", &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SftpError::Local { op, .. } if op == "put-checksum"),
        "got {err:?}",
    );
}

#[cfg(unix)]
#[tokio::test]
async fn symlink_loop_detected_during_recursive_walk() {
    let (_server_dir, _server, client) = setup().await;
    let local_root = tempfile::tempdir().unwrap();
    let a = local_root.path().join("a");
    let b = local_root.path().join("b");
    std::fs::create_dir(&a).unwrap();
    std::fs::create_dir(&b).unwrap();
    // a/loop -> ../b ; b/loop -> ../a — walker that follows symlinks must
    // detect the cycle.
    std::os::unix::fs::symlink("../b", a.join("loop")).unwrap();
    std::os::unix::fs::symlink("../a", b.join("loop")).unwrap();
    let opts = RecursiveOptions {
        follow_symlinks: true,
        ..Default::default()
    };
    let err = put_recursive(&client, local_root.path(), "/loopy", &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(err, SftpError::Local { op, ref detail, .. }
            if op == "put-walk" && detail.contains("symlink loop")),
        "got {err:?}",
    );
}

#[tokio::test]
async fn error_mapping_classifies_missing_path() {
    let (_dir, _server, client) = setup().await;
    let err = client.metadata("/does-not-exist").await.unwrap_err();
    assert!(matches!(err, SftpError::NoSuchFile { .. }), "got {err:?}");
}

#[tokio::test]
async fn error_mapping_classifies_directory_not_empty() {
    let (dir, _server, client) = setup().await;
    std::fs::create_dir(dir.path().join("nest")).unwrap();
    std::fs::write(dir.path().join("nest/child"), b"x").unwrap();
    let err = client.remove_dir("/nest").await.unwrap_err();
    assert!(matches!(err, SftpError::NotEmpty { .. }), "got {err:?}");
}

#[tokio::test]
async fn checksum_helper_matches_for_identical_bodies() {
    let (dir, _server, client) = setup().await;
    let local = dir.path().join("seed.txt");
    std::fs::write(&local, b"matching body").unwrap();
    // Mirror the same body via SFTP and verify both digests align.
    client
        .write_file("/uploaded.txt", b"matching body")
        .await
        .unwrap();
    let l = sha256_local_file(&local).await.unwrap();
    let r = sha256_remote_file(&client, "/uploaded.txt").await.unwrap();
    assert_eq!(l, r);
}

/// Compile-time back-compat assertion: the old `spt_ssh2::sftp::SftpClient`
/// re-export keeps resolving via the shim file we left in place.
#[test]
fn back_compat_spt_ssh2_re_export_resolves() {
    fn _accepts_old_path(_c: &spt_ssh2::sftp::SftpClient) {}
    fn _accepts_old_root(_c: &spt_ssh2::SftpClient) {}
}
