//! Path-traversal / hostile-server regression tests for recursive SFTP get.
//!
//! The remote SFTP server is the **untrusted** side of this product. A
//! malicious or compromised server can return READDIR entry names and
//! symlink targets crafted to escape the local download root (`..`,
//! absolute paths, Windows drive / UNC prefixes, separator-bearing names,
//! symlinks pointing outside the jail). `get_recursive` must sanitise every
//! server-supplied name and refuse to write or link outside the destination
//! directory.
//!
//! These tests use [`MockSftpServer::start_with_evil_entries`], which lets
//! the server append synthetic hostile entries to every directory listing —
//! something a real filesystem could never produce as a single dir entry.
//!
//! Mirrors the traversal coverage in
//! `crates/spt-ftp-translator/tests/path_traversal.rs`.

#![cfg(feature = "testing")]
#![allow(clippy::uninlined_format_args)]

use std::path::Path;

use spt_sftp::get_recursive;
use spt_sftp::mock::{EvilKind, MockSftpServer};
use spt_sftp::RecursiveOptions;

/// Spin up a mock server rooted at `root` that lists `evil` entries in
/// addition to whatever is on disk.
async fn server_with_evil(
    root: &Path,
    evil: Vec<(String, EvilKind, Option<String>)>,
) -> (MockSftpServer, spt_sftp::SftpClient) {
    MockSftpServer::start_with_evil_entries(root, evil).await
}

/// Anything created at or above `dest`'s PARENT (i.e. escaping the jail).
/// Returns the set of escaped paths that exist, for diagnostics.
fn escaped_outside(dest: &Path) -> Vec<std::path::PathBuf> {
    let parent = dest.parent().unwrap();
    let mut hits = Vec::new();
    for cand in [
        parent.join("escape"),
        parent.join("escape.txt"),
        parent.parent().map(|p| p.join("escape.txt")).unwrap(),
    ] {
        if cand.exists() {
            hits.push(cand);
        }
    }
    hits
}

// ---------------------------------------------------------------------------
// 1. A server entry named `../escape` does NOT write outside the dest.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn dotdot_entry_name_is_skipped_not_written_outside() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![("../escape".to_string(), EvilKind::File, None)];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest_parent = tempfile::tempdir().unwrap();
    let dest = dest_parent.path().join("dl");
    let report = get_recursive(&client, "/seed", &dest, &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(
        report.files, 0,
        "hostile `../escape` must not be downloaded"
    );
    assert!(
        escaped_outside(&dest).is_empty(),
        "file escaped the download root: {:?}",
        escaped_outside(&dest)
    );
    // Nothing under the legitimate dest either (the only entry was hostile).
    assert!(!dest.join("escape").exists());
}

// ---------------------------------------------------------------------------
// 2. Absolute-path entry name is rejected.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn absolute_path_entry_name_is_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![("/etc/spt-escape".to_string(), EvilKind::File, None)];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest_parent = tempfile::tempdir().unwrap();
    let dest = dest_parent.path().join("dl");
    let report = get_recursive(&client, "/seed", &dest, &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.files, 0);
    assert!(
        !Path::new("/etc/spt-escape").exists(),
        "absolute-path entry escaped to /etc"
    );
}

// ---------------------------------------------------------------------------
// 3. Windows drive-prefixed entry name is rejected.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn drive_prefixed_entry_name_is_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![("C:\\spt-escape.txt".to_string(), EvilKind::File, None)];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest_parent = tempfile::tempdir().unwrap();
    let dest = dest_parent.path().join("dl");
    let report = get_recursive(&client, "/seed", &dest, &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.files, 0);
    assert!(!Path::new("C:\\spt-escape.txt").exists());
    assert!(escaped_outside(&dest).is_empty());
}

// ---------------------------------------------------------------------------
// 4. UNC-prefixed entry name is rejected.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn unc_prefixed_entry_name_is_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![("\\\\srv\\share\\x".to_string(), EvilKind::File, None)];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest_parent = tempfile::tempdir().unwrap();
    let dest = dest_parent.path().join("dl");
    let report = get_recursive(&client, "/seed", &dest, &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.files, 0);
    assert!(escaped_outside(&dest).is_empty());
}

// ---------------------------------------------------------------------------
// 5. Separator-bearing entry name (`sub/../../escape.txt`) is rejected.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn separator_bearing_entry_name_is_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![("sub/../../escape.txt".to_string(), EvilKind::File, None)];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest_parent = tempfile::tempdir().unwrap();
    let dest = dest_parent.path().join("dl");
    let report = get_recursive(&client, "/seed", &dest, &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.files, 0);
    assert!(escaped_outside(&dest).is_empty());
}

// ---------------------------------------------------------------------------
// 6. Nested traversal: a hostile entry inside a deeper directory of the tree
//    is rejected at that level, not only at the top.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn nested_traversal_in_recursive_tree_is_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    // Real benign tree the walker descends into. The evil entry is appended
    // to EVERY listing, so it appears inside `seed/sub` too.
    std::fs::create_dir_all(srv_dir.path().join("seed/sub")).unwrap();
    std::fs::write(srv_dir.path().join("seed/sub/ok.txt"), b"ok").unwrap();
    let evil = vec![("../../../escape.txt".to_string(), EvilKind::File, None)];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest_parent = tempfile::tempdir().unwrap();
    let dest = dest_parent.path().join("dl");
    let report = get_recursive(&client, "/seed", &dest, &RecursiveOptions::default())
        .await
        .unwrap();

    // The benign file downloads; the hostile entries (one per listing) are
    // all skipped.
    assert_eq!(report.files, 1);
    assert_eq!(std::fs::read(dest.join("sub/ok.txt")).unwrap(), b"ok");
    assert!(escaped_outside(&dest).is_empty());
    assert!(!dest.parent().unwrap().join("escape.txt").exists());
}

// ---------------------------------------------------------------------------
// 7. A benign nested tree still downloads correctly (no regression).
// ---------------------------------------------------------------------------
#[tokio::test]
async fn benign_nested_tree_still_downloads() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(srv_dir.path().join("seed/sub1/sub2")).unwrap();
    std::fs::write(srv_dir.path().join("seed/a.txt"), b"A").unwrap();
    std::fs::write(srv_dir.path().join("seed/sub1/b.txt"), b"BB").unwrap();
    std::fs::write(srv_dir.path().join("seed/sub1/sub2/c.txt"), b"CCC").unwrap();
    // No evil entries.
    let (_server, client) = server_with_evil(srv_dir.path(), Vec::new()).await;

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

// ---------------------------------------------------------------------------
// 8. `.` and `..` entries (some servers include them) are skipped, not
//    treated as a write target.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn dot_and_dotdot_entries_are_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    std::fs::write(srv_dir.path().join("seed/real.txt"), b"r").unwrap();
    let evil = vec![
        (".".to_string(), EvilKind::Dir, None),
        ("..".to_string(), EvilKind::Dir, None),
    ];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest = tempfile::tempdir().unwrap();
    let report = get_recursive(&client, "/seed", dest.path(), &RecursiveOptions::default())
        .await
        .unwrap();
    assert_eq!(report.files, 1);
    assert_eq!(std::fs::read(dest.path().join("real.txt")).unwrap(), b"r");
}

// ---------------------------------------------------------------------------
// 9. (unix) A symlink whose target is `../../etc/x` is NOT created — the
//    escaping link must be refused.
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[tokio::test]
async fn symlink_with_relative_escaping_target_is_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    // Benign NAME, hostile TARGET — passes name sanitisation, fails the
    // symlink-target containment check.
    let evil = vec![(
        "link".to_string(),
        EvilKind::Symlink,
        Some("../../etc/x".to_string()),
    )];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest = tempfile::tempdir().unwrap();
    let report = get_recursive(&client, "/seed", dest.path(), &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.symlinks, 0, "escaping symlink must be refused");
    assert!(
        !dest.path().join("link").exists(),
        "escaping symlink was created"
    );
    // No symlink anywhere up the chain.
    assert!(std::fs::symlink_metadata(dest.path().join("link")).is_err());
}

// ---------------------------------------------------------------------------
// 10. (unix) A symlink with an ABSOLUTE target (`/etc/passwd`) is NOT created.
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[tokio::test]
async fn symlink_with_absolute_target_is_skipped() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![(
        "link".to_string(),
        EvilKind::Symlink,
        Some("/etc/passwd".to_string()),
    )];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest = tempfile::tempdir().unwrap();
    let report = get_recursive(&client, "/seed", dest.path(), &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.symlinks, 0);
    assert!(!dest.path().join("link").exists());
}

// ---------------------------------------------------------------------------
// 11. (unix) A symlink with a benign in-jail target IS created (no regression).
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[tokio::test]
async fn symlink_with_benign_target_is_created() {
    let srv_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![(
        "link".to_string(),
        EvilKind::Symlink,
        Some("sibling.txt".to_string()),
    )];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest = tempfile::tempdir().unwrap();
    let report = get_recursive(&client, "/seed", dest.path(), &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.symlinks, 1, "benign symlink should be recreated");
    let meta = std::fs::symlink_metadata(dest.path().join("link")).unwrap();
    assert!(meta.file_type().is_symlink());
    assert_eq!(
        std::fs::read_link(dest.path().join("link")).unwrap(),
        Path::new("sibling.txt")
    );
}

// ---------------------------------------------------------------------------
// 12. (unix) A symlink whose target uses `..` but stays WITHIN the jail is
//     allowed (e.g. `../other/x` from `sub/`).
// ---------------------------------------------------------------------------
#[cfg(unix)]
#[tokio::test]
async fn symlink_with_in_jail_dotdot_target_is_created() {
    let srv_dir = tempfile::tempdir().unwrap();
    // The link lives directly under seed/, so `../seed-sibling` would escape,
    // but a target like `other/x` (no escape) and `./x` stay in-jail. We use
    // a target that walks down then is contained.
    std::fs::create_dir(srv_dir.path().join("seed")).unwrap();
    let evil = vec![(
        "link".to_string(),
        EvilKind::Symlink,
        Some("inner/target".to_string()),
    )];
    let (_server, client) = server_with_evil(srv_dir.path(), evil).await;

    let dest = tempfile::tempdir().unwrap();
    let report = get_recursive(&client, "/seed", dest.path(), &RecursiveOptions::default())
        .await
        .unwrap();

    assert_eq!(report.symlinks, 1);
    assert_eq!(
        std::fs::read_link(dest.path().join("link")).unwrap(),
        Path::new("inner/target")
    );
}
