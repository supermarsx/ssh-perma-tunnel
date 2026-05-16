//! Drive libssh2 against a system `sshd`.
//!
//! This is the **track-a** workaround for the upstream russh-0.46 ↔
//! libssh2-WinCNG `LIBSSH2_ERROR_KEY_EXCHANGE_FAILURE` (-8) interop bug: a real
//! OpenSSH server negotiates cleanly with libssh2 on Linux/macOS.
//!
//! All tests in this file are:
//!
//! * `#[cfg_attr(target_os = "windows", ignore)]` — Windows builds compile the
//!   tests for completeness but skip them at runtime (the Windows OpenSSH
//!   `sshd.exe` config schema and ACL setup differ enough that supporting it
//!   is out of scope).
//! * Skipped at runtime when `sshd` is not on `PATH` (typical for stripped
//!   CI containers).
//!
//! Test scope (Linux/macOS only):
//!   * builder smoke — verifies the `OpenSshTestServer` fixture compiles and
//!     the fixture's `locate_sshd` discovery contract holds.
//!   * `sshd` start — when sshd is available, spawns it and asserts the
//!     loopback listener is reachable.
//!
//! Note: this file deliberately does **not** drive an `Ssh2Protocol::connect`
//! against the spawned sshd. That requires a configured pubkey and a tightly
//! controlled user account; doing it portably across Linux/macOS CI hosts is
//! out of scope. The fixture itself unblocks ambitious downstream tests; this
//! file ships the smoke tests that exercise it.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

#[cfg(feature = "testing")]
#[cfg_attr(target_os = "windows", ignore)]
#[tokio::test]
async fn openssh_locate_sshd_does_not_panic() {
    #[cfg(unix)]
    {
        // Locate is contractually allowed to return None (sshd not installed).
        let _ = spt_ssh2::testing::OpenSshTestServer::locate_sshd();
    }
}

#[cfg(all(unix, feature = "testing"))]
#[cfg_attr(target_os = "windows", ignore)]
#[tokio::test]
async fn openssh_start_skips_cleanly_when_sshd_absent() {
    use spt_ssh2::testing::OpenSshTestServer;

    if OpenSshTestServer::locate_sshd().is_none() {
        eprintln!("skip: sshd not on PATH");
        return;
    }
    // sshd is present — start it and verify the listener is reachable.
    let server = OpenSshTestServer::new().start().await.expect("start ok");
    let Some(running) = server else {
        eprintln!("skip: locate_sshd succeeded but start returned None");
        return;
    };
    // Confirm the port is listening.
    let connect = tokio::net::TcpStream::connect(running.addr).await;
    assert!(
        connect.is_ok(),
        "expected sshd port {} to be reachable: {:?}",
        running.addr,
        connect.err()
    );
    running.shutdown();
}

#[cfg(all(unix, feature = "testing"))]
#[cfg_attr(target_os = "windows", ignore)]
#[tokio::test]
async fn openssh_config_path_present_when_running() {
    use spt_ssh2::testing::OpenSshTestServer;

    if OpenSshTestServer::locate_sshd().is_none() {
        eprintln!("skip: sshd not on PATH");
        return;
    }
    let Some(running) = OpenSshTestServer::new()
        .start()
        .await
        .expect("start ok")
    else {
        return;
    };
    let cfg = running.config_path().expect("config path");
    assert!(cfg.exists(), "sshd_config must exist on disk: {}", cfg.display());
    let body = std::fs::read_to_string(&cfg).unwrap();
    assert!(body.contains("ListenAddress 127.0.0.1"));
    assert!(body.contains("StrictModes no"));
    running.shutdown();
}

// Non-Unix placeholder so the test binary still has a tokio::test entry and
// compiles cleanly under `cargo test --features testing` on Windows.
#[cfg(all(not(unix), feature = "testing"))]
#[tokio::test]
async fn openssh_interop_not_supported_on_this_platform() {
    eprintln!("openssh_interop tests are Unix-only; skipping on this platform");
}

// Non-feature build: ship at least one entry so the test binary has a target.
#[cfg(not(feature = "testing"))]
#[test]
fn openssh_interop_requires_testing_feature() {
    eprintln!(
        "openssh_interop tests require the `testing` feature; build with \
         --features testing to enable"
    );
}
