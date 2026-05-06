//! Same-process driver test for the `tunnel run` lifecycle.
//!
//! Rather than spawn a child process and drive Ctrl-C events on Windows
//! (which is genuinely awkward), we drive the [`Orchestrator`] directly
//! through the same calls `cli_dispatch::tunnel_run` performs:
//!
//! 1. Acquire the state lock.
//! 2. Stand up a [`StatusWriter`] and write the initial snapshot.
//! 3. Build a [`MockTunnelProtocol`]-backed bundle for one profile that has
//!    zero forwards.
//! 4. `Orchestrator::start_profile` to put the supervisor through its
//!    `Idle → Connecting → Established` arc.
//! 5. Verify `status.json` exists, lists the profile, and is valid JSON.
//! 6. `Orchestrator::shutdown().await` to prove the start/stop lifecycle is
//!    clean — no panics, no orphan tasks.
//!
//! This is the closest same-process analogue of the SIGTERM-clean-exit
//! contract `tunnel run` advertises.

use std::sync::Arc;
use std::time::Duration;

use spt_auth::AuthConfig;
use spt_config::load::load_str;
use spt_forward::testing::MockTunnelProtocol;
use spt_protocol::Endpoint;
use spt_state::{paths, StateLock, StatusWriter, StatusWriterConfig};
use spt_supervisor::{Orchestrator, ProfileSupervisorConfig};
use tempfile::TempDir;

const IDLE_PROFILE: &str = r#"
version = 1

[[profiles]]
name = "idle"
protocol = "ssh2"
host = "127.0.0.1"
user = "alice"
"#;

#[tokio::test]
async fn orchestrator_start_then_shutdown_writes_status_and_exits_clean() {
    let dir = TempDir::new().expect("tempdir");
    let state_dir = dir.path().to_path_buf();

    // 1. State lock — same as `cli_dispatch::tunnel_run`.
    let lock = StateLock::acquire(&state_dir).expect("state lock");

    // 2. Status writer.
    let writer_cfg = StatusWriterConfig {
        interval: Duration::from_millis(50),
        ring_size: 0,
    };
    let writer = StatusWriter::new(state_dir.clone(), writer_cfg);

    // 3. Load the idle config.
    let (cfg, _w) = load_str(IDLE_PROFILE, false).expect("load");
    writer
        .update(|s| {
            s.pid = std::process::id();
            s.version = "test".into();
            s.config_fingerprint_sha256 =
                spt_config::fingerprint::fingerprint_hex(&cfg);
            s.profiles = cfg
                .profiles
                .iter()
                .map(|p| spt_state::status::ProfileStatus {
                    id: p.name.clone(),
                    state: "starting".into(),
                    ..Default::default()
                })
                .collect();
        })
        .await;
    writer.flush().await.expect("flush");

    // 4. Build a mock-protocol orchestrator and start the profile. The mock
    //    succeeds on `connect`, so the supervisor moves to `Established`
    //    and waits there until shutdown — exactly the lifecycle a real
    //    `tunnel run` exhibits with no forwards configured.
    let orchestrator = Orchestrator::new();
    let mock = Arc::new(MockTunnelProtocol::new());
    orchestrator.start_profile(
        &cfg.profiles[0],
        mock.clone(),
        AuthConfig::new("alice", vec![]),
        vec![Endpoint::new("127.0.0.1", 22)],
        ProfileSupervisorConfig::default(),
    );

    // Give the supervisor a moment to drive at least one `connect()`.
    for _ in 0..40_u32 {
        if mock.connect_count() > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        mock.connect_count() >= 1,
        "expected supervisor to drive at least one connect, got {}",
        mock.connect_count()
    );
    assert_eq!(orchestrator.len(), 1, "profile should be registered");

    // 5. Verify status.json on disk.
    let status_path = paths::status_path(&state_dir);
    let raw = std::fs::read_to_string(&status_path).expect("read status.json");
    let v: serde_json::Value = serde_json::from_str(&raw).expect("status.json is valid JSON");
    let profiles = v
        .get("profiles")
        .and_then(|x| x.as_array())
        .expect("profiles array present");
    assert!(
        !profiles.is_empty(),
        "profiles[] should be non-empty after startup"
    );
    assert_eq!(profiles[0]["id"], "idle");

    // 6. Clean shutdown — this is the "SIGTERM → exit 0" equivalent.
    orchestrator.shutdown().await;
    assert!(orchestrator.is_empty(), "all profiles stopped after shutdown");

    // The state lock drops cleanly at end of scope.
    drop(lock);
}

#[tokio::test]
async fn shutdown_with_no_profiles_is_a_noop() {
    // Edge case: an orchestrator that was never asked to start any profile
    // shuts down cleanly. Catches accumulator-loop / hang regressions.
    let orchestrator = Orchestrator::new();
    orchestrator.shutdown().await;
    assert!(orchestrator.is_empty());
}
