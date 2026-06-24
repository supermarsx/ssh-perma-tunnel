//! e2e (Wave F): self-update flow (check → download → verify → install)
//! driven against the in-process [`spt_updater::testing::MockReleaseSource`]
//! with **no network**, plus the event-sink fan-out (`event test` / `event
//! replay` shape) firing a synthetic event through real, hermetic sinks.
//!
//! ## What is real here
//!
//! * **Update flow.** The mock source returns a fake "available release" whose
//!   single artifact is a `file://` URL to bytes staged in a tempdir. That
//!   drives the *real* `download::download_release` (its `file://` branch), the
//!   *real* `verify::verify_artifact` (SHA-256 fail-closed semantics), and the
//!   *real* `install::install_over` (a non-running target file swap; cfg(unix)
//!   mode preservation). Installing over the *running* exe is not testable
//!   directly, so we install over a non-running temp target via the exposed
//!   `install_over`, exactly as the crate's own `apply_tests` do.
//! * **Event sinks.** We build sinks through the real `spt_events::build_sink`
//!   (the same seam the CLI's `event_sink_fire` helper uses) and fire a
//!   synthetic event through: an **http/webhook sink** at a loopback HTTP
//!   receiver (real `ReqwestTransport`), asserting the POST body carries the
//!   event; a **command sink** running a harmless OS command (real
//!   `ProcessRunner`) whose templated argument creates a marker file, asserting
//!   the event field was interpolated and the process ran; and a **capturing
//!   (in-memory) sink** for an isolation check. Per-sink errors are isolated: a
//!   deliberately-misconfigured sink reports an error while its siblings still
//!   deliver.
//!
//! All hermetic: ephemeral loopback ports, a loopback HTTP receiver, tempdirs
//! under the OS temp dir, bounded waits. cfg(unix)-gated assertions: the
//! install-over mode-preservation check and the 0600-ish perms note for the
//! Linux gate.

#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use secrecy::ExposeSecret as _;
use spt_config::schema::{EventCommand, EventSink};
use spt_events::event::{EventBuilder, EventKind, Severity};
use spt_events::sinks::command::ProcessRunner;
use spt_events::sinks::http::{HttpTransport, RecordingTransport};
use spt_events::testing::CapturingSink;
use spt_events::{build_sink, Sink, SinkDeps};
use spt_secrets::testing::MemoryBackend;
use spt_secrets::{Resolver, SecretBackend};
use spt_updater::config::{
    ActionConfig, ReleaseChannel, ScheduleKind, SourceKind, StagingConfig, UpdaterConfig,
    VerifyConfig,
};
use spt_updater::source::ReleaseSource;
use spt_updater::testing::{MockChecksum, MockReleaseSource};
use spt_updater::{download, install, verify, version, UpdateMode};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// A unique scratch directory under the OS temp dir (this crate has no
/// `tempfile` dev-dep, so we roll a process+counter-unique path and clean up
/// at the end of each test).
fn scratch(tag: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let n = SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "spt-e2e-{tag}-{}-{}-{n}",
        std::process::id(),
        // nanos for extra collision-resistance across runs
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn synthetic_event() -> Arc<spt_events::event::Event> {
    Arc::new(
        EventBuilder::new(EventKind::new("synthetic.test"), Severity::Info)
            .field("marker", "wave-f-42")
            .message("synthetic event from update_eventsink e2e")
            .build(),
    )
}

fn verify_inputs(staged: &download::Staged) -> verify::VerifyInputs {
    verify::VerifyInputs {
        expected_sha256: staged.expected_sha256.clone(),
        sha256sums_body: staged.sha256sums.clone(),
        artifact_name: Some(staged.name.clone()),
    }
}

fn best_effort_verify() -> VerifyConfig {
    VerifyConfig {
        require_minisign: false,
        minisign_pubkey: None,
        require_sha256sums: false,
        gpg_pubkey: None,
    }
}

// ===========================================================================
// Wave F — self-update flow against the mock source
// ===========================================================================

/// `check`: the mock source surfaces a fake newer release; `poll_once`-style
/// version comparison reports it as available. Driven through the public
/// `ReleaseSource::latest` + `version` API with no network.
#[tokio::test]
async fn update_check_detects_newer_release() {
    let src_dir = scratch("upd-check");
    // `99.0` is unconditionally newer than any real build version.
    let src =
        MockReleaseSource::staged(&src_dir, "99.0", b"NEWBIN", MockChecksum::Correct).unwrap();

    let release = src.latest().await.expect("mock latest");
    assert_eq!(
        src.call_count(),
        1,
        "flow must poll the source exactly once"
    );

    let latest = version::Version::parse_tag(&release.tag).expect("parse tag");
    let current = version::CurrentVersion::from_build();
    assert!(
        latest.is_newer_than(&current.0),
        "99.0 must be newer than the current build {}",
        current.0.to_tag_string()
    );

    let _ = std::fs::remove_dir_all(&src_dir);
}

/// `check` skip: a not-newer release (`0.0`) must NOT be flagged as an update.
#[tokio::test]
async fn update_check_skips_when_not_newer() {
    let src_dir = scratch("upd-skip");
    let src = MockReleaseSource::staged(&src_dir, "0.0", b"OLD", MockChecksum::Correct).unwrap();
    let release = src.latest().await.unwrap();
    let latest = version::Version::parse_tag(&release.tag).unwrap();
    let current = version::CurrentVersion::from_build();
    assert!(
        !latest.is_newer_than(&current.0),
        "0.0 must not be newer than the current build"
    );
    let _ = std::fs::remove_dir_all(&src_dir);
}

/// `download` + `verify` (correct checksum): the staged artifact is downloaded
/// from the mock source's `file://` URL and passes SHA-256 verification.
#[tokio::test]
async fn update_download_and_verify_passes_with_matching_checksum() {
    let src_dir = scratch("upd-dlok-src");
    let stage_dir = scratch("upd-dlok-stage");
    let body = b"NEW BINARY BYTES (verified)";
    let src = MockReleaseSource::staged(&src_dir, "99.0", body, MockChecksum::Correct).unwrap();

    let release = src.latest().await.unwrap();
    let staged = download::download_release(&release, download::TARGET, &stage_dir)
        .await
        .expect("download staged artifact");
    assert!(staged.artifact.exists(), "artifact must be staged on disk");
    assert_eq!(std::fs::read(&staged.artifact).unwrap(), body);

    // Strict checksum verification must pass with the published true digest.
    let mut cfg = best_effort_verify();
    cfg.require_sha256sums = true;
    verify::verify_artifact(&cfg, &staged.artifact, None, &verify_inputs(&staged))
        .expect("verify must pass for matching checksum");

    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&stage_dir);
}

/// `verify` fail-closed: a release whose published checksum is WRONG must be
/// rejected (the AEAD/SHA mismatch path) — no install proceeds.
#[tokio::test]
async fn update_verify_fails_closed_on_wrong_checksum() {
    let src_dir = scratch("upd-bad-src");
    let stage_dir = scratch("upd-bad-stage");
    let src = MockReleaseSource::staged(&src_dir, "99.0", b"bytes", MockChecksum::Wrong).unwrap();

    let release = src.latest().await.unwrap();
    let staged = download::download_release(&release, download::TARGET, &stage_dir)
        .await
        .unwrap();

    // Even in best-effort mode, a *present-but-wrong* digest must fail.
    let err = verify::verify_artifact(
        &best_effort_verify(),
        &staged.artifact,
        None,
        &verify_inputs(&staged),
    )
    .expect_err("wrong checksum must fail closed");
    assert_eq!(err.code(), "updater_verify", "must be a verify error");

    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&stage_dir);
}

/// `verify` strict fail-closed: `require_sha256sums = true` with NO published
/// digest must refuse to install.
#[tokio::test]
async fn update_verify_fails_closed_when_required_but_absent() {
    let src_dir = scratch("upd-none-src");
    let stage_dir = scratch("upd-none-stage");
    let src = MockReleaseSource::staged(&src_dir, "99.0", b"x", MockChecksum::None).unwrap();
    let release = src.latest().await.unwrap();
    let staged = download::download_release(&release, download::TARGET, &stage_dir)
        .await
        .unwrap();

    let mut cfg = best_effort_verify();
    cfg.require_sha256sums = true;
    let err = verify::verify_artifact(&cfg, &staged.artifact, None, &verify_inputs(&staged))
        .expect_err("strict verify must fail when no digest published");
    assert_eq!(err.code(), "updater_verify");

    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&stage_dir);
}

/// Full `check → download → verify → install` over a NON-running temp target,
/// driven end-to-end with the mock source. The running-exe swap is not
/// testable directly, so we install over a sham target file via `install_over`
/// (mirrors the crate's own `apply_tests`). cfg(unix): the target's mode is
/// preserved across the swap.
#[tokio::test]
async fn update_full_flow_installs_over_non_running_target() {
    let src_dir = scratch("upd-full-src");
    let stage_dir = scratch("upd-full-stage");
    let body = b"NEW BINARY BYTES";
    let src = MockReleaseSource::staged(&src_dir, "99.0", body, MockChecksum::Correct).unwrap();

    // check
    let release = src.latest().await.unwrap();
    let latest = version::Version::parse_tag(&release.tag).unwrap();
    assert!(latest.is_newer_than(&version::CurrentVersion::from_build().0));

    // download
    let staged = download::download_release(&release, download::TARGET, &stage_dir)
        .await
        .unwrap();

    // verify (strict, matching checksum)
    let mut vcfg = best_effort_verify();
    vcfg.require_sha256sums = true;
    verify::verify_artifact(&vcfg, &staged.artifact, None, &verify_inputs(&staged)).unwrap();

    // install over a non-running target carrying OLD bytes
    let target = stage_dir.join("installed-spt");
    std::fs::write(&target, b"OLD CONTENT").unwrap();

    #[cfg(unix)]
    let mode_before = {
        use std::os::unix::fs::PermissionsExt as _;
        // Make the target executable so we can assert the mode is preserved.
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).unwrap();
        0o755u32
    };

    install::install_over(&staged.artifact, &target)
        .await
        .expect("install over non-running target");
    assert_eq!(
        std::fs::read(&target).unwrap(),
        body,
        "target must now contain the new bytes"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode_after = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode_after, mode_before,
            "install_over must preserve the target's unix mode"
        );
    }

    let _ = std::fs::remove_dir_all(&src_dir);
    let _ = std::fs::remove_dir_all(&stage_dir);
}

/// A failing source surfaces a clean error from the check stage — no panic,
/// no install.
#[tokio::test]
async fn update_source_error_is_clean() {
    let src = MockReleaseSource::failing("simulated network failure");
    let err = src.latest().await.expect_err("must surface source error");
    assert!(
        format!("{err}").contains("simulated network failure"),
        "error must carry the source message: {err}"
    );
}

/// The full-config plumbing builds without I/O — proves the mock release fits
/// an `UpdaterConfig`-shaped flow (the `Auto` mode that `apply_update` drives).
#[test]
fn updater_config_with_static_source_is_constructable() {
    let cfg = UpdaterConfig {
        enabled: true,
        mode: UpdateMode::Auto,
        schedule: ScheduleKind::Interval(Duration::from_secs(60)),
        source: SourceKind::GitHub {
            repo: "owner/repo".into(),
            channel: ReleaseChannel::Stable,
        },
        verify: best_effort_verify(),
        action: ActionConfig {
            restart_supervisor: false,
            notify_audit: false,
            post_install_hook: None,
        },
        staging: StagingConfig {
            dir: None,
            keep_last: 1,
        },
        window: None,
    };
    assert_eq!(cfg.mode, UpdateMode::Auto);
    assert!(cfg.enabled);
}

// ===========================================================================
// Wave F — event-sink fan-out (`event test` / `event replay` shape)
// ===========================================================================

/// Spawn a one-shot loopback HTTP receiver that accepts a single request,
/// captures its raw body, and replies `200 OK`. Returns the bound `http://`
/// URL and a oneshot receiver yielding the captured body bytes.
async fn spawn_http_receiver() -> (String, tokio::sync::oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind receiver");
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/events");
    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();
    tokio::spawn(async move {
        if let Ok((mut sock, _)) = listener.accept().await {
            // Read the request, then locate the body after the header break.
            let mut buf = Vec::new();
            let mut chunk = [0u8; 2048];
            // Read until we have headers + (best-effort) the whole body.
            loop {
                match tokio::time::timeout(Duration::from_secs(2), sock.read(&mut chunk)).await {
                    Ok(Ok(0) | Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => {
                        buf.extend_from_slice(&chunk[..n]);
                        // Once we have the declared content-length worth of
                        // body, capture it and stop reading.
                        if body_complete(&buf) {
                            if let Some(body) = http_body(&buf) {
                                let _ = tx.send(body.to_vec());
                            }
                            break;
                        }
                    }
                }
            }
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = sock.flush().await;
        }
    });
    (url, rx)
}

/// Return the body slice following the `\r\n\r\n` header terminator, if seen.
fn http_body(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| &buf[p + 4..])
}

/// Heuristic: the body is complete when its length reaches the declared
/// `Content-Length` (falls back to "any body present" when absent).
fn body_complete(buf: &[u8]) -> bool {
    let text = String::from_utf8_lossy(buf);
    let declared = text
        .lines()
        .find_map(|l| {
            let l = l.to_ascii_lowercase();
            l.strip_prefix("content-length:")
                .map(|v| v.trim().parse::<usize>().ok())
        })
        .flatten();
    match (http_body(buf), declared) {
        (Some(body), Some(len)) => body.len() >= len,
        (Some(body), None) => !body.is_empty(),
        _ => false,
    }
}

/// The http/webhook sink (built through the real `build_sink`) POSTs the event
/// to a loopback receiver, which records the body. Asserts the event made it
/// through onto the wire.
#[tokio::test]
async fn event_http_sink_delivers_to_loopback_receiver() {
    let (url, rx) = spawn_http_receiver().await;

    let sink_cfg = EventSink {
        name: "alerts".into(),
        kind: "webhook_post".into(),
        url: Some(url),
        // The default body template (`{{event}}`) is a literal placeholder;
        // render the real event fields so the receiver sees the data.
        body_template: Some(r#"{"kind":"{{kind}}","marker":"{{marker}}"}"#.into()),
        ..Default::default()
    };
    let resolver = Resolver::new(vec![]);
    // Real reqwest-backed HTTP transport (no pin, default timeout).
    let http = spt_events::sinks::http::reqwest_transport::ReqwestTransport::with_pin(
        Duration::from_secs(5),
        &[],
        false,
        Some(5),
    )
    .expect("build reqwest transport");
    let deps = SinkDeps::none().with_http(Arc::new(http) as Arc<dyn HttpTransport>);

    let sink = build_sink(&sink_cfg, &[], &deps, &resolver).expect("build http sink");
    sink.deliver(synthetic_event())
        .await
        .expect("http sink delivers");

    let body = tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .expect("receiver got a request in time")
        .expect("receiver body");
    let text = String::from_utf8_lossy(&body);
    assert!(
        text.contains("synthetic.test") && text.contains("wave-f-42"),
        "loopback receiver must see the event JSON; got: {text}"
    );
}

/// The command sink (built through the real `build_sink`, real `ProcessRunner`)
/// runs a harmless OS command whose templated argument names a marker file;
/// the file's existence proves the process ran with the event interpolated.
#[tokio::test]
async fn event_command_sink_runs_harmless_command_with_event() {
    let dir = scratch("evt-cmd");
    // The marker path embeds a templated event field so we also prove arg
    // interpolation reached the spawned process.
    let marker = dir.join("fired-{{kind}}.marker");
    let marker_tmpl = marker.to_string_lossy().to_string();

    // A harmless, always-present OS command that creates the marker file.
    // The marker path carries `{{kind}}`, so a successful run proves both that
    // the process executed and that the event field was interpolated.
    // `copy /y nul <file>` creates a 0-byte file and exits 0 with no shell
    // redirection (which `tokio`'s arg-quoting would otherwise mangle).
    #[cfg(windows)]
    let (program, args) = (
        "cmd".to_string(),
        vec![
            "/C".to_string(),
            "copy".to_string(),
            "/y".to_string(),
            "nul".to_string(),
            marker_tmpl.clone(),
        ],
    );
    #[cfg(unix)]
    let (program, args) = (
        "/bin/sh".to_string(),
        vec!["-c".to_string(), format!("printf '' > '{marker_tmpl}'")],
    );

    let cmd_entry = EventCommand {
        name: "notify".into(),
        command: program,
        args: Some(args),
        allow_exec: Some(true),
        timeout: Some("10s".into()),
    };
    let sink_cfg = EventSink {
        name: "notify".into(),
        kind: "command".into(),
        ..Default::default()
    };
    let resolver = Resolver::new(vec![]);
    let deps =
        SinkDeps::none().with_command(
            Arc::new(ProcessRunner) as Arc<dyn spt_events::sinks::command::CommandRunner>
        );

    let sink = build_sink(
        &sink_cfg,
        std::slice::from_ref(&cmd_entry),
        &deps,
        &resolver,
    )
    .expect("build command sink");
    sink.deliver(synthetic_event())
        .await
        .expect("command sink runs");

    // The template `{{kind}}` interpolates to `synthetic.test`.
    let fired = dir.join("fired-synthetic.test.marker");
    assert!(
        fired.exists(),
        "command must have created the marker {} (templated from the event)",
        fired.display()
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// Per-sink error isolation: a deliberately-misconfigured sink reports an error
/// while a good in-memory sink still delivers — modelling the `event test`
/// fan-over-sinks loop that records a per-sink result without aborting.
#[tokio::test]
async fn event_per_sink_errors_are_isolated() {
    let resolver = Resolver::new(vec![]);
    let evt = synthetic_event();

    // Good: an in-memory capturing sink (always succeeds).
    let capturing = CapturingSink::new("capture");
    capturing
        .deliver(Arc::clone(&evt))
        .await
        .expect("capturing sink delivers");
    assert_eq!(capturing.len(), 1, "capturing sink recorded the event");

    // Bad: an http sink with NO url is a construction error, reported per-sink
    // (stringified), not a panic — exactly how the CLI isolates failures.
    let bad_cfg = EventSink {
        name: "bad".into(),
        kind: "http".into(),
        ..Default::default()
    };
    let deps = SinkDeps::none();
    let built = build_sink(&bad_cfg, &[], &deps, &resolver);
    let err = match built {
        Ok(_) => panic!("misconfigured http sink must error"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("url"),
        "error must explain the missing url: {err}"
    );

    // The good sink's delivery is unaffected by the bad sink's failure.
    assert_eq!(capturing.len(), 1);
}

/// A `secret://` reference in a sink's `auth` resolves through the real
/// resolver chain (in-memory backend) when building the sink — proving the
/// `build_sink` secret-resolution seam works end-to-end.
#[tokio::test]
async fn event_sink_resolves_secret_auth_reference() {
    let (url, rx) = spawn_http_receiver().await;

    // Seed a bearer token behind a `secret://events/token` reference.
    let secret_ref = spt_secrets::SecretRef::new("events", "token").unwrap();
    let backend: Arc<dyn SecretBackend> = Arc::new(MemoryBackend::with_entry(
        secret_ref,
        b"s3cr3t-token".to_vec(),
    ));
    let resolver = Resolver::new(vec![backend]);

    let sink_cfg = EventSink {
        name: "secured".into(),
        kind: "http".into(),
        url: Some(url),
        auth: Some("secret://events/token".into()),
        ..Default::default()
    };
    // Use a RecordingTransport so we can assert the resolved bearer token
    // reached the request without a live server validating it.
    let recorder = Arc::new(RecordingTransport::new());
    let deps = SinkDeps::none().with_http(recorder.clone() as Arc<dyn HttpTransport>);

    let sink = build_sink(&sink_cfg, &[], &deps, &resolver).expect("build secured http sink");
    sink.deliver(synthetic_event())
        .await
        .expect("secured sink delivers");

    let reqs = recorder.requests();
    assert_eq!(reqs.len(), 1, "exactly one request recorded");
    match &reqs[0].auth {
        spt_events::sinks::http::HttpAuth::Bearer(tok) => {
            assert_eq!(
                tok, "s3cr3t-token",
                "resolved secret must be the bearer token"
            );
        }
        other => panic!("expected Bearer auth from resolved secret, got {other:?}"),
    }

    // Drain the (unused) receiver so the spawned task can exit cleanly.
    drop(rx);
}

/// Sanity: the secret expose path returns the raw token (guards the resolver
/// wiring used above).
#[test]
fn secret_backend_exposes_seeded_token() {
    let secret_ref = spt_secrets::SecretRef::new("events", "token").unwrap();
    let backend = MemoryBackend::with_entry(secret_ref.clone(), b"abc123".to_vec());
    let got = backend.get(&secret_ref).unwrap().unwrap();
    assert_eq!(got.expose_secret().as_slice(), b"abc123");
}

// Silence unused-import warnings on platforms where a cfg path doesn't use them.
#[allow(dead_code)]
fn _assert_send(_p: &Path) {}
