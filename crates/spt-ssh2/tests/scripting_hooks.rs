//! E8-F1 end-to-end: scripting lifecycle hooks fire on the real russh
//! connect / forward / disconnect paths.
//!
//! Before E8-F1, `dispatch_script_event` had zero production callers: the Rhai
//! engine was loaded and attached to every `Ssh2Session` but no lifecycle
//! boundary ever invoked it, so the entire `docs/scripting.md` surface was
//! inert. These tests drive a real russh↔russh session through
//! `Ssh2Protocol::connect` with a script engine attached and assert — via a
//! capturing audit sink — that the configured hooks actually run.

#![allow(clippy::missing_panics_doc)]

use std::sync::Arc;

use spt_auth::{AuthConfig, AuthMethod};
use spt_core::BindAddr;
use spt_protocol::{Endpoint, LocalForwardSpec, TargetAddr, TunnelProtocol};
use spt_scripting::audit::AuditEntry;
use spt_scripting::config::{HookName, ScriptConfig, ScriptHooks};
use spt_scripting::{HookOutcome, MockAuditSink, ScriptEngine};
use spt_ssh2::testing::RusshTestServer;
use spt_ssh2::Ssh2Protocol;

/// Build a script engine whose hook functions all exist (so each invocation
/// records `HookOutcome::Ok`) and attach a capturing audit sink. Returns the
/// engine and the sink so the test can inspect which hooks fired.
fn engine_with_all_hooks() -> (Arc<ScriptEngine>, Arc<MockAuditSink>) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("hooks.rhai");
    // Each hook just touches the event so the function body is non-trivial but
    // side-effect free (the sandbox forbids anything else).
    std::fs::write(
        &path,
        r"
fn pre(ev)  { ev.host }
fn post(ev) { ev.host }
fn fwd(ev)  { ev.forward_id }
fn down(ev) { ev.reason }
",
    )
    .expect("write script");

    let cfg = ScriptConfig {
        path,
        hooks: ScriptHooks {
            pre_connect: Some("pre".into()),
            post_connect: Some("post".into()),
            on_forward_state: Some("fwd".into()),
            on_disconnect: Some("down".into()),
            on_event: None,
        },
        limits: spt_scripting::config::ScriptLimits::default(),
    };
    let sink = Arc::new(MockAuditSink::new());
    let engine = ScriptEngine::load(&cfg)
        .expect("load script")
        .with_audit_sink(sink.clone());
    // The tempdir must outlive the engine read, which already happened in
    // `load` (the source is read once into the AST). Leak the dir guard for
    // the duration of the test by forgetting it.
    std::mem::forget(dir);
    (Arc::new(engine), sink)
}

/// Count how many times a given hook recorded an `Ok` invocation.
fn ok_invocations(sink: &MockAuditSink, want: HookName) -> usize {
    sink.entries()
        .into_iter()
        .filter(|e| {
            matches!(
                e,
                AuditEntry::Invoked { hook, outcome, .. }
                    if *hook == want && *outcome == HookOutcome::Ok
            )
        })
        .count()
}

#[tokio::test]
async fn script_hooks_fire_on_connect_forward_and_disconnect() {
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    std::env::set_var("SPT_TEST_SCRIPT_HOOKS_PW", "anything");

    let (engine, sink) = engine_with_all_hooks();
    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .script_engine(Some(engine))
        .profile_name(Some("edge".into()))
        .build();

    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_SCRIPT_HOOKS_PW".into()),
        }],
    );

    let mut session = proto
        .connect(&endpoint, &auth)
        .await
        .expect("russh backend connects");

    // pre_connect (fired before the dial) and post_connect (fired after auth)
    // must both have run exactly once for this single connect.
    assert_eq!(
        ok_invocations(&sink, HookName::PreConnect),
        1,
        "pre_connect hook must fire once on connect"
    );
    assert_eq!(
        ok_invocations(&sink, HookName::PostConnect),
        1,
        "post_connect hook must fire once after auth"
    );

    // Opening a local forward fires on_forward_state.
    let fwd = LocalForwardSpec {
        name: "web".into(),
        listen: BindAddr::TcpHostPort {
            host: "127.0.0.1".into(),
            port: 0,
        },
        target: TargetAddr {
            host: "127.0.0.1".into(),
            port: 80,
        },
        max_connections: None,
    };
    session
        .open_local_forward(&fwd)
        .await
        .expect("open local forward");
    assert!(
        ok_invocations(&sink, HookName::OnForwardState) >= 1,
        "on_forward_state hook must fire when a forward is opened"
    );

    // Closing the session fires on_disconnect.
    session.close().await.expect("close session");
    assert_eq!(
        ok_invocations(&sink, HookName::OnDisconnect),
        1,
        "on_disconnect hook must fire once on close"
    );

    server.shutdown().await;
}

#[tokio::test]
async fn no_script_engine_means_no_hook_invocations() {
    // Sanity check that the dispatch sites short-circuit cleanly when no
    // engine is attached (the common case): a session with no script engine
    // connects and closes without touching any audit sink.
    let server = RusshTestServer::new()
        .with_password("tester", "anything")
        .start()
        .await
        .expect("start russh server");
    std::env::set_var("SPT_TEST_SCRIPT_NOENGINE_PW", "anything");

    let proto = Ssh2Protocol::builder()
        .trust(spt_ssh2::testing::tofu_trust_verifier())
        .build();
    let endpoint = Endpoint::new("127.0.0.1", server.addr.port());
    let auth = AuthConfig::new(
        "tester",
        vec![AuthMethod::Password {
            secret: spt_auth::SecretRef::Env("SPT_TEST_SCRIPT_NOENGINE_PW".into()),
        }],
    );
    let session = proto.connect(&endpoint, &auth).await.expect("connects");
    session.close().await.expect("closes");
    server.shutdown().await;
}
