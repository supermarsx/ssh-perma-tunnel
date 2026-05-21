//! Integration tests for [`spt_scripting`] — 13 scenarios per t6-e7 plan.
//!
//! These tests exercise the engine surface against the stub interpreter
//! that ships when `rhai` is absent from the lockfile. When the dep is
//! added in a follow-up, the test inputs (script bodies, event payloads)
//! remain valid for the real engine — only the engine module body changes.

use std::path::PathBuf;

use spt_scripting::{
    config::HookName, Disconnect, ForwardState, ForwardStateTransition, Generic, PostConnect,
    PreConnect, ScriptConfig, ScriptEngine, ScriptError, ScriptHooks, ScriptLimits,
};
use spt_scripting::event::Event;
use tempfile::TempDir;

fn write_script(dir: &TempDir, body: &str) -> PathBuf {
    let path = dir.path().join("hooks.rhai");
    std::fs::write(&path, body).unwrap();
    path
}

fn default_hooks() -> ScriptHooks {
    ScriptHooks {
        pre_connect: Some("on_pre_connect".into()),
        post_connect: Some("on_post_connect".into()),
        on_forward_state: Some("on_forward".into()),
        on_disconnect: Some("on_disc".into()),
        on_event: Some("on_any".into()),
    }
}

fn full_script() -> &'static str {
    r"
fn on_pre_connect(ev) { ev }
fn on_post_connect(ev) { ev }
fn on_forward(ev) { ev }
fn on_disc(ev) { ev }
fn on_any(ev) { ev }
"
}

// 1. pre_connect hook fires with host/port event payload
#[test]
fn pre_connect_fires_with_host_and_port_payload() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();

    let ev = Event::PreConnect(PreConnect {
        profile: "edge".into(),
        host: "203.0.113.7".into(),
        port: 22,
        attempt: 1,
    });
    eng.invoke(HookName::PreConnect, &ev).unwrap();

    let rec = eng.recorder_snapshot();
    assert_eq!(rec.calls.len(), 1);
    assert_eq!(rec.calls[0].0, HookName::PreConnect);
    assert!(rec.calls[0].1.contains(r#""host":"203.0.113.7""#));
    assert!(rec.calls[0].1.contains(r#""port":22"#));
}

// 2. post_connect hook fires with auth-method tag
#[test]
fn post_connect_fires_with_auth_method_tag() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();
    let ev = Event::PostConnect(PostConnect {
        profile: "edge".into(),
        host: "203.0.113.7".into(),
        port: 22,
        auth_method: "publickey".into(),
        server_banner: Some("SSH-2.0-OpenSSH_9.6".into()),
    });
    eng.invoke(HookName::PostConnect, &ev).unwrap();
    let rec = eng.recorder_snapshot();
    assert_eq!(rec.calls.len(), 1);
    assert!(rec.calls[0].1.contains(r#""auth_method":"publickey""#));
}

// 3. on_forward_state delivers state-machine transitions
#[test]
fn on_forward_state_delivers_transitions() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();
    for t in [
        ForwardStateTransition::Listening,
        ForwardStateTransition::Active,
        ForwardStateTransition::Paused,
        ForwardStateTransition::Closed,
    ] {
        let ev = Event::ForwardState(ForwardState {
            profile: "edge".into(),
            forward_id: "local:8080".into(),
            transition: t,
        });
        eng.invoke(HookName::OnForwardState, &ev).unwrap();
    }
    let rec = eng.recorder_snapshot();
    assert_eq!(rec.calls.len(), 4);
    assert!(rec.calls[0].1.contains(r#""transition":"listening""#));
    assert!(rec.calls[1].1.contains(r#""transition":"active""#));
    assert!(rec.calls[2].1.contains(r#""transition":"paused""#));
    assert!(rec.calls[3].1.contains(r#""transition":"closed""#));
}

// 4. on_disconnect fires with reason code + duration
#[test]
fn on_disconnect_fires_with_reason_and_duration() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();
    let ev = Event::Disconnect(Disconnect {
        profile: "edge".into(),
        reason: "keepalive_timeout".into(),
        duration_ms: 12_345,
    });
    eng.invoke(HookName::OnDisconnect, &ev).unwrap();
    let rec = eng.recorder_snapshot();
    assert_eq!(rec.calls.len(), 1);
    assert!(rec.calls[0].1.contains(r#""reason":"keepalive_timeout""#));
    assert!(rec.calls[0].1.contains(r#""duration_ms":12345"#));
}

// 5. on_event generic delivery
#[test]
fn on_event_generic_delivery() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();
    let ev = Event::Generic(Generic {
        profile: "edge".into(),
        kind: "telemetry".into(),
        payload_json: r#"{"latency_ms":42}"#.into(),
    });
    eng.invoke(HookName::OnEvent, &ev).unwrap();
    let rec = eng.recorder_snapshot();
    assert_eq!(rec.calls.len(), 1);
    // Outer-enum discriminator emits `"kind":"generic"`; the inner `tag`
    // carries the free-form telemetry tag.
    assert!(rec.calls[0].1.contains(r#""kind":"generic""#), "{}", rec.calls[0].1);
    assert!(rec.calls[0].1.contains(r#""tag":"telemetry""#), "{}", rec.calls[0].1);
}

// 6. sandbox blocks `eval`
#[test]
fn sandbox_blocks_eval() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, "fn on_pre_connect(ev) { eval(\"1+1\") }\n");
    let err = ScriptEngine::load(&ScriptConfig {
        path: path.clone(),
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap_err();
    assert!(
        matches!(err, ScriptError::DisabledSymbol { ref symbol, .. } if symbol == "eval"),
        "got {err:?}"
    );
}

// 7. sandbox blocks `import`
#[test]
fn sandbox_blocks_import() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, "import \"net\" as net;\nfn on_pre_connect(ev) { ev }\n");
    let err = ScriptEngine::load(&ScriptConfig {
        path: path.clone(),
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap_err();
    assert!(
        matches!(err, ScriptError::DisabledSymbol { ref symbol, .. } if symbol == "import"),
        "got {err:?}"
    );
}

// 8. max_operations limit triggers script abort
#[test]
fn max_operations_limit_triggers_abort() {
    let dir = tempfile::tempdir().unwrap();
    // Script with ~120 non-whitespace bytes; limit is set just under that.
    let path = write_script(
        &dir,
        "fn on_pre_connect(ev) { let acc = 0; for i in 0..1000 { acc += i; } acc }\n",
    );
    let limits = ScriptLimits {
        max_operations: 10, // far below the source-byte count
        ..ScriptLimits::default()
    };
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits,
    })
    .unwrap();
    let ev = Event::PreConnect(PreConnect {
        profile: "p".into(),
        host: "h".into(),
        port: 22,
        attempt: 1,
    });
    let err = eng.invoke(HookName::PreConnect, &ev).unwrap_err();
    assert!(
        matches!(err, ScriptError::LimitExceeded { ref reason, .. } if reason.contains("max_operations")),
        "got {err:?}"
    );
}

// 9. max_call_levels: deeply nested / recursive script aborted.
//
// NOTE — stub behaviour: the stub interpreter enforces this limit by
// counting lexical brace nesting, which is the worst-case bound on
// runtime call depth. When the real `rhai::Engine` is wired in, this
// limit additionally catches recursive `fn rec() { rec() }`-style
// scripts at call time — that runtime path cannot be exercised against
// the stub. See `.orchestration/logs/t6-e7.md` for the framing.
#[test]
fn max_call_levels_rejects_deeply_nested_blocks() {
    let dir = tempfile::tempdir().unwrap();
    // Lexical nesting depth = 6. Set limit to 2.
    let path = write_script(
        &dir,
        "fn on_pre_connect(ev) { { { { { { ev } } } } } }\n",
    );
    let limits = ScriptLimits {
        max_call_levels: 2,
        max_operations: 1_000_000_000,
        ..ScriptLimits::default()
    };
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits,
    })
    .unwrap();
    let ev = Event::PreConnect(PreConnect {
        profile: "p".into(),
        host: "h".into(),
        port: 22,
        attempt: 1,
    });
    let err = eng.invoke(HookName::PreConnect, &ev).unwrap_err();
    assert!(
        matches!(err, ScriptError::LimitExceeded { ref reason, .. } if reason.contains("max_call_levels")),
        "got {err:?}"
    );
}

// 10. max_string_size: oversize string allocation rejected at load
#[test]
fn max_string_size_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let big = "a".repeat(2000);
    let src = format!("fn on_pre_connect(ev) {{ let s = \"{big}\"; ev }}\n");
    let path = write_script(&dir, &src);
    let limits = ScriptLimits {
        max_string_size: 100,
        ..ScriptLimits::default()
    };
    let err = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits,
    })
    .unwrap_err();
    assert!(
        matches!(err, ScriptError::CompileFailed { ref reason, .. } if reason.contains("max_string_size")),
        "got {err:?}"
    );
}

// 11. malformed script returns config error at LOAD (not at first invocation)
#[test]
fn malformed_script_errors_at_load_not_invocation() {
    let dir = tempfile::tempdir().unwrap();
    // Unbalanced braces.
    let path = write_script(&dir, "fn on_pre_connect(ev) { let x = 1; \n");
    let err = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap_err();
    assert!(
        matches!(err, ScriptError::CompileFailed { .. }),
        "got {err:?}"
    );
    // Surface as InvalidConfig at the core boundary.
    let core_err: spt_core::Error = err.into();
    assert!(
        matches!(core_err, spt_core::Error::InvalidConfig(_)),
        "got {core_err:?}"
    );
}

// 12. script absent in config: hooks are no-ops, no allocation
#[test]
fn script_absent_in_config_hooks_are_noops() {
    // The "absent" path is exercised at the caller (Option<Arc<ScriptEngine>>
    // == None). Here we assert that a present engine with zero configured
    // hooks also no-ops without panic and without recording calls.
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, "fn other() { 1 }\n");
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: ScriptHooks::default(), // every field None
        limits: ScriptLimits::default(),
    })
    .unwrap();
    let ev = Event::PreConnect(PreConnect {
        profile: "p".into(),
        host: "h".into(),
        port: 22,
        attempt: 1,
    });
    eng.invoke(HookName::PreConnect, &ev).unwrap();
    eng.invoke(HookName::PostConnect, &ev).unwrap();
    eng.invoke(HookName::OnForwardState, &ev).unwrap();
    eng.invoke(HookName::OnDisconnect, &ev).unwrap();
    eng.invoke(HookName::OnEvent, &ev).unwrap();
    assert!(eng.recorder_snapshot().calls.is_empty());
}

// Sandbox MUST: each hook runs against a *fresh* scope clone — no shared
// mutable state across invocations. Today (rhai absent) we verify the
// observable contract: invoking the same hook twice with different events
// records the *second* event verbatim, with no residue of the first. When
// the real engine lands this test extends to assert `scope.clone_visible()`
// is what's passed to `engine.call_fn` so a script that does
// `static_counter += 1` cannot retain state across calls.
#[test]
fn hook_invocations_carry_per_call_event_payload_with_no_residue() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();
    let ev1 = Event::PreConnect(PreConnect {
        profile: "edge".into(),
        host: "10.0.0.1".into(),
        port: 22,
        attempt: 1,
    });
    let ev2 = Event::PreConnect(PreConnect {
        profile: "edge".into(),
        host: "10.0.0.2".into(),
        port: 2222,
        attempt: 2,
    });
    eng.invoke(HookName::PreConnect, &ev1).unwrap();
    eng.invoke(HookName::PreConnect, &ev2).unwrap();
    let rec = eng.recorder_snapshot();
    assert_eq!(rec.calls.len(), 2);
    // Second invocation contains exactly the second event's host/port, with
    // no carry-over of the first.
    assert!(rec.calls[1].1.contains(r#""host":"10.0.0.2""#));
    assert!(rec.calls[1].1.contains(r#""port":2222"#));
    assert!(!rec.calls[1].1.contains(r#""host":"10.0.0.1""#));
}

// 13. ScriptConfig schema deser: minimal + full forms round-trip
#[test]
fn script_config_schema_deser_minimal_and_full() {
    // Minimal: path only.
    let minimal_json = r#"{"path":"/tmp/x.rhai"}"#;
    let m: ScriptConfig = serde_json::from_str(minimal_json).unwrap();
    assert_eq!(m.path, PathBuf::from("/tmp/x.rhai"));
    assert!(m.hooks.is_empty());
    assert_eq!(m.limits, ScriptLimits::default());

    // Full form with every field present.
    let full_json = r#"{
        "path":"/tmp/y.rhai",
        "hooks": {
            "pre_connect":"a","post_connect":"b","on_forward_state":"c",
            "on_disconnect":"d","on_event":"e"
        },
        "limits": {
            "max_operations": 100,
            "max_call_levels": 4,
            "max_string_size": 1024,
            "max_array_size": 64,
            "max_modules": 0
        }
    }"#;
    let f: ScriptConfig = serde_json::from_str(full_json).unwrap();
    assert_eq!(f.hooks.pre_connect.as_deref(), Some("a"));
    assert_eq!(f.hooks.on_event.as_deref(), Some("e"));
    assert_eq!(f.limits.max_operations, 100);
    assert_eq!(f.limits.max_call_levels, 4);

    // Round-trip: serialise full form and re-deser.
    let back_json = serde_json::to_string(&f).unwrap();
    let back: ScriptConfig = serde_json::from_str(&back_json).unwrap();
    assert_eq!(back, f);
}
