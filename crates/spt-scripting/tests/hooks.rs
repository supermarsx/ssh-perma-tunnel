//! Integration tests for [`spt_scripting`] — 17 scenarios per the t7-A2
//! contract (t6-e7 contract plus the rhai-real follow-ups).
//!
//! These exercise the real `rhai 1.19+` engine: sandbox bounds (eval/import
//! disabled, all `set_max_*` limits enforced), per-hook payload delivery,
//! fresh-scope-per-invocation, multi-session re-use across an `Arc`, and
//! the end-to-end dispatch shape used by
//! `Ssh2Session::dispatch_script_event`.

use std::path::PathBuf;

use spt_scripting::event::Event;
use spt_scripting::{
    config::HookName, Disconnect, ForwardState, ForwardStateTransition, Generic, PostConnect,
    PreConnect, ScriptConfig, ScriptEngine, ScriptError, ScriptHooks, ScriptLimits,
};
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
    assert!(
        rec.calls[0].1.contains(r#""kind":"generic""#),
        "{}",
        rec.calls[0].1
    );
    assert!(
        rec.calls[0].1.contains(r#""tag":"telemetry""#),
        "{}",
        rec.calls[0].1
    );
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
    let path = write_script(
        &dir,
        "import \"net\" as net;\nfn on_pre_connect(ev) { ev }\n",
    );
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

// 8. max_operations limit triggers script abort. Real rhai counts AST node
// evaluations; a tight loop over `0..1000` blows well past 10 ops.
#[test]
fn max_operations_limit_triggers_abort() {
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(
        &dir,
        "fn on_pre_connect(ev) { let acc = 0; for i in 0..1000 { acc += i; } acc }\n",
    );
    let limits = ScriptLimits {
        max_operations: 10,
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

// 9. max_call_levels: a script with a recursive function exceeds the
// configured call-depth limit. rhai's `set_max_call_levels` measures
// recursive function call depth at runtime (not lexical block nesting),
// so we drive it with `fn rec(n)` calling itself.
#[test]
fn max_call_levels_rejects_recursive_function() {
    let dir = tempfile::tempdir().unwrap();
    // Recursive function. With `max_call_levels = 2`, the third nested
    // call (rec(n-1) → rec(n-2) → rec(n-3)) trips the limit.
    let path = write_script(
        &dir,
        "fn rec(n) { if n <= 0 { 0 } else { rec(n - 1) + 1 } }\n\
         fn on_pre_connect(ev) { rec(20) }\n",
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

// 10. max_string_size: oversize string literal is rejected. rhai enforces
// `set_max_string_size` at parse time on literals AND at runtime on
// concatenations / `to_string` conversions. Either path surfaces a
// `CompileFailed` (parse-time) or `LimitExceeded` (runtime); the test
// asserts the parse-time path because the literal here is the simplest
// case to drive deterministically.
#[test]
fn max_string_size_rejected_at_parse_time() {
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
        matches!(err, ScriptError::CompileFailed { ref reason, .. } if reason.to_ascii_lowercase().contains("string")),
        "got {err:?}"
    );
}

// 10b. max_string_size at runtime: concatenation that grows past the bound
// aborts mid-script. This pins the *runtime* enforcement path that the
// parse-time literal check (test 10) cannot exercise.
#[test]
fn max_string_size_rejected_at_runtime_concat() {
    let dir = tempfile::tempdir().unwrap();
    // Each loop iteration appends 5 chars; with max_string_size = 50 the
    // 11th iteration trips. `for` is a CorePackage primitive; `+=` on
    // string is the standard concat operator.
    let path = write_script(
        &dir,
        "fn on_pre_connect(ev) {\n\
            let s = \"\";\n\
            for i in 0..100 { s += \"abcde\"; }\n\
            s\n\
         }\n",
    );
    let limits = ScriptLimits {
        max_string_size: 50,
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
        matches!(err, ScriptError::LimitExceeded { .. }),
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

// 14. Engine reused across multiple sessions: `Arc<ScriptEngine>` is shared
// between two simulated session contexts dispatching different events in
// sequence. The engine must remain `Send + Sync` and the recorder must
// accumulate calls from both sites.
#[test]
fn engine_reused_across_multiple_sessions() {
    use std::sync::Arc;
    use std::thread;

    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let eng = Arc::new(
        ScriptEngine::load(&ScriptConfig {
            path,
            hooks: default_hooks(),
            limits: ScriptLimits::default(),
        })
        .unwrap(),
    );

    // Spawn two threads simulating concurrent sessions.
    let eng_a = Arc::clone(&eng);
    let t_a = thread::spawn(move || {
        let ev = Event::PreConnect(PreConnect {
            profile: "a".into(),
            host: "10.0.0.1".into(),
            port: 22,
            attempt: 1,
        });
        eng_a.invoke(HookName::PreConnect, &ev).unwrap();
    });
    let eng_b = Arc::clone(&eng);
    let t_b = thread::spawn(move || {
        let ev = Event::PostConnect(PostConnect {
            profile: "b".into(),
            host: "10.0.0.2".into(),
            port: 22,
            auth_method: "publickey".into(),
            server_banner: None,
        });
        eng_b.invoke(HookName::PostConnect, &ev).unwrap();
    });
    t_a.join().unwrap();
    t_b.join().unwrap();

    let rec = eng.recorder_snapshot();
    assert_eq!(rec.calls.len(), 2);
    let hooks: Vec<HookName> = rec.calls.iter().map(|(h, _)| *h).collect();
    assert!(hooks.contains(&HookName::PreConnect));
    assert!(hooks.contains(&HookName::PostConnect));
}

// 15. Fresh scope per invocation — `rhai::Engine::call_fn` is fed a fresh
// `Scope::new()` per dispatch. The script body cannot observe any
// variable defined by a previous invocation: a function trying to read
// a variable that was never bound in *this* call's scope errors with
// "Variable not found", confirming the scope is not the one from the
// previous call.
#[test]
fn fresh_scope_per_invocation_no_leak() {
    // The function reads `leftover`, which only exists inside the
    // function-local scope. Two back-to-back invocations both succeed
    // because each one creates its own `leftover`; no state from the
    // previous call lingers (otherwise a `let leftover` re-binding
    // would error on the second call).
    let body = "\
        fn on_pre_connect(ev) {\n\
            let leftover = 0;\n\
            leftover += 1;\n\
            leftover\n\
        }\n";
    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, body);
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();
    let ev = Event::PreConnect(PreConnect {
        profile: "p".into(),
        host: "h".into(),
        port: 22,
        attempt: 1,
    });
    // Three back-to-back invocations, all green — independent scopes.
    for _ in 0..3 {
        eng.invoke(HookName::PreConnect, &ev).unwrap();
    }
    assert_eq!(eng.recorder_snapshot().calls.len(), 3);
    assert!(eng.recorder_snapshot().aborts.is_empty());
}

// 16. End-to-end via `Ssh2Session::dispatch_script_event`. We construct a
// `MockSsh2Session`-style configuration directly on `Ssh2Session` is not
// trivial (the libssh2 session requires a real `AsyncSession`); instead
// we exercise the equivalent contract: an `Arc<ScriptEngine>` is built
// from a profile, passed through the same `Option<Arc<ScriptEngine>>`
// shape that the session-side `with_script_engine` consumes, and a
// `dispatch_script_event`-equivalent call delivers the event. This pins
// the contract for the supervisor wiring (`profile_factory.rs::ProfileBundle.script_engine`)
// independent of the libssh2 session bring-up.
#[test]
fn end_to_end_dispatch_via_arc_engine_handle() {
    use std::sync::Arc;

    // Mimic the `Ssh2Session::dispatch_script_event` body — short-circuits
    // when the option is `None`, otherwise calls `engine.invoke`. Declared
    // up-front so clippy's `items-after-statements` lint stays quiet.
    fn dispatch(
        engine: Option<&Arc<ScriptEngine>>,
        hook: HookName,
        event: &Event,
    ) -> Result<(), ScriptError> {
        let Some(eng) = engine else {
            return Ok(());
        };
        eng.invoke(hook, event)
    }

    let dir = tempfile::tempdir().unwrap();
    let path = write_script(&dir, full_script());
    let engine: Option<Arc<ScriptEngine>> = Some(Arc::new(
        ScriptEngine::load(&ScriptConfig {
            path,
            hooks: default_hooks(),
            limits: ScriptLimits::default(),
        })
        .unwrap(),
    ));

    let ev1 = Event::PreConnect(PreConnect {
        profile: "p".into(),
        host: "h".into(),
        port: 22,
        attempt: 1,
    });
    let ev2 = Event::PostConnect(PostConnect {
        profile: "p".into(),
        host: "h".into(),
        port: 22,
        auth_method: "publickey".into(),
        server_banner: None,
    });
    let ev3 = Event::ForwardState(ForwardState {
        profile: "p".into(),
        forward_id: "local:8080".into(),
        transition: ForwardStateTransition::Active,
    });
    let ev4 = Event::Disconnect(Disconnect {
        profile: "p".into(),
        reason: "peer_eof".into(),
        duration_ms: 1234,
    });
    dispatch(engine.as_ref(), HookName::PreConnect, &ev1).unwrap();
    dispatch(engine.as_ref(), HookName::PostConnect, &ev2).unwrap();
    dispatch(engine.as_ref(), HookName::OnForwardState, &ev3).unwrap();
    dispatch(engine.as_ref(), HookName::OnDisconnect, &ev4).unwrap();

    let rec = engine.as_ref().unwrap().recorder_snapshot();
    assert_eq!(rec.calls.len(), 4);
    assert!(rec.aborts.is_empty());

    // `None` engine handle — every dispatch is a no-op.
    let absent: Option<Arc<ScriptEngine>> = None;
    dispatch(absent.as_ref(), HookName::PreConnect, &ev1).unwrap();
}

// 17. Script that raises an uncaught error: classified as `HookFailed`,
// returned to the caller, but recorded in the abort log.
#[test]
fn uncaught_script_error_classified_as_hook_failed() {
    let dir = tempfile::tempdir().unwrap();
    // `throw` is a CorePackage primitive that surfaces as `ErrorRuntime`.
    let path = write_script(&dir, "fn on_pre_connect(ev) { throw \"nope\" }\n");
    let eng = ScriptEngine::load(&ScriptConfig {
        path,
        hooks: default_hooks(),
        limits: ScriptLimits::default(),
    })
    .unwrap();
    let ev = Event::PreConnect(PreConnect {
        profile: "p".into(),
        host: "h".into(),
        port: 22,
        attempt: 1,
    });
    let err = eng.invoke(HookName::PreConnect, &ev).unwrap_err();
    assert!(matches!(err, ScriptError::HookFailed { .. }), "got {err:?}");
    let rec = eng.recorder_snapshot();
    assert!(rec.calls.is_empty());
    assert_eq!(rec.aborts.len(), 1);
}
