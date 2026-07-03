//! Real `rhai 1.19+` sandbox engine.
//!
//! This module wraps a [`rhai::Engine`] + compiled [`rhai::AST`] + a seed
//! [`rhai::Scope`]. Every hook invocation clones the seed scope so there is
//! no shared mutable state across calls — a fresh scope per dispatch.
//!
//! # Sandbox surface
//!
//! * Engine built via [`rhai::Engine::new_raw`] — *nothing* registered by
//!   default. We register exactly [`rhai::packages::CorePackage`] (arithmetic,
//!   comparison, string/array core); no filesystem, no network, no `eval`,
//!   no `import`, no module loading.
//! * `engine.disable_symbol("eval")` and `engine.disable_symbol("import")`
//!   are applied before [`rhai::Engine::compile`] so a script using either
//!   token fails at compile time.
//! * All five `engine.set_max_*` bounds from [`ScriptLimits`] are applied to
//!   the engine before AST registration.
//! * Each invocation runs against a cloned, empty scope; the AST-side
//!   `static` items are read-only after compilation, so hooks cannot retain
//!   state across calls.
//!
//! Malformed scripts are rejected at [`ScriptEngine::load`] time, mapped to
//! [`ScriptError::CompileFailed`] / [`ScriptError::DisabledSymbol`] /
//! [`ScriptError::ScriptUnreadable`].

use std::collections::HashSet;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rhai::packages::Package as _;
use sha2::{Digest as _, Sha256};
use tracing::{debug, warn};

use crate::audit::{AuditSink, HookOutcome, NoopAuditSink};
use crate::config::{HookName, ScriptConfig, ScriptLimits};
use crate::error::ScriptError;
use crate::event::Event;

/// Sandbox engine: compiled script + bounded `rhai::Engine`.
///
/// Cheap to clone via `Arc<ScriptEngine>` — the engine, AST, and limits live
/// behind the `Arc` and are shared across every session opened for the
/// owning profile.
pub struct ScriptEngine {
    path: PathBuf,
    engine: rhai::Engine,
    ast: rhai::AST,
    /// Function names declared in the AST. Cached at load time so the
    /// hook dispatcher can short-circuit (and emit a single WARN) for
    /// hook bindings that reference a missing function.
    declared_functions: HashSet<String>,
    hooks: crate::config::ScriptHooks,
    limits: ScriptLimits,
    /// In-process record of hook invocations. The audit layer (Phase B1)
    /// drains this; tests use [`Self::recorder_snapshot`] to assert call
    /// sites without spinning up a full session.
    recorder: Mutex<HookRecorder>,
    /// SHA-256 of the source bytes at load time. Carried into the
    /// `ScriptLoaded` audit event so subscribers can pin provenance
    /// across on-disk renames.
    source_sha256: [u8; 32],
    /// Audit subscriber. Defaults to [`NoopAuditSink`]; replaced via
    /// [`Self::with_audit_sink`]. The sink is fired:
    ///
    /// * Once at [`Self::with_audit_sink`] attach — retro-active
    ///   `on_loaded(path, sha256)` so subscribers added after load
    ///   still observe the load event.
    /// * Once at every [`Self::invoke`] call — `on_invoked(hook,
    ///   duration, outcome)`.
    audit_sink: Arc<dyn AuditSink>,
}

/// In-process record of hook invocations. Used by integration tests and
/// the audit layer alike.
#[derive(Debug, Default, Clone)]
pub struct HookRecorder {
    /// List of `(hook, json-event)` pairs in invocation order.
    pub calls: Vec<(HookName, String)>,
    /// List of `(hook, ScriptError-display)` for invocations that aborted.
    pub aborts: Vec<(HookName, String)>,
}

impl ScriptEngine {
    /// Build the engine, read + compile the script, apply sandbox limits.
    ///
    /// All validation happens here — by the time this function returns
    /// `Ok`, every subsequent [`Self::invoke`] is allowed to assume the
    /// AST and limits are well-formed. Errors are reported as
    /// [`ScriptError::ScriptUnreadable`] / [`ScriptError::CompileFailed`]
    /// / [`ScriptError::DisabledSymbol`].
    pub fn load(cfg: &ScriptConfig) -> Result<Self, ScriptError> {
        let source =
            std::fs::read_to_string(&cfg.path).map_err(|e| ScriptError::ScriptUnreadable {
                path: cfg.path.clone(),
                reason: e.to_string(),
            })?;
        let source_sha256: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(source.as_bytes());
            hasher.finalize().into()
        };

        // `Engine::new_raw` registers ZERO packages by default — no
        // filesystem, no network, no print, no debug. We then layer the
        // Core package on top to give scripts arithmetic / comparison /
        // string / array primitives. Anything beyond Core (Standard,
        // Arithmetic, BasicArray, …) is deliberately omitted: scripts can
        // read event fields, do math, and return — they cannot touch the
        // outside world.
        let mut engine = rhai::Engine::new_raw();
        engine.register_global_module(rhai::packages::CorePackage::new().as_shared_module());

        // Apply all sandbox limits before compilation so the parser also
        // honours them (rhai enforces some at parse time, e.g. literal
        // length bounds are not enforced statically but the
        // `max_modules = 0` setting refuses `import` at parse time).
        engine.set_max_operations(cfg.limits.max_operations);
        engine.set_max_call_levels(cfg.limits.max_call_levels);
        engine.set_max_string_size(cfg.limits.max_string_size);
        engine.set_max_array_size(cfg.limits.max_array_size);
        engine.set_max_modules(cfg.limits.max_modules);

        // Belt-and-braces: disable the dangerous symbols explicitly so
        // even if a future rhai release re-enables them by default, our
        // sandbox stays intact.
        engine.disable_symbol("eval");
        engine.disable_symbol("import");

        let ast = engine
            .compile(&source)
            .map_err(|e| classify_compile_error(&cfg.path, &e))?;

        let declared_functions: HashSet<String> =
            ast.iter_functions().map(|f| f.name.to_string()).collect();

        debug!(
            path = %cfg.path.display(),
            functions = ?declared_functions,
            "spt-scripting: loaded script"
        );

        Ok(Self {
            path: cfg.path.clone(),
            engine,
            ast,
            declared_functions,
            hooks: cfg.hooks.clone(),
            limits: cfg.limits,
            recorder: Mutex::new(HookRecorder::default()),
            source_sha256,
            audit_sink: Arc::new(NoopAuditSink),
        })
    }

    /// Attach an audit subscriber. Default is [`NoopAuditSink`].
    ///
    /// The sink is consumed by [`Self::load`] and [`Self::invoke`] — both
    /// fire through the sink so the audit layer (Phase B1 of t7) can
    /// record per-script provenance and per-hook duration / outcome.
    ///
    /// The `on_loaded` event is fired retro-actively at the moment the
    /// sink is attached so a subscriber added after the engine is
    /// constructed still observes the load event with the correct SHA.
    #[must_use]
    pub fn with_audit_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        sink.on_loaded(&self.path, &self.source_sha256);
        self.audit_sink = sink;
        self
    }

    /// SHA-256 of the source bytes captured at load time. Exposed for
    /// tests and for downstream audit subscribers that want to
    /// re-correlate load events.
    #[must_use]
    pub fn source_sha256(&self) -> [u8; 32] {
        self.source_sha256
    }

    /// Dispatch a single hook invocation.
    ///
    /// * If `hook` is not configured (`function_for == None`), this
    ///   returns immediately without allocating.
    /// * If the configured function name is not declared in the script,
    ///   the call is logged at WARN and the invocation is a no-op — a
    ///   typo in the hook binding should not kill the session.
    /// * Otherwise the event is serialised to a [`rhai::Dynamic`] via
    ///   `rhai::serde::to_dynamic`, a *fresh* scope is built (no carry-over
    ///   across invocations), and the function is invoked through
    ///   [`rhai::Engine::call_fn`]. The return value is ignored — hooks
    ///   are fire-and-forget by design.
    ///
    /// Sandbox-limit violations and uncaught script-side errors are
    /// surfaced to the caller; the session-side dispatcher in
    /// `Ssh2Session::dispatch_script_event` logs and *continues* (a script
    /// failure must not bring down the supervisor).
    ///
    /// # `on_event` catch-all (wire-observ finding 5)
    ///
    /// The `on_event` hook is the generic catch-all. Previously it had **no
    /// call site** and never fired. Now every specific lifecycle dispatch
    /// (`pre_connect` / `post_connect` / `on_forward_state` / `on_disconnect`)
    /// **also** fires `on_event` — when, and only when, a script binds it —
    /// with a [`crate::event::Generic`] projection of the same event. The
    /// catch-all runs after the specific hook and never masks or alters the
    /// specific hook's `Result`; its own failure is recorded (recorder / audit
    /// sink) and logged at debug. When `on_event` is unbound the behaviour is
    /// byte-identical to before (no extra invocation).
    pub fn invoke(&self, hook: HookName, event: &Event) -> Result<(), ScriptError> {
        let primary = self.invoke_hook(hook, event);
        // Fire the generic catch-all in addition to the specific hook — but not
        // for an `on_event` dispatch itself (avoids double-fire / recursion),
        // and only when the script actually binds `on_event`.
        if hook != HookName::OnEvent && self.hooks.function_for(HookName::OnEvent).is_some() {
            let generic = Event::Generic(event.as_generic());
            if let Err(e) = self.invoke_hook(HookName::OnEvent, &generic) {
                tracing::debug!(
                    primary_hook = %hook,
                    error = %e,
                    "spt-scripting: on_event catch-all hook failed (primary hook result preserved)"
                );
            }
        }
        primary
    }

    /// Dispatch a single hook invocation for exactly `hook` (no catch-all).
    fn invoke_hook(&self, hook: HookName, event: &Event) -> Result<(), ScriptError> {
        let started = Instant::now();
        let Some(fn_name) = self.hooks.function_for(hook) else {
            self.audit_sink
                .on_invoked(hook, started.elapsed(), HookOutcome::Skipped);
            return Ok(());
        };
        if !self.declared_functions.contains(fn_name) {
            warn!(
                hook = %hook,
                function = fn_name,
                script = %self.path.display(),
                "spt-scripting: function declared in config is missing from script"
            );
            self.audit_sink
                .on_invoked(hook, started.elapsed(), HookOutcome::Skipped);
            return Ok(());
        }

        // Serialise the structured event into a `rhai::Dynamic`. The
        // event payloads implement `serde::Serialize`, so we route via
        // `rhai::serde::to_dynamic` rather than hand-rolling a `CustomType`
        // impl for each payload.
        let payload = match rhai::serde::to_dynamic(event) {
            Ok(p) => p,
            Err(e) => {
                let err = ScriptError::HookFailed {
                    hook: hook.to_string(),
                    reason: format!("event serialisation: {e}"),
                };
                self.audit_sink
                    .on_invoked(hook, started.elapsed(), HookOutcome::Err);
                return Err(err);
            }
        };

        // Fresh scope per call. Anything the previous invocation pushed is
        // gone; the only thing in scope is the `event` payload itself.
        let mut scope = rhai::Scope::new();
        // t8-A2: wrap the rhai FFI boundary in `catch_unwind`. rhai handles
        // most script-level errors via `Result<…, EvalAltResult>`, but
        // host-registered callbacks (the operator-supplied `register_fn`
        // surface — exposed in this engine only at compile-time as the Core
        // package, but extensible via future audit hooks) can panic. A
        // panic that crosses the rhai call boundary aborts the process when
        // the host opts into `-C panic=abort`; we catch it here and surface
        // a clean `ScriptError::HookFailed` so the supervisor stays up.
        let result: Result<Result<rhai::Dynamic, Box<rhai::EvalAltResult>>, _> =
            catch_unwind(AssertUnwindSafe(|| {
                self.engine
                    .call_fn(&mut scope, &self.ast, fn_name, (payload,))
            }));
        let result: Result<rhai::Dynamic, _> = match result {
            Ok(r) => r,
            Err(panic) => {
                let elapsed = started.elapsed();
                let msg = panic_string(&panic);
                let err = ScriptError::HookFailed {
                    hook: hook.to_string(),
                    reason: format!(
                        "panic across the rhai FFI boundary: {msg}. \
                         Investigate any host-registered functions invoked \
                         from this hook for stray `unwrap`/`expect`."
                    ),
                };
                if let Ok(mut rec) = self.recorder.lock() {
                    rec.aborts.push((hook, err.to_string()));
                }
                self.audit_sink.on_invoked(hook, elapsed, HookOutcome::Err);
                return Err(err);
            }
        };

        match result {
            Ok(_) => {
                let elapsed = started.elapsed();
                let json = event.to_json();
                debug!(
                    hook = %hook,
                    function = fn_name,
                    elapsed_us = elapsed.as_micros() as u64,
                    "spt-scripting: invoked hook"
                );
                if let Ok(mut rec) = self.recorder.lock() {
                    rec.calls.push((hook, json));
                }
                self.audit_sink.on_invoked(hook, elapsed, HookOutcome::Ok);
                Ok(())
            }
            Err(e) => {
                let elapsed = started.elapsed();
                let err = classify_runtime_error(hook, &e);
                if let Ok(mut rec) = self.recorder.lock() {
                    rec.aborts.push((hook, err.to_string()));
                }
                self.audit_sink.on_invoked(hook, elapsed, HookOutcome::Err);
                Err(err)
            }
        }
    }

    /// Snapshot of the recorder. Cheap clone; intended for assertions.
    #[must_use]
    pub fn recorder_snapshot(&self) -> HookRecorder {
        self.recorder.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Path of the script this engine was built from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Sandbox limits in force.
    #[must_use]
    pub fn limits(&self) -> ScriptLimits {
        self.limits
    }

    /// Test-only: register a host-side function that, when called from a
    /// loaded script, panics with the supplied message.
    ///
    /// Exists to let `t8-A2` exercise the `catch_unwind` panic-recovery
    /// boundary inside [`Self::invoke`] without piping a real FFI surface
    /// (libgssapi / sspi / Dokan / fuser) through the test harness. The
    /// production engine never registers panicking functions — production
    /// scripts use the bounded [`rhai::packages::CorePackage`] only.
    #[cfg(test)]
    pub(crate) fn register_panic_fn_for_tests(&mut self, name: &str, msg: &'static str) {
        self.engine
            .register_fn(name, move || -> rhai::Dynamic { panic!("{msg}") });
    }
}

impl std::fmt::Debug for ScriptEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `rhai::Engine` and `rhai::AST` are intentionally elided — both are
        // large opaque types whose `Debug` would dump the entire compiled
        // bytecode. The remaining fields fully describe the configuration
        // surface a test or audit subscriber cares about.
        f.debug_struct("ScriptEngine")
            .field("path", &self.path)
            .field("functions", &self.declared_functions)
            .field("hooks", &self.hooks)
            .field("limits", &self.limits)
            .field("recorder", &"<Mutex>")
            .field("source_sha256", &hex_short(&self.source_sha256))
            .field("audit_sink", &self.audit_sink)
            .finish_non_exhaustive()
    }
}

fn hex_short(bytes: &[u8; 32]) -> String {
    // Render the first 8 bytes as hex; full digest is available via
    // `source_sha256()`. The shortened form keeps log lines compact.
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

fn classify_compile_error(path: &Path, err: &rhai::ParseError) -> ScriptError {
    let msg = err.to_string();
    // `disable_symbol("eval")` causes the rhai parser to emit a "disabled
    // operator/token" diagnostic when `eval` appears as a call site, and
    // `set_max_modules(0)` causes `import` to surface as a "reserved
    // keyword" diagnostic (rhai treats `import` as a parser-level keyword
    // gated by the `no_module` configuration). Catch both shapes and
    // collapse them into `DisabledSymbol` so the audit / config layers can
    // distinguish sandbox violations from generic syntax errors.
    let lowered = msg.to_ascii_lowercase();
    for symbol in ["eval", "import"] {
        if lowered.contains(symbol)
            && (lowered.contains("disabled")
                || lowered.contains("improper")
                || lowered.contains("not allowed")
                || lowered.contains("reserved keyword"))
        {
            return ScriptError::DisabledSymbol {
                path: path.to_path_buf(),
                symbol: (*symbol).to_owned(),
            };
        }
    }
    ScriptError::CompileFailed {
        path: path.to_path_buf(),
        reason: msg,
    }
}

/// t8-A2: extract a human-readable string from a `catch_unwind` payload.
///
/// `std::panic::catch_unwind` returns `Box<dyn Any + Send>` whose concrete
/// type is either `String` (when the user panicked with `panic!("{}", …)`),
/// `&'static str` (when the user panicked with a string literal), or
/// something more exotic (custom panic types). We render the first two
/// shapes verbatim; everything else falls through to a stable marker
/// string so the operator-facing diagnostic isn't truncated.
fn panic_string(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<String>() {
        return s.clone();
    }
    if let Some(s) = p.downcast_ref::<&'static str>() {
        return (*s).to_string();
    }
    "(non-string panic payload)".to_string()
}

fn classify_runtime_error(hook: HookName, err: &rhai::EvalAltResult) -> ScriptError {
    // Sandbox-limit violations map to LimitExceeded; everything else is a
    // hook failure (uncaught script-side error, type mismatch, …).
    use rhai::EvalAltResult as E;
    let reason = err.to_string();
    let limit_kind: Option<&'static str> = match err {
        E::ErrorTooManyOperations(_) => Some("max_operations"),
        E::ErrorStackOverflow(_) => Some("max_call_levels"),
        E::ErrorDataTooLarge(_, _) => Some("max_string_size/max_array_size"),
        E::ErrorTooManyModules(_) => Some("max_modules"),
        _ => None,
    };
    if let Some(kind) = limit_kind {
        return ScriptError::LimitExceeded {
            hook: hook.to_string(),
            reason: format!("{kind}: {reason}"),
        };
    }
    ScriptError::HookFailed {
        hook: hook.to_string(),
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScriptHooks;
    use crate::event::PreConnect;

    fn write(dir: &tempfile::TempDir, body: &str) -> PathBuf {
        let p = dir.path().join("h.rhai");
        std::fs::write(&p, body).unwrap();
        p
    }

    fn hooks_pre(name: &str) -> ScriptHooks {
        ScriptHooks {
            pre_connect: Some(name.to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn load_extracts_declared_functions() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, "fn alpha(ev) { ev }\nfn beta(ev) { ev }\n");
        let eng = ScriptEngine::load(&ScriptConfig {
            path: p,
            hooks: ScriptHooks::default(),
            limits: ScriptLimits::default(),
        })
        .unwrap();
        assert!(eng.declared_functions.contains("alpha"));
        assert!(eng.declared_functions.contains("beta"));
    }

    #[test]
    fn invoke_with_missing_function_softskips() {
        let dir = tempfile::tempdir().unwrap();
        let p = write(&dir, "fn other(ev) { ev }\n");
        let eng = ScriptEngine::load(&ScriptConfig {
            path: p,
            hooks: hooks_pre("not_present"),
            limits: ScriptLimits::default(),
        })
        .unwrap();
        let ev = Event::PreConnect(PreConnect {
            profile: "p".into(),
            host: "h".into(),
            port: 22,
            attempt: 1,
        });
        // Missing fn → soft skip, no error, no recorder entry.
        eng.invoke(HookName::PreConnect, &ev).unwrap();
        assert!(eng.recorder_snapshot().calls.is_empty());
    }

    // t7-B1: audit-sink integration ----------------------------------------

    fn sample_event() -> Event {
        Event::PreConnect(PreConnect {
            profile: "p".into(),
            host: "h".into(),
            port: 22,
            attempt: 1,
        })
    }

    /// `ScriptEngine::load` computes a SHA-256 of the source bytes and
    /// surfaces it via the public accessor. Attaching a sink fires a
    /// retro-active `on_loaded` with the captured hash.
    #[test]
    fn load_captures_sha256_of_source() {
        use crate::audit::AuditEntry;
        let dir = tempfile::tempdir().unwrap();
        let body = "fn pre(ev) { ev }\n";
        let path = write(&dir, body);
        let eng = ScriptEngine::load(&ScriptConfig {
            path: path.clone(),
            hooks: ScriptHooks::default(),
            limits: ScriptLimits::default(),
        })
        .unwrap();
        let expected: [u8; 32] = {
            let mut hasher = Sha256::new();
            hasher.update(body.as_bytes());
            hasher.finalize().into()
        };
        assert_eq!(eng.source_sha256(), expected);

        let sink = Arc::new(crate::audit::MockAuditSink::new());
        let eng = eng.with_audit_sink(sink.clone());
        let entries = sink.entries();
        assert_eq!(entries.len(), 1);
        match &entries[0] {
            AuditEntry::Loaded { path: p, sha256 } => {
                assert_eq!(p, &path);
                assert_eq!(sha256, &expected);
            }
            AuditEntry::Invoked { .. } => panic!("expected Loaded entry"),
        }
        drop(eng);
    }

    /// `invoke` fires `on_invoked` with `HookOutcome::Ok` when the hook
    /// runs cleanly.
    #[test]
    fn invoke_records_duration_and_ok_outcome() {
        use crate::audit::{AuditEntry, HookOutcome};
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn pre(ev) { ev }\n");
        let sink = Arc::new(crate::audit::MockAuditSink::new());
        let eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: hooks_pre("pre"),
            limits: ScriptLimits::default(),
        })
        .unwrap()
        .with_audit_sink(sink.clone());
        eng.invoke(HookName::PreConnect, &sample_event()).unwrap();

        // 1 load + 1 invoke.
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        match &entries[1] {
            AuditEntry::Invoked { hook, outcome, .. } => {
                assert_eq!(*hook, HookName::PreConnect);
                assert_eq!(*outcome, HookOutcome::Ok);
            }
            AuditEntry::Loaded { .. } => panic!("expected Invoked entry"),
        }
    }

    /// A hook that throws surfaces as `HookOutcome::Err` through the
    /// audit sink.
    #[test]
    fn invoke_records_err_outcome_when_hook_throws() {
        use crate::audit::{AuditEntry, HookOutcome};
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn pre(ev) { throw \"boom\"; }\n");
        let sink = Arc::new(crate::audit::MockAuditSink::new());
        let eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: hooks_pre("pre"),
            limits: ScriptLimits::default(),
        })
        .unwrap()
        .with_audit_sink(sink.clone());
        let err = eng
            .invoke(HookName::PreConnect, &sample_event())
            .expect_err("hook throws");
        assert!(matches!(err, ScriptError::HookFailed { .. }));

        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        match &entries[1] {
            AuditEntry::Invoked { outcome, .. } => {
                assert_eq!(*outcome, HookOutcome::Err);
            }
            AuditEntry::Loaded { .. } => panic!("expected Invoked entry"),
        }
    }

    // ──────── t8-A2: panic-recovery across the rhai FFI boundary ──────

    /// `panic_string` extracts both `String` and `&'static str` payloads.
    #[test]
    fn panic_string_handles_common_payloads() {
        let s_payload: Box<dyn std::any::Any + Send> = Box::new(String::from("boom"));
        assert_eq!(panic_string(&s_payload), "boom");
        let static_payload: Box<dyn std::any::Any + Send> = Box::new("static");
        assert_eq!(panic_string(&static_payload), "static");
        // Anything else falls through to the placeholder so the operator
        // diagnostic isn't truncated.
        let other: Box<dyn std::any::Any + Send> = Box::new(42_u64);
        assert_eq!(panic_string(&other), "(non-string panic payload)");
    }

    /// A host-registered callback that panics inside `rhai::Engine::call_fn`
    /// surfaces as `ScriptError::HookFailed` carrying the panic message —
    /// the panic does **not** unwind past the engine boundary and abort the
    /// process.
    #[test]
    fn rhai_panic_in_callback_surfaces_as_runtime_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn pre(ev) { boom() }\n");
        let mut eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: hooks_pre("pre"),
            limits: ScriptLimits::default(),
        })
        .unwrap();
        eng.register_panic_fn_for_tests("boom", "host callback exploded");

        let err = eng
            .invoke(HookName::PreConnect, &sample_event())
            .expect_err("panic must surface as ScriptError");
        match err {
            ScriptError::HookFailed { hook, reason } => {
                assert_eq!(hook, "pre_connect");
                assert!(
                    reason.contains("panic across the rhai FFI boundary"),
                    "expected panic-boundary marker; got: {reason}",
                );
                assert!(
                    reason.contains("host callback exploded"),
                    "expected panic payload to be carried; got: {reason}",
                );
            }
            other => panic!("expected HookFailed, got {other:?}"),
        }
    }

    /// The panicking callback's outcome is reported through the audit sink
    /// as `HookOutcome::Err` (mirrors the throw-from-script path) — that
    /// is the operator-visible signal the supervisor uses to count hook
    /// failures.
    #[test]
    fn rhai_panic_records_err_outcome_through_audit_sink() {
        use crate::audit::{AuditEntry, HookOutcome};
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn pre(ev) { boom() }\n");
        let sink = Arc::new(crate::audit::MockAuditSink::new());
        let mut eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: hooks_pre("pre"),
            limits: ScriptLimits::default(),
        })
        .unwrap()
        .with_audit_sink(sink.clone());
        eng.register_panic_fn_for_tests("boom", "kaboom");
        let _ = eng.invoke(HookName::PreConnect, &sample_event());

        let entries = sink.entries();
        // 1 load + 1 invoke.
        assert_eq!(entries.len(), 2);
        match &entries[1] {
            AuditEntry::Invoked { outcome, .. } => {
                assert_eq!(*outcome, HookOutcome::Err);
            }
            AuditEntry::Loaded { .. } => panic!("expected Invoked entry"),
        }
    }

    // ──────── wire-observ finding 5: on_event catch-all ──────────────

    /// With `on_event` bound, invoking a *specific* lifecycle hook ALSO fires
    /// `on_event` with a `Generic` projection. Pre-fix `on_event` had no call
    /// site and this recorded only the specific hook.
    #[test]
    fn on_event_catch_all_fires_on_lifecycle_hook() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn pre(ev) { ev }\nfn any(ev) { ev }\n");
        let eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: ScriptHooks {
                pre_connect: Some("pre".into()),
                on_event: Some("any".into()),
                ..Default::default()
            },
            limits: ScriptLimits::default(),
        })
        .unwrap();
        eng.invoke(HookName::PreConnect, &sample_event()).unwrap();
        let calls = eng.recorder_snapshot().calls;
        assert!(
            calls.iter().any(|(h, _)| *h == HookName::PreConnect),
            "specific hook must still fire: {calls:?}"
        );
        let on_event = calls
            .iter()
            .find(|(h, _)| *h == HookName::OnEvent)
            .expect("on_event catch-all must fire on the lifecycle event");
        // The catch-all receives a Generic projection tagged with the variant.
        assert!(
            on_event.1.contains("pre_connect"),
            "payload: {}",
            on_event.1
        );
    }

    /// When `on_event` is NOT bound, a specific-hook invocation fires only that
    /// hook — behaviour is byte-identical to before the catch-all wiring.
    #[test]
    fn on_event_not_fired_when_unbound() {
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn pre(ev) { ev }\n");
        let eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: hooks_pre("pre"),
            limits: ScriptLimits::default(),
        })
        .unwrap();
        eng.invoke(HookName::PreConnect, &sample_event()).unwrap();
        let calls = eng.recorder_snapshot().calls;
        assert_eq!(
            calls.len(),
            1,
            "only the specific hook should fire: {calls:?}"
        );
        assert_eq!(calls[0].0, HookName::PreConnect);
    }

    /// A direct `on_event` dispatch does not recurse / double-fire.
    #[test]
    fn direct_on_event_dispatch_fires_once() {
        use crate::event::Generic;
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn any(ev) { ev }\n");
        let eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: ScriptHooks {
                on_event: Some("any".into()),
                ..Default::default()
            },
            limits: ScriptLimits::default(),
        })
        .unwrap();
        let ev = Event::Generic(Generic {
            profile: "p".into(),
            kind: "custom".into(),
            payload_json: "{}".into(),
        });
        eng.invoke(HookName::OnEvent, &ev).unwrap();
        let calls = eng.recorder_snapshot().calls;
        assert_eq!(calls.len(), 1, "on_event must fire exactly once: {calls:?}");
        assert_eq!(calls[0].0, HookName::OnEvent);
    }

    /// Soft-skip path (configured hook with no function body) reports
    /// `HookOutcome::Skipped`.
    #[test]
    fn invoke_records_skipped_when_function_missing() {
        use crate::audit::{AuditEntry, HookOutcome};
        let dir = tempfile::tempdir().unwrap();
        let path = write(&dir, "fn other(ev) { ev }\n");
        let sink = Arc::new(crate::audit::MockAuditSink::new());
        let eng = ScriptEngine::load(&ScriptConfig {
            path,
            hooks: hooks_pre("not_present"),
            limits: ScriptLimits::default(),
        })
        .unwrap()
        .with_audit_sink(sink.clone());
        eng.invoke(HookName::PreConnect, &sample_event()).unwrap();
        let entries = sink.entries();
        assert_eq!(entries.len(), 2);
        match &entries[1] {
            AuditEntry::Invoked { outcome, .. } => {
                assert_eq!(*outcome, HookOutcome::Skipped);
            }
            AuditEntry::Loaded { .. } => panic!("expected Invoked entry"),
        }
    }
}
