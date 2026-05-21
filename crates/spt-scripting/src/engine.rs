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
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use rhai::packages::Package as _;
use tracing::{debug, warn};

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
        })
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
    pub fn invoke(&self, hook: HookName, event: &Event) -> Result<(), ScriptError> {
        let Some(fn_name) = self.hooks.function_for(hook) else {
            return Ok(());
        };
        if !self.declared_functions.contains(fn_name) {
            warn!(
                hook = %hook,
                function = fn_name,
                script = %self.path.display(),
                "spt-scripting: function declared in config is missing from script"
            );
            return Ok(());
        }

        // Serialise the structured event into a `rhai::Dynamic`. The
        // event payloads implement `serde::Serialize`, so we route via
        // `rhai::serde::to_dynamic` rather than hand-rolling a `CustomType`
        // impl for each payload.
        let payload = rhai::serde::to_dynamic(event).map_err(|e| ScriptError::HookFailed {
            hook: hook.to_string(),
            reason: format!("event serialisation: {e}"),
        })?;

        let started = Instant::now();
        // Fresh scope per call. Anything the previous invocation pushed is
        // gone; the only thing in scope is the `event` payload itself.
        let mut scope = rhai::Scope::new();
        let result: Result<rhai::Dynamic, _> =
            self.engine
                .call_fn(&mut scope, &self.ast, fn_name, (payload,));

        match result {
            Ok(_) => {
                let json = event.to_json();
                debug!(
                    hook = %hook,
                    function = fn_name,
                    elapsed_us = started.elapsed().as_micros() as u64,
                    "spt-scripting: invoked hook"
                );
                if let Ok(mut rec) = self.recorder.lock() {
                    rec.calls.push((hook, json));
                }
                Ok(())
            }
            Err(e) => {
                let err = classify_runtime_error(hook, &e);
                if let Ok(mut rec) = self.recorder.lock() {
                    rec.aborts.push((hook, err.to_string()));
                }
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
            .finish_non_exhaustive()
    }
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
}
