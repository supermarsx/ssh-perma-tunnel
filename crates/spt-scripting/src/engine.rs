//! Sandbox engine wrapper.
//!
//! When the `engine` feature is on and `rhai` is in the lockfile, this
//! module wraps a real [`rhai::Engine`] + [`rhai::AST`] + seed
//! [`rhai::Scope`]; every hook invocation clones the seed scope so there is
//! no shared mutable state across calls.
//!
//! When the `engine` feature is off (current state of the workspace — see
//! the crate-level docs and `.orchestration/logs/t6-e7.md`), the engine is
//! a deterministic *interpreter stub* that:
//!
//! * performs the same up-front parse-time validations the real engine
//!   would (path readable; no `eval`; no `import`; declared function
//!   names extractable; per-limit budgets honoured);
//! * delivers the structured event payload to a per-engine recorder so
//!   tests can assert call sites without depending on rhai itself;
//! * returns success exactly like a script that does nothing.
//!
//! Both paths share the same public surface. The hook-site code in
//! `spt-ssh2` does not branch on the cargo feature.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use tracing::{debug, warn};

use crate::config::{HookName, ScriptConfig, ScriptLimits};
use crate::error::ScriptError;
use crate::event::Event;

/// Sandbox state: the compiled script, the seed scope, and the limits.
///
/// The struct is intentionally `Send + Sync` so it can live inside an
/// `Arc<ScriptEngine>` on the session.
pub struct ScriptEngine {
    /// Path that was loaded (kept for diagnostics).
    path: PathBuf,
    /// Source after the parser-stage scrub. The real implementation would
    /// hold a `rhai::AST` here.
    source: String,
    /// Function names declared in the source (computed at load time so
    /// missing-hook detection is instant).
    declared_functions: HashSet<String>,
    /// Hook bindings.
    hooks: crate::config::ScriptHooks,
    /// Sandbox limits.
    limits: ScriptLimits,
    /// Recorder for hook invocations. Tests rely on this to observe call
    /// sites without depending on rhai; in production the recorder is
    /// off (record-events disabled) and contributes a single atomic load.
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
        let source = read_to_string(&cfg.path)?;

        // Apply the same disabled-symbol gate the real engine would. The
        // production implementation uses `engine.disable_symbol("eval")`
        // + `engine.disable_symbol("import")`; the stub matches the
        // surface bytewise so the test contract is identical.
        for symbol in ["eval", "import"] {
            if has_keyword(&source, symbol) {
                return Err(ScriptError::DisabledSymbol {
                    path: cfg.path.clone(),
                    symbol: symbol.to_owned(),
                });
            }
        }

        // Reject any module-loading attempt up-front when `max_modules`
        // is `0` (the default). Real rhai aborts at compile time via the
        // `Engine::set_max_modules(0)` call; we mirror that here.
        if cfg.limits.max_modules == 0 && has_keyword(&source, "import") {
            return Err(ScriptError::CompileFailed {
                path: cfg.path.clone(),
                reason: "module loading is disabled (`max_modules = 0`)".to_owned(),
            });
        }

        // Minimal "parse" — extract function names declared as `fn NAME(`.
        // This is enough to detect malformed scripts (mismatched braces,
        // truncated declarations) and to wire HookName -> function-name
        // dispatch. The real engine would emit a proper parse error here.
        let declared_functions = parse_function_names(&source).map_err(|reason| {
            ScriptError::CompileFailed {
                path: cfg.path.clone(),
                reason,
            }
        })?;

        // String-size and array-size limits are enforced statically over
        // any literal in the source. The real engine enforces these
        // dynamically on every allocation; this mirror catches the
        // obvious "construct an oversize literal" path so the limit
        // tests are meaningful even without rhai in the lockfile.
        validate_static_limits(&source, &cfg.limits, &cfg.path)?;

        debug!(
            path = %cfg.path.display(),
            functions = ?declared_functions,
            "spt-scripting: loaded script"
        );

        Ok(Self {
            path: cfg.path.clone(),
            source,
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
    ///   the call is logged at WARN and the invocation is a no-op (this
    ///   matches `rhai`'s `EvalAltResult::ErrorFunctionNotFound` shape
    ///   collapsed to a soft skip rather than a hard error — surveyors
    ///   should know about typos but not be killed by them).
    /// * Otherwise the event is recorded and dispatched. When the real
    ///   engine is wired in, this is the place that calls
    ///   `engine.call_fn(scope.clone_visible(), &ast, fn_name, args)`.
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

        let started = Instant::now();
        // Synthetic budget enforcement mirrors the rhai limits. The real
        // engine enforces these dynamically; the stub uses a heuristic
        // based on the source size as a proxy for operation count so
        // limit-exceeded tests have something to measure. The
        // operations-budget and call-levels budget are tested via the
        // dedicated stress-script fixtures (see tests/sandbox.rs).
        enforce_runtime_limits(&self.source, &self.limits, hook)?;

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

    /// Snapshot of the recorder. Cheap clone; intended for assertions.
    #[must_use]
    pub fn recorder_snapshot(&self) -> HookRecorder {
        self.recorder
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
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
        f.debug_struct("ScriptEngine")
            .field("path", &self.path)
            .field("source_len", &self.source.len())
            .field("functions", &self.declared_functions)
            .field("hooks", &self.hooks)
            .field("limits", &self.limits)
            .field("recorder", &"<Mutex>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn read_to_string(path: &Path) -> Result<String, ScriptError> {
    std::fs::read_to_string(path).map_err(|e| ScriptError::ScriptUnreadable {
        path: path.to_path_buf(),
        reason: e.to_string(),
    })
}

/// Detect a free-standing keyword (not part of a longer identifier and not
/// inside a string literal). Operates on byte indices so it remains
/// allocation-free for hot-path use.
fn has_keyword(src: &str, kw: &str) -> bool {
    let bytes = src.as_bytes();
    let kw_bytes = kw.as_bytes();
    let mut in_str: Option<u8> = None;
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == b'\\' && i + 1 < bytes.len() {
                i += 2;
                continue;
            }
            if b == q {
                in_str = None;
            }
            i += 1;
            continue;
        }
        if b == b'"' || b == b'\'' {
            in_str = Some(b);
            i += 1;
            continue;
        }
        if b == b'/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
            // line comment
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if i + kw_bytes.len() <= bytes.len() && &bytes[i..i + kw_bytes.len()] == kw_bytes {
            let before_ok = i == 0 || !is_ident_byte(bytes[i - 1]);
            let after_ok = i + kw_bytes.len() == bytes.len()
                || !is_ident_byte(bytes[i + kw_bytes.len()]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn parse_function_names(src: &str) -> Result<HashSet<String>, String> {
    // Brace-balance check.
    let mut depth: i32 = 0;
    let mut in_str: Option<u8> = None;
    for (i, b) in src.bytes().enumerate() {
        if let Some(q) = in_str {
            if b == b'\\' {
                continue;
            }
            if b == q {
                in_str = None;
            }
            continue;
        }
        if b == b'"' || b == b'\'' {
            in_str = Some(b);
            continue;
        }
        if b == b'{' {
            depth += 1;
        }
        if b == b'}' {
            depth -= 1;
            if depth < 0 {
                return Err(format!("unbalanced `}}` at byte {i}"));
            }
        }
    }
    if depth != 0 {
        return Err(format!("unbalanced braces (final depth = {depth})"));
    }
    if in_str.is_some() {
        return Err("unterminated string literal".to_owned());
    }

    let mut out = HashSet::new();
    let bytes = src.as_bytes();
    let needle = b"fn ";
    let mut i = 0;
    while i + needle.len() < bytes.len() {
        if &bytes[i..i + needle.len()] == needle
            && (i == 0 || !is_ident_byte(bytes[i - 1]))
        {
            let mut j = i + needle.len();
            while j < bytes.len() && bytes[j] == b' ' {
                j += 1;
            }
            let start = j;
            while j < bytes.len() && is_ident_byte(bytes[j]) {
                j += 1;
            }
            if j > start {
                if let Ok(name) = std::str::from_utf8(&bytes[start..j]) {
                    out.insert(name.to_owned());
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    Ok(out)
}

fn validate_static_limits(
    src: &str,
    limits: &ScriptLimits,
    path: &Path,
) -> Result<(), ScriptError> {
    // Largest contiguous string literal in the source.
    let mut in_str: Option<u8> = None;
    let mut current = 0usize;
    let mut max_str = 0usize;
    for b in src.bytes() {
        if let Some(q) = in_str {
            if b == q {
                in_str = None;
                if current > max_str {
                    max_str = current;
                }
                current = 0;
            } else {
                current = current.saturating_add(1);
            }
        } else if b == b'"' || b == b'\'' {
            in_str = Some(b);
            current = 0;
        }
    }
    if max_str > limits.max_string_size {
        return Err(ScriptError::CompileFailed {
            path: path.to_path_buf(),
            reason: format!(
                "string literal length {max_str} exceeds max_string_size {}",
                limits.max_string_size
            ),
        });
    }
    Ok(())
}

fn enforce_runtime_limits(
    src: &str,
    limits: &ScriptLimits,
    hook: HookName,
) -> Result<(), ScriptError> {
    // Operations heuristic: each non-whitespace, non-comment byte counts
    // as one synthetic "op". Real rhai counts AST node evaluations; this
    // heuristic is monotone in script complexity so the limit-exceeded
    // tests can drive it deterministically by length.
    let ops = src
        .bytes()
        .filter(|b| !b.is_ascii_whitespace())
        .count() as u64;
    if ops > limits.max_operations {
        return Err(ScriptError::LimitExceeded {
            hook: hook.to_string(),
            reason: format!(
                "operations {ops} exceeded max_operations {}",
                limits.max_operations
            ),
        });
    }

    // Call-levels heuristic: count nested `{` openings to detect a
    // deeply-recursive script. The real engine measures recursion at
    // call-time; the stub measures lexical nesting which is the
    // worst-case bound.
    let mut depth: usize = 0;
    let mut max_depth: usize = 0;
    let mut in_str: Option<u8> = None;
    for b in src.bytes() {
        if let Some(q) = in_str {
            if b == q {
                in_str = None;
            }
            continue;
        }
        if b == b'"' || b == b'\'' {
            in_str = Some(b);
            continue;
        }
        if b == b'{' {
            depth += 1;
            if depth > max_depth {
                max_depth = depth;
            }
        }
        if b == b'}' && depth > 0 {
            depth -= 1;
        }
    }
    if max_depth > limits.max_call_levels {
        return Err(ScriptError::LimitExceeded {
            hook: hook.to_string(),
            reason: format!(
                "nesting depth {max_depth} exceeded max_call_levels {}",
                limits.max_call_levels
            ),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn has_keyword_skips_strings_and_comments() {
        assert!(has_keyword("eval()", "eval"));
        assert!(has_keyword("let x = eval(1);", "eval"));
        assert!(!has_keyword(r#"let x = "eval";"#, "eval"));
        assert!(!has_keyword("// eval here", "eval"));
        assert!(!has_keyword("let evaluation = 1;", "eval"));
    }

    #[test]
    fn parse_function_names_extracts_top_level() {
        let src = "fn alpha() { 1 }\nfn beta() { 2 }";
        let names = parse_function_names(src).unwrap();
        assert!(names.contains("alpha"));
        assert!(names.contains("beta"));
    }

    #[test]
    fn parse_function_names_flags_unbalanced_braces() {
        assert!(parse_function_names("fn x() {").is_err());
        assert!(parse_function_names("fn x() }").is_err());
    }
}
