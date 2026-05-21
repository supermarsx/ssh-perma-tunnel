//! Error taxonomy for the scripting engine.

use std::path::PathBuf;

use spt_core::Error;
use thiserror::Error as ThisError;

/// Errors raised by [`crate::ScriptEngine`].
///
/// All variants map cleanly to [`spt_core::Error::InvalidConfig`] at load
/// time and to [`spt_core::Error::RuntimeFailure`] at invocation time
/// (since a script failure should not bring down the supervisor — the
/// session continues without the hook).
#[derive(Debug, ThisError)]
pub enum ScriptError {
    /// The configured script path could not be read from disk.
    #[error("script path `{path}` could not be read: {reason}")]
    ScriptUnreadable {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O reason.
        reason: String,
    },
    /// The script failed to compile (syntax error, forbidden symbol use,
    /// or violation of a `set_max_*` bound at AST construction).
    #[error("script `{path}` failed to compile: {reason}")]
    CompileFailed {
        /// Path of the offending script.
        path: PathBuf,
        /// Reason from the engine.
        reason: String,
    },
    /// A sandbox limit was tripped at runtime (operations / call levels /
    /// string size / array size / modules). The hook invocation is
    /// aborted and the session continues without the hook return value.
    #[error("script runtime limit hit in `{hook}`: {reason}")]
    LimitExceeded {
        /// Name of the hook that tripped the limit.
        hook: String,
        /// Reason from the engine.
        reason: String,
    },
    /// The script invoked a disabled symbol (`eval` / `import` / ...).
    #[error("script `{path}` uses disabled symbol `{symbol}`")]
    DisabledSymbol {
        /// Path of the offending script.
        path: PathBuf,
        /// Disabled symbol that was referenced.
        symbol: String,
    },
    /// A hook function raised an uncaught script-side error. The session
    /// continues; the error is logged and surfaced for tests.
    #[error("hook `{hook}` raised: {reason}")]
    HookFailed {
        /// Name of the hook that raised.
        hook: String,
        /// Reason from the engine.
        reason: String,
    },
}

impl ScriptError {
    /// Convert into the workspace-wide [`spt_core::Error`]. Load-time
    /// failures become [`Error::InvalidConfig`]; runtime failures become
    /// [`Error::RuntimeFailure`].
    #[must_use]
    pub fn into_core(self) -> Error {
        match &self {
            Self::ScriptUnreadable { .. }
            | Self::CompileFailed { .. }
            | Self::DisabledSymbol { .. } => Error::InvalidConfig(self.to_string()),
            Self::LimitExceeded { .. } | Self::HookFailed { .. } => {
                Error::RuntimeFailure(self.to_string())
            }
        }
    }
}

impl From<ScriptError> for Error {
    fn from(value: ScriptError) -> Self {
        value.into_core()
    }
}
