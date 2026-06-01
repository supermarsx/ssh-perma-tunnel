//! Error type for the updater. Kept narrow so callers can pattern-match
//! on the failure mode without crawling a 30-variant enum.

use thiserror::Error;

/// Updater-local errors. Most variants carry a free-text reason; the
/// `code()` accessor returns a stable string for telemetry / scripts.
#[derive(Debug, Error)]
pub enum UpdaterError {
    /// Failed to spawn the dedicated OS thread.
    #[error("spawn failed: {0}")]
    SpawnFailed(String),

    /// The updater thread has exited. Cannot deliver further requests.
    #[error("updater thread is no longer running")]
    ThreadGone,

    /// Release-source backend returned an error (HTTP / parse / pin).
    #[error("source: {0}")]
    Source(String),

    /// Artifact verification failed (signature / hash / format).
    #[error("verify: {0}")]
    Verify(String),

    /// Install-time failure (rename, permission, restart).
    #[error("install: {0}")]
    Install(String),

    /// Config-derived error surfaced at startup time.
    #[error("config: {0}")]
    Config(String),

    /// Generic I/O error wrapper.
    #[error("io: {0}")]
    Io(String),
}

impl UpdaterError {
    /// Stable telemetry code for the error kind.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::SpawnFailed(_) => "updater_spawn_failed",
            Self::ThreadGone => "updater_thread_gone",
            Self::Source(_) => "updater_source",
            Self::Verify(_) => "updater_verify",
            Self::Install(_) => "updater_install",
            Self::Config(_) => "updater_config",
            Self::Io(_) => "updater_io",
        }
    }
}

impl From<std::io::Error> for UpdaterError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

/// Updater-local Result alias.
pub type UpdaterResult<T> = std::result::Result<T, UpdaterError>;
