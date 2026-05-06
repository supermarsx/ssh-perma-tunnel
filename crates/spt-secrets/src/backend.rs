//! Backend trait and shared types.

use secrecy::SecretBox;
use serde::{Deserialize, Serialize};
use spt_core::Result;
use zeroize::Zeroizing;

use crate::reference::SecretRef;

/// Zeroizing secret-bytes wrapper used everywhere we hand a secret to a
/// caller. The inner `Zeroizing<Vec<u8>>` zeroes its allocation on drop, and
/// `SecretBox` prevents accidental `Debug` exposure.
pub type SecretBytes = SecretBox<Zeroizing<Vec<u8>>>;

/// Convenience constructor — wrap raw bytes in a [`SecretBytes`].
#[must_use]
pub fn secret_bytes(v: Vec<u8>) -> SecretBytes {
    SecretBox::new(Box::new(Zeroizing::new(v)))
}

/// Identifies a backend in doctor reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    /// OS keychain via the `keyring` crate.
    Keychain,
    /// Local encrypted vault file.
    Vault,
    /// Process environment variables.
    Env,
    /// Mode-checked file paths.
    File,
}

/// Coarse status reported by [`SecretBackend::doctor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendStatus {
    /// Backend is reachable and usable.
    Ok,
    /// Backend is reachable but partially functional (e.g. keychain
    /// available but headless session, or vault locked).
    Degraded,
    /// Backend is not available on this platform / in this environment.
    Unavailable,
}

/// Per-backend doctor record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendDoctor {
    /// Which backend this record describes.
    pub kind: BackendKind,
    /// Coarse status.
    pub status: BackendStatus,
    /// Human-readable description.
    pub message: String,
    /// Optional remediation hint.
    pub remediation: Option<String>,
}

impl BackendDoctor {
    /// Convenience constructor for an `Ok` record.
    #[must_use]
    pub fn ok(kind: BackendKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            status: BackendStatus::Ok,
            message: message.into(),
            remediation: None,
        }
    }

    /// Convenience constructor for an `Unavailable` record.
    #[must_use]
    pub fn unavailable(
        kind: BackendKind,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            status: BackendStatus::Unavailable,
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }

    /// Convenience constructor for a `Degraded` record.
    #[must_use]
    pub fn degraded(
        kind: BackendKind,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            status: BackendStatus::Degraded,
            message: message.into(),
            remediation: Some(remediation.into()),
        }
    }
}

/// Pluggable backend interface implemented by keychain / vault / env / file.
///
/// All operations are synchronous; resolver callers run them on the runtime's
/// blocking pool when invoked from async contexts.
pub trait SecretBackend: Send + Sync {
    /// Identifier of this backend.
    fn kind(&self) -> BackendKind;

    /// Look up a reference. Returns `Ok(None)` when the backend has no entry
    /// for the reference (i.e. resolver should fall through), and an error
    /// only on actual backend failures.
    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>>;

    /// Store a value. May be a no-op on read-only backends, in which case
    /// implementations return [`spt_core::Error::UnsupportedPlatform`].
    fn set(&self, r: &SecretRef, value: &[u8]) -> Result<()>;

    /// List references known to the backend.
    fn list(&self) -> Result<Vec<SecretRef>>;

    /// Remove a reference. Returns `Ok(false)` when the entry was not
    /// present, `Ok(true)` when it was removed.
    fn remove(&self, r: &SecretRef) -> Result<bool>;

    /// Health report for this backend.
    fn doctor(&self) -> BackendDoctor;
}
