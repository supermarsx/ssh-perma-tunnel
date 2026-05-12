//! OS keychain backend backed by the `keyring` crate.
//!
//! Service / account convention used for every entry:
//!
//! * `service = "spt"`
//! * `account = "<ns>:<name>"` for normal references
//! * `account = "vault-master"` for the local vault master key (managed by
//!   [`crate::vault`]; users should not address it through a [`SecretRef`]).
//!
//! Per-OS notes (informational; runtime behavior is identical):
//!
//! * **macOS** — uses the user login Keychain via `Security.framework`.
//!   Storage is per-user; first read in a process may prompt for unlock.
//! * **Linux** — uses the Secret Service D-Bus API (`gnome-keyring` or `KWallet`
//!   in compatibility mode). Requires a running Secret Service and an
//!   unlocked default collection. Headless servers without a desktop session
//!   should fall back to the encrypted vault.
//! * **Windows** — uses the user Credential Manager via the Win32
//!   Credentials API. Storage is per-user and per-machine; roaming profiles
//!   may not roam credentials.

use keyring::Entry;
use spt_core::{Error, Result};
use tracing::warn;

use crate::backend::{secret_bytes, BackendDoctor, BackendKind, SecretBackend, SecretBytes};
use crate::reference::SecretRef;

/// Service name registered with the OS keychain.
pub const SERVICE: &str = "spt";

/// Reserved account name for the local vault master key.
pub const VAULT_MASTER_ACCOUNT: &str = "vault-master";

/// Keychain-backed [`SecretBackend`].
///
/// `KeychainBackend::list` is a best-effort no-op because the `keyring`
/// crate's portable abstraction does not expose enumeration on every
/// platform. Callers that need enumeration should consult the local vault.
pub struct KeychainBackend {
    service: String,
}

impl Default for KeychainBackend {
    fn default() -> Self {
        Self {
            service: SERVICE.to_owned(),
        }
    }
}

impl KeychainBackend {
    /// Create a keychain backend rooted at the default `"spt"` service.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a keychain backend with a custom service name. Primarily used
    /// by tests to isolate fixtures.
    #[must_use]
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry_for(&self, r: &SecretRef) -> Result<Entry> {
        let account = format!("{}:{}", r.ns(), r.name());
        Entry::new(&self.service, &account).map_err(|e| Error::SecretUnavailable {
            reference: r.to_string(),
            reason: format!("keyring entry init: {e}"),
        })
    }

    /// Internal accessor for [`crate::vault`] — fetch the vault master key
    /// from the configured service.
    pub(crate) fn master_entry(&self) -> Result<Entry> {
        Entry::new(&self.service, VAULT_MASTER_ACCOUNT).map_err(|e| Error::SecretUnavailable {
            reference: format!("keychain://{}/{VAULT_MASTER_ACCOUNT}", self.service),
            reason: format!("keyring entry init: {e}"),
        })
    }
}

impl SecretBackend for KeychainBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Keychain
    }

    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        let entry = self.entry_for(r)?;
        match entry.get_secret() {
            Ok(bytes) => Ok(Some(secret_bytes(bytes))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("keychain get: {e}"),
            }),
        }
    }

    fn set(&self, r: &SecretRef, value: &[u8]) -> Result<()> {
        let entry = self.entry_for(r)?;
        entry
            .set_secret(value)
            .map_err(|e| Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("keychain set: {e}"),
            })
    }

    fn list(&self) -> Result<Vec<SecretRef>> {
        // `keyring` 3 does not expose a portable enumeration API. Returning
        // an empty list is correct: the resolver and CLI both treat
        // keychain entries as discoverable only via explicit lookup.
        warn!("keychain backend does not support enumeration; returning empty list");
        Ok(Vec::new())
    }

    fn remove(&self, r: &SecretRef) -> Result<bool> {
        let entry = self.entry_for(r)?;
        match entry.delete_credential() {
            Ok(()) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("keychain remove: {e}"),
            }),
        }
    }

    fn doctor(&self) -> BackendDoctor {
        // Probe with a synthetic account that's never written. A successful
        // `Entry::new` followed by `NoEntry` on `get_secret` proves the
        // backend is reachable.
        match Entry::new(&self.service, "spt-doctor-probe") {
            Ok(entry) => match entry.get_secret() {
                Ok(_) | Err(keyring::Error::NoEntry) => {
                    BackendDoctor::ok(BackendKind::Keychain, "OS keychain reachable")
                }
                Err(keyring::Error::PlatformFailure(e)) => BackendDoctor::unavailable(
                    BackendKind::Keychain,
                    format!("platform failure: {e}"),
                    keychain_remediation(),
                ),
                Err(keyring::Error::NoStorageAccess(e)) => BackendDoctor::unavailable(
                    BackendKind::Keychain,
                    format!("no storage access: {e}"),
                    keychain_remediation(),
                ),
                Err(e) => BackendDoctor::degraded(
                    BackendKind::Keychain,
                    format!("probe error: {e}"),
                    "see `spt secret doctor` for details",
                ),
            },
            Err(e) => BackendDoctor::unavailable(
                BackendKind::Keychain,
                format!("keyring init failed: {e}"),
                keychain_remediation(),
            ),
        }
    }
}

#[cfg(target_os = "linux")]
fn keychain_remediation() -> String {
    "Linux: ensure a Secret Service provider (gnome-keyring or KWallet) is \
     running in the user session and the default collection is unlocked, \
     or use the local encrypted vault for headless deployments."
        .to_owned()
}

#[cfg(target_os = "macos")]
fn keychain_remediation() -> String {
    "macOS: ensure the user login Keychain is unlocked.".to_owned()
}

#[cfg(target_os = "windows")]
fn keychain_remediation() -> String {
    "Windows: ensure the Credential Manager service is running and the user \
     profile is interactive."
        .to_owned()
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn keychain_remediation() -> String {
    "OS keychain support is not available on this platform; use the local \
     encrypted vault."
        .to_owned()
}
