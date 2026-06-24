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

use std::sync::Once;

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
            // The reference has no entry in this store → fall through.
            Err(keyring::Error::NoEntry) => Ok(None),
            // The platform secret store is entirely unavailable — no running
            // Secret Service / D-Bus session (the common case on headless
            // Linux servers) or the store can't be accessed at all. The
            // keychain simply can't serve *any* reference here, so it must NOT
            // abort the resolver chain: env/file backends still need a shot.
            // We translate these to `Ok(None)` ("this backend has nothing for
            // you, keep looking") and warn once so the condition is visible.
            Err(e @ (keyring::Error::PlatformFailure(_) | keyring::Error::NoStorageAccess(_))) => {
                warn_keychain_unavailable_once(&e);
                Ok(None)
            }
            // Any other error means the entry *exists* but could not be read
            // correctly (e.g. a malformed/ambiguous credential). That is a
            // genuine failure that must halt resolution loudly.
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

/// Emit a single `warn!` the first time the OS keychain is found to be
/// entirely unavailable during a `get`. On headless servers this is the
/// expected steady state (no Secret Service / D-Bus), so we deliberately log
/// it once rather than on every resolution to avoid log spam while still
/// surfacing the condition for operators who expected a keychain.
fn warn_keychain_unavailable_once(e: &keyring::Error) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        warn!(
            error = %e,
            "OS keychain unavailable; falling through to remaining secret \
             backends (env/file). This is expected on headless servers."
        );
    });
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

#[cfg(test)]
mod tests {
    //! Inline unit tests for [`KeychainBackend`].
    //!
    //! ## Isolation strategy
    //!
    //! These tests live in the `spt-secrets` lib-test binary, which also
    //! runs `vault::tests`. Both modules call
    //! `keyring::set_default_credential_builder` via their own
    //! `OnceLock<()>` guards, so whichever module's test thread reaches it
    //! first pins the global builder. Both builders share equivalent
    //! semantics (a `HashMap<(service,user), Vec<u8>>`), so basic
    //! round-trip tests work regardless of which one wins.
    //!
    //! What we **do not** do here:
    //!
    //! * Rely on fault injection. The fault map lives in `testing::keymock`'s
    //!   `OnceLock`, and the active builder may be `vault::tests`'s
    //!   non-fault-aware one. Fault-injection-dependent assertions live
    //!   in the IT file (`tests/keychain_mock.rs`), which runs as its own
    //!   process and fully owns the global builder.
    //! * Share service names with `vault::tests` (which use
    //!   `"spt-test-vault-*"`). All names here are prefixed `"spt-kchn-*"`
    //!   to keep the per-module shared stores disjoint.

    use super::*;
    use crate::backend::BackendStatus;
    use crate::testing::seeded_keychain;
    use keyring::Entry;
    use secrecy::ExposeSecret;

    fn ref_for(name: &str) -> SecretRef {
        SecretRef::new("kchn", name).expect("valid ref")
    }

    #[test]
    fn default_is_default_service() {
        let kc = KeychainBackend::default();
        assert_eq!(kc.service, SERVICE);
    }

    #[test]
    fn new_matches_default() {
        let kc1 = KeychainBackend::new();
        let kc2 = KeychainBackend::default();
        assert_eq!(kc1.service, kc2.service);
    }

    #[test]
    fn with_service_overrides_root() {
        let kc = KeychainBackend::with_service("custom-svc");
        assert_eq!(kc.service, "custom-svc");
    }

    #[test]
    fn kind_is_keychain() {
        let kc = KeychainBackend::with_service("spt-kchn-kind");
        assert_eq!(kc.kind(), BackendKind::Keychain);
    }

    #[test]
    fn entry_for_uses_ns_colon_name_account() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-entry-account");
        let r = SecretRef::new("alpha", "beta").unwrap();
        let entry = kc.entry_for(&r).expect("entry");
        // Write through the entry directly, then read back through a fresh
        // Entry constructed with the same service/account to prove the
        // account encoding is `ns:name`.
        entry.set_secret(b"x").unwrap();
        let again = Entry::new("spt-kchn-entry-account", "alpha:beta").unwrap();
        assert_eq!(again.get_secret().unwrap(), b"x");
    }

    #[test]
    fn master_entry_uses_reserved_account() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-master");
        let entry = kc.master_entry().expect("master entry");
        entry.set_secret(b"master-key-bytes").unwrap();
        let direct = Entry::new("spt-kchn-master", VAULT_MASTER_ACCOUNT).unwrap();
        assert_eq!(direct.get_secret().unwrap(), b"master-key-bytes");
    }

    #[test]
    fn get_round_trip_returns_some() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-get-hit");
        let r = ref_for("hit");
        kc.set(&r, b"payload").unwrap();
        let got = kc.get(&r).unwrap().expect("some");
        assert_eq!(got.expose_secret().as_slice(), b"payload");
    }

    #[test]
    fn get_missing_short_circuits_to_none() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-get-miss");
        let r = ref_for("absent");
        // Never `set` — the underlying mock returns `NoEntry`, which the
        // backend must translate to `Ok(None)`.
        assert!(kc.get(&r).unwrap().is_none());
    }

    #[test]
    fn set_success_writes_into_keychain() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-set-ok");
        let r = ref_for("write");
        kc.set(&r, b"value").unwrap();
        // Direct readback through the keyring API confirms write landed.
        let direct = Entry::new("spt-kchn-set-ok", "kchn:write").unwrap();
        assert_eq!(direct.get_secret().unwrap(), b"value");
    }

    #[test]
    fn list_returns_empty_and_emits_warn() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-list");
        // Even with entries present, `list` is intentionally a no-op.
        let r = ref_for("a");
        kc.set(&r, b"v").unwrap();
        let listed = kc.list().expect("list ok");
        assert!(listed.is_empty());
    }

    #[test]
    fn remove_existing_entry_returns_true() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-remove-true");
        let r = ref_for("present");
        kc.set(&r, b"v").unwrap();
        assert!(kc.remove(&r).unwrap());
        // Second remove must report not-present.
        assert!(!kc.remove(&r).unwrap());
    }

    #[test]
    fn remove_missing_entry_returns_false() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-remove-false");
        let r = ref_for("ghost");
        assert!(!kc.remove(&r).unwrap());
    }

    #[test]
    fn doctor_reports_ok_when_probe_is_noentry() {
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-doctor-ok");
        let d = kc.doctor();
        assert_eq!(d.kind, BackendKind::Keychain);
        assert!(matches!(d.status, BackendStatus::Ok));
        assert!(d.message.contains("reachable"));
        assert!(d.remediation.is_none());
    }

    #[test]
    fn doctor_reports_ok_when_probe_is_already_set() {
        // A pre-existing value at the probe slot is still a healthy
        // outcome — the doctor accepts either `NoEntry` or a successful
        // read. We pre-seed the probe slot to exercise that arm.
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-doctor-preset");
        let probe = Entry::new("spt-kchn-doctor-preset", "spt-doctor-probe").unwrap();
        probe.set_secret(b"already-there").unwrap();
        let d = kc.doctor();
        assert_eq!(d.kind, BackendKind::Keychain);
        assert!(matches!(d.status, BackendStatus::Ok));
    }

    #[test]
    fn with_service_isolates_namespaces() {
        let _g = seeded_keychain();
        let kc_a = KeychainBackend::with_service("spt-kchn-iso-a");
        let kc_b = KeychainBackend::with_service("spt-kchn-iso-b");
        let r = ref_for("shared-name");
        kc_a.set(&r, b"a-value").unwrap();
        // `kc_b` shares the same `(ns,name)` reference but a distinct
        // service, so it must NOT see kc_a's value.
        assert!(kc_b.get(&r).unwrap().is_none());
        // Round-trip on each side independently.
        kc_b.set(&r, b"b-value").unwrap();
        assert_eq!(
            kc_a.get(&r).unwrap().unwrap().expose_secret().as_slice(),
            b"a-value"
        );
        assert_eq!(
            kc_b.get(&r).unwrap().unwrap().expose_secret().as_slice(),
            b"b-value"
        );
    }

    #[test]
    fn keychain_remediation_is_non_empty_on_target_os() {
        // Any of the four cfg-arms returns a non-empty string. We only
        // need the active one to compile and yield prose.
        let s = keychain_remediation();
        assert!(!s.is_empty());
    }

    #[test]
    fn entry_for_returns_ok_for_well_formed_ref() {
        // `entry_for` only `map_err`s the keyring init failure; on the
        // mock builder it cannot fail. Exercising the happy-path branch
        // proves the SecretRef → account conversion compiles + works.
        let _g = seeded_keychain();
        let kc = KeychainBackend::with_service("spt-kchn-entry-ok");
        let r = SecretRef::new("ns_with_underscore", "name.with.dots").unwrap();
        let _entry = kc.entry_for(&r).expect("entry");
    }
}
