//! Test facilities for `spt-secrets`.
//!
//! Behind the `testing` feature flag (and automatically under `cfg(test)`).
//! Provides:
//!
//! * [`MemoryBackend`] — in-memory `HashMap`-backed [`SecretBackend`]. No I/O.
//! * [`AlwaysFailBackend`] — every method returns the configured error.
//!   Useful for failure-path tests.
//! * [`RecordingResolver`] — wraps a backend and records every `get` call.
//! * [`MockKeychainGuard`] — installs a process-wide `keyring` mock with a
//!   shared in-memory store, mirroring the one used by the crate's vault
//!   tests so external test code can round-trip through the keychain.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};

use secrecy::ExposeSecret;
use spt_core::{Error, Result};
use zeroize::Zeroizing;

use crate::backend::{secret_bytes, BackendDoctor, BackendKind, SecretBackend, SecretBytes};
use crate::reference::SecretRef;

// ---------------------------------------------------------------------------
// MemoryBackend
// ---------------------------------------------------------------------------

/// In-memory [`SecretBackend`].
///
/// Stores values in a `Mutex<HashMap<SecretRef, Vec<u8>>>`. Reports as
/// [`BackendKind::Vault`] so the chain-description string is meaningful.
///
/// # Examples
///
/// ```
/// use spt_secrets::testing::MemoryBackend;
/// use spt_secrets::SecretBackend;
/// use spt_secrets::SecretRef;
/// use secrecy::ExposeSecret;
/// let r = SecretRef::new("ns", "n").unwrap();
/// let b = MemoryBackend::with_entry(r.clone(), b"hello".to_vec());
/// let got = b.get(&r).unwrap().unwrap();
/// assert_eq!(&***got.expose_secret(), b"hello");
/// ```
pub struct MemoryBackend {
    kind: BackendKind,
    entries: Mutex<HashMap<SecretRef, Vec<u8>>>,
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryBackend {
    /// Empty backend.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::MemoryBackend;
    /// let _ = MemoryBackend::new();
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            kind: BackendKind::Vault,
            entries: Mutex::new(HashMap::new()),
        }
    }

    /// Backend pre-populated with one entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::MemoryBackend;
    /// use spt_secrets::SecretRef;
    /// let r = SecretRef::new("a", "b").unwrap();
    /// let _ = MemoryBackend::with_entry(r, b"x".to_vec());
    /// ```
    #[must_use]
    pub fn with_entry(r: SecretRef, value: Vec<u8>) -> Self {
        let b = Self::new();
        b.entries.lock().unwrap().insert(r, value);
        b
    }

    /// Backend pre-populated with the given entries.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::MemoryBackend;
    /// use spt_secrets::SecretRef;
    /// let r = SecretRef::new("a", "b").unwrap();
    /// let _ = MemoryBackend::with_entries(vec![(r, b"v".to_vec())]);
    /// ```
    #[must_use]
    pub fn with_entries(items: Vec<(SecretRef, Vec<u8>)>) -> Self {
        let b = Self::new();
        let mut g = b.entries.lock().unwrap();
        for (r, v) in items {
            g.insert(r, v);
        }
        drop(g);
        b
    }

    /// Override the reported [`BackendKind`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::MemoryBackend;
    /// use spt_secrets::BackendKind;
    /// use spt_secrets::SecretBackend;
    /// let b = MemoryBackend::new().with_kind(BackendKind::Env);
    /// assert_eq!(b.kind(), BackendKind::Env);
    /// ```
    #[must_use]
    pub fn with_kind(mut self, kind: BackendKind) -> Self {
        self.kind = kind;
        self
    }
}

impl SecretBackend for MemoryBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }

    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .get(r)
            .cloned()
            .map(secret_bytes))
    }

    fn set(&self, r: &SecretRef, value: &[u8]) -> Result<()> {
        self.entries
            .lock()
            .unwrap()
            .insert(r.clone(), value.to_vec());
        Ok(())
    }

    fn list(&self) -> Result<Vec<SecretRef>> {
        Ok(self.entries.lock().unwrap().keys().cloned().collect())
    }

    fn remove(&self, r: &SecretRef) -> Result<bool> {
        Ok(self.entries.lock().unwrap().remove(r).is_some())
    }

    fn doctor(&self) -> BackendDoctor {
        BackendDoctor::ok(self.kind, "in-memory test backend")
    }
}

// ---------------------------------------------------------------------------
// AlwaysFailBackend
// ---------------------------------------------------------------------------

/// Backend that returns a fixed error category from every method.
///
/// Because [`spt_core::Error`] is not [`Clone`], the backend stores a small
/// `Kind` discriminator plus a reason string and reconstructs the error on
/// each call. The default is [`AlwaysFailBackend::secret_unavailable`].
///
/// Useful for exercising failure-path branches in resolver chains.
///
/// # Examples
///
/// ```
/// use spt_secrets::testing::AlwaysFailBackend;
/// use spt_secrets::{SecretBackend, SecretRef};
/// let b = AlwaysFailBackend::secret_unavailable("test");
/// let r = SecretRef::new("a", "b").unwrap();
/// assert!(b.get(&r).is_err());
/// ```
pub struct AlwaysFailBackend {
    kind: BackendKind,
    err_kind: AlwaysFailKind,
    reason: String,
}

#[derive(Debug, Clone, Copy)]
enum AlwaysFailKind {
    SecretUnavailable,
    SecretCryptoFailed,
    PermissionDenied,
    UnsupportedPlatform,
}

impl AlwaysFailBackend {
    /// Build a backend that returns [`Error::SecretUnavailable`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::AlwaysFailBackend;
    /// let _ = AlwaysFailBackend::secret_unavailable("missing");
    /// ```
    #[must_use]
    pub fn secret_unavailable(reason: impl Into<String>) -> Self {
        Self {
            kind: BackendKind::Vault,
            err_kind: AlwaysFailKind::SecretUnavailable,
            reason: reason.into(),
        }
    }

    /// Build a backend that returns [`Error::SecretCryptoFailed`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::AlwaysFailBackend;
    /// let _ = AlwaysFailBackend::crypto_failed("aead tag");
    /// ```
    #[must_use]
    pub fn crypto_failed(reason: impl Into<String>) -> Self {
        Self {
            kind: BackendKind::Vault,
            err_kind: AlwaysFailKind::SecretCryptoFailed,
            reason: reason.into(),
        }
    }

    /// Build a backend that returns [`Error::PermissionDenied`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::AlwaysFailBackend;
    /// let _ = AlwaysFailBackend::permission_denied("EACCES");
    /// ```
    #[must_use]
    pub fn permission_denied(reason: impl Into<String>) -> Self {
        Self {
            kind: BackendKind::File,
            err_kind: AlwaysFailKind::PermissionDenied,
            reason: reason.into(),
        }
    }

    /// Build a backend that returns [`Error::UnsupportedPlatform`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::AlwaysFailBackend;
    /// let _ = AlwaysFailBackend::unsupported("haiku");
    /// ```
    #[must_use]
    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            kind: BackendKind::Keychain,
            err_kind: AlwaysFailKind::UnsupportedPlatform,
            reason: reason.into(),
        }
    }

    /// Override the reported [`BackendKind`].
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::AlwaysFailBackend;
    /// use spt_secrets::{BackendKind, SecretBackend};
    /// let b = AlwaysFailBackend::secret_unavailable("x").with_kind(BackendKind::Keychain);
    /// assert_eq!(b.kind(), BackendKind::Keychain);
    /// ```
    #[must_use]
    pub fn with_kind(mut self, kind: BackendKind) -> Self {
        self.kind = kind;
        self
    }

    fn make_err(&self, r: Option<&SecretRef>) -> Error {
        match self.err_kind {
            AlwaysFailKind::SecretUnavailable => Error::SecretUnavailable {
                reference: r.map(SecretRef::to_string).unwrap_or_default(),
                reason: self.reason.clone(),
            },
            AlwaysFailKind::SecretCryptoFailed => Error::SecretCryptoFailed(self.reason.clone()),
            AlwaysFailKind::PermissionDenied => Error::PermissionDenied(self.reason.clone()),
            AlwaysFailKind::UnsupportedPlatform => Error::UnsupportedPlatform(self.reason.clone()),
        }
    }
}

impl SecretBackend for AlwaysFailBackend {
    fn kind(&self) -> BackendKind {
        self.kind
    }
    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        Err(self.make_err(Some(r)))
    }
    fn set(&self, r: &SecretRef, _v: &[u8]) -> Result<()> {
        Err(self.make_err(Some(r)))
    }
    fn list(&self) -> Result<Vec<SecretRef>> {
        Err(self.make_err(None))
    }
    fn remove(&self, r: &SecretRef) -> Result<bool> {
        Err(self.make_err(Some(r)))
    }
    fn doctor(&self) -> BackendDoctor {
        BackendDoctor::unavailable(self.kind, "always-fail", "for tests only")
    }
}

// ---------------------------------------------------------------------------
// RecordingResolver
// ---------------------------------------------------------------------------

/// Wraps a [`SecretBackend`] and records every `get` call.
///
/// `calls()` returns a snapshot of recorded references in invocation order.
///
/// # Examples
///
/// ```
/// use spt_secrets::testing::{MemoryBackend, RecordingResolver};
/// use spt_secrets::{SecretBackend, SecretRef};
/// use std::sync::Arc;
/// let inner = Arc::new(MemoryBackend::new());
/// let rec = RecordingResolver::new(inner);
/// let r = SecretRef::new("a", "b").unwrap();
/// let _ = rec.get(&r);
/// assert_eq!(rec.calls(), vec![r]);
/// ```
pub struct RecordingResolver {
    inner: Arc<dyn SecretBackend>,
    calls: Mutex<Vec<SecretRef>>,
}

impl RecordingResolver {
    /// Wrap an existing backend.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::{MemoryBackend, RecordingResolver};
    /// use std::sync::Arc;
    /// let _ = RecordingResolver::new(Arc::new(MemoryBackend::new()));
    /// ```
    #[must_use]
    pub fn new(inner: Arc<dyn SecretBackend>) -> Self {
        Self {
            inner,
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Snapshot of recorded `get` calls in invocation order.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::{MemoryBackend, RecordingResolver};
    /// use std::sync::Arc;
    /// let r = RecordingResolver::new(Arc::new(MemoryBackend::new()));
    /// assert!(r.calls().is_empty());
    /// ```
    #[must_use]
    pub fn calls(&self) -> Vec<SecretRef> {
        self.calls.lock().unwrap().clone()
    }

    /// Reset the recorded log.
    ///
    /// # Examples
    ///
    /// ```
    /// use spt_secrets::testing::{MemoryBackend, RecordingResolver};
    /// use std::sync::Arc;
    /// let r = RecordingResolver::new(Arc::new(MemoryBackend::new()));
    /// r.clear();
    /// assert!(r.calls().is_empty());
    /// ```
    pub fn clear(&self) {
        self.calls.lock().unwrap().clear();
    }
}

impl SecretBackend for RecordingResolver {
    fn kind(&self) -> BackendKind {
        self.inner.kind()
    }
    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        self.calls.lock().unwrap().push(r.clone());
        self.inner.get(r)
    }
    fn set(&self, r: &SecretRef, v: &[u8]) -> Result<()> {
        self.inner.set(r, v)
    }
    fn list(&self) -> Result<Vec<SecretRef>> {
        self.inner.list()
    }
    fn remove(&self, r: &SecretRef) -> Result<bool> {
        self.inner.remove(r)
    }
    fn doctor(&self) -> BackendDoctor {
        self.inner.doctor()
    }
}

// ---------------------------------------------------------------------------
// Keyring mock helper
// ---------------------------------------------------------------------------

mod keymock {
    use keyring::credential::{
        Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi, CredentialPersistence,
    };
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    type Store = Mutex<HashMap<(String, String), Vec<u8>>>;
    type FaultMap = Mutex<HashMap<(String, String), FaultKind>>;

    /// Discriminator used by the mock to construct fresh `keyring::Error`
    /// values per call. We cannot store `keyring::Error` directly because
    /// it is `#[non_exhaustive]` and non-`Clone`.
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum FaultKind {
        PlatformFailure,
        NoStorageAccess,
        NoEntry,
        BadEncoding,
        Invalid,
    }

    impl FaultKind {
        pub(crate) fn to_error(self) -> keyring::Error {
            match self {
                Self::PlatformFailure => keyring::Error::PlatformFailure(Box::new(
                    std::io::Error::other("mock platform failure"),
                )),
                Self::NoStorageAccess => keyring::Error::NoStorageAccess(Box::new(
                    std::io::Error::other("mock no storage access"),
                )),
                Self::NoEntry => keyring::Error::NoEntry,
                Self::BadEncoding => keyring::Error::BadEncoding(Vec::new()),
                Self::Invalid => {
                    keyring::Error::Invalid("attr".to_owned(), "mock invalid".to_owned())
                }
            }
        }
    }

    pub(super) fn shared_store() -> &'static Store {
        static S: OnceLock<Store> = OnceLock::new();
        S.get_or_init(|| Mutex::new(HashMap::new()))
    }

    pub(super) fn fault_map() -> &'static FaultMap {
        static F: OnceLock<FaultMap> = OnceLock::new();
        F.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn current_fault(service: &str, user: &str) -> Option<FaultKind> {
        fault_map()
            .lock()
            .unwrap()
            .get(&(service.to_owned(), user.to_owned()))
            .copied()
    }

    #[derive(Debug)]
    pub(super) struct SharedMockCred {
        pub service: String,
        pub user: String,
    }

    impl CredentialApi for SharedMockCred {
        fn set_password(&self, password: &str) -> keyring::Result<()> {
            self.set_secret(password.as_bytes())
        }
        fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
            if let Some(kind) = current_fault(&self.service, &self.user) {
                return Err(kind.to_error());
            }
            shared_store()
                .lock()
                .unwrap()
                .insert((self.service.clone(), self.user.clone()), secret.to_vec());
            Ok(())
        }
        fn get_password(&self) -> keyring::Result<String> {
            let bytes = self.get_secret()?;
            String::from_utf8(bytes).map_err(|_| keyring::Error::BadEncoding(Vec::new()))
        }
        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            if let Some(kind) = current_fault(&self.service, &self.user) {
                return Err(kind.to_error());
            }
            shared_store()
                .lock()
                .unwrap()
                .get(&(self.service.clone(), self.user.clone()))
                .cloned()
                .ok_or(keyring::Error::NoEntry)
        }
        fn delete_credential(&self) -> keyring::Result<()> {
            if let Some(kind) = current_fault(&self.service, &self.user) {
                return Err(kind.to_error());
            }
            let mut g = shared_store().lock().unwrap();
            if g.remove(&(self.service.clone(), self.user.clone()))
                .is_some()
            {
                Ok(())
            } else {
                Err(keyring::Error::NoEntry)
            }
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    pub(super) struct SharedMockBuilder;

    impl CredentialBuilderApi for SharedMockBuilder {
        fn build(
            &self,
            _target: Option<&str>,
            service: &str,
            user: &str,
        ) -> keyring::Result<Box<Credential>> {
            Ok(Box::new(SharedMockCred {
                service: service.to_owned(),
                user: user.to_owned(),
            }))
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
        fn persistence(&self) -> CredentialPersistence {
            CredentialPersistence::ProcessOnly
        }
    }

    pub(super) fn install_once() {
        static ONCE: OnceLock<()> = OnceLock::new();
        ONCE.get_or_init(|| {
            keyring::set_default_credential_builder(
                Box::new(SharedMockBuilder) as Box<CredentialBuilder>
            );
        });
    }

    /// Force the shared-mock builder to be the active keyring default,
    /// regardless of any other module's prior install. Tests that need
    /// fault injection must call this to be sure their `set_fault` calls
    /// are observed.
    pub(crate) fn install_force() {
        use keyring::credential::CredentialBuilder;
        keyring::set_default_credential_builder(
            Box::new(SharedMockBuilder) as Box<CredentialBuilder>
        );
    }

    pub(super) fn clear_store() {
        shared_store().lock().unwrap().clear();
        fault_map().lock().unwrap().clear();
    }

    pub(crate) fn set_fault_inner(service: &str, user: &str, kind: FaultKind) {
        fault_map()
            .lock()
            .unwrap()
            .insert((service.to_owned(), user.to_owned()), kind);
    }

    pub(crate) fn clear_fault_inner(service: &str, user: &str) {
        fault_map()
            .lock()
            .unwrap()
            .remove(&(service.to_owned(), user.to_owned()));
    }
}

/// Process-wide serialization lock for the keyring mock.
///
/// The `keyring` crate exposes a *single* global default credential builder,
/// and the mock's backing store + fault map are process-global
/// (`OnceLock`-backed statics). A guard that installs the mock therefore also
/// resets (`clear_store`) that global state on setup and on drop. If two
/// keyring-touching tests ran concurrently in the same test binary, one
/// test's install/drop would wipe another's programmed store/faults mid-run
/// (the F-T1 flake). Every guard returned by [`seeded_keychain`] /
/// [`install_mock_keyring`] holds this lock for its whole lifetime, so all
/// keyring-touching tests in a binary run one-at-a-time — the repo's
/// `static Mutex` test-lock idiom. `unique-service-per-test` is NOT sufficient
/// on its own: the race is the global reset, not a key collision.
fn keyring_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        // A panicking test poisons the lock; recover the guard so the poison
        // does not cascade into spurious failures of every later keyring test.
        .unwrap_or_else(PoisonError::into_inner)
}

/// Install a process-wide `keyring` mock that uses a shared in-memory store.
///
/// Idempotent — installation runs at most once per process. Returns a guard
/// that (a) holds the process-wide [`keyring_lock`] so keyring-touching tests
/// run serially, and (b) clears the store on drop so successive tests don't
/// leak state across each other. The mock itself remains installed (the
/// `keyring` crate only allows the default builder to be set once per
/// process).
///
/// # Examples
///
/// ```
/// use spt_secrets::testing::seeded_keychain;
/// let _guard = seeded_keychain();
/// // Now `keyring::Entry::new(...).set_secret(...)` writes into the shared
/// // mock store; the guard clears the store on drop.
/// ```
#[must_use]
pub fn seeded_keychain() -> KeychainTestGuard {
    let lock = keyring_lock();
    keymock::install_once();
    keymock::clear_store();
    KeychainTestGuard { _lock: lock }
}

/// RAII guard returned by [`seeded_keychain`]. Holds the process-wide keyring
/// test lock and clears the shared mock store on drop.
pub struct KeychainTestGuard {
    _lock: MutexGuard<'static, ()>,
}

impl Drop for KeychainTestGuard {
    fn drop(&mut self) {
        keymock::clear_store();
    }
}

/// Fault kinds that can be programmed into a [`MockKeychainGuard`]-managed
/// shared store. Each kind reconstructs the corresponding `keyring::Error`
/// variant on every `get`/`set`/`delete_credential` call against the
/// configured `(service, user)` slot.
#[derive(Debug, Clone, Copy)]
pub enum MockFaultKind {
    /// Yields `keyring::Error::PlatformFailure`.
    PlatformFailure,
    /// Yields `keyring::Error::NoStorageAccess`.
    NoStorageAccess,
    /// Yields `keyring::Error::NoEntry`.
    NoEntry,
    /// Yields `keyring::Error::BadEncoding`.
    BadEncoding,
    /// Yields `keyring::Error::Invalid`.
    Invalid,
}

impl From<MockFaultKind> for keymock::FaultKind {
    fn from(value: MockFaultKind) -> Self {
        match value {
            MockFaultKind::PlatformFailure => Self::PlatformFailure,
            MockFaultKind::NoStorageAccess => Self::NoStorageAccess,
            MockFaultKind::NoEntry => Self::NoEntry,
            MockFaultKind::BadEncoding => Self::BadEncoding,
            MockFaultKind::Invalid => Self::Invalid,
        }
    }
}

/// Install the shared-mock keyring builder unconditionally and return an
/// RAII guard that clears the store + fault map on drop.
///
/// Unlike [`seeded_keychain`], this **always** wins the global builder
/// race — useful in integration tests where fault injection must be
/// observed regardless of any other module's prior install.
///
/// The guard exposes [`MockKeychainGuard::set_fault`] /
/// [`MockKeychainGuard::clear_fault`] to program per-entry error returns.
#[must_use]
pub fn install_mock_keyring() -> MockKeychainGuard {
    let lock = keyring_lock();
    keymock::install_force();
    keymock::clear_store();
    MockKeychainGuard { _lock: lock }
}

/// Stronger sibling of [`KeychainTestGuard`] returned by
/// [`install_mock_keyring`]. Holds the process-wide keyring test lock,
/// programs per-entry fault injection, and clears the shared store on drop.
pub struct MockKeychainGuard {
    _lock: MutexGuard<'static, ()>,
}

impl MockKeychainGuard {
    /// Register a fault: subsequent `get`/`set`/`delete_credential` calls
    /// against the `(service, user)` slot return the matching
    /// `keyring::Error` variant.
    ///
    /// Method-style on the guard (rather than a free fn) to make ownership
    /// of the active mock explicit at call sites.
    #[allow(clippy::unused_self)]
    pub fn set_fault(&self, service: &str, user: &str, kind: MockFaultKind) {
        keymock::set_fault_inner(service, user, kind.into());
    }

    /// Remove a previously-registered fault.
    #[allow(clippy::unused_self)]
    pub fn clear_fault(&self, service: &str, user: &str) {
        keymock::clear_fault_inner(service, user);
    }
}

impl Drop for MockKeychainGuard {
    fn drop(&mut self) {
        keymock::clear_store();
    }
}

// ---------------------------------------------------------------------------
// Helper: extract bytes from a SecretBytes for assertions
// ---------------------------------------------------------------------------

/// Convenience for tests: copy the inner bytes out of a [`SecretBytes`].
///
/// The returned `Zeroizing<Vec<u8>>` is itself wiped on drop.
///
/// # Examples
///
/// ```
/// use spt_secrets::testing::{expose_bytes, MemoryBackend};
/// use spt_secrets::{SecretBackend, SecretRef};
/// let r = SecretRef::new("a", "b").unwrap();
/// let b = MemoryBackend::with_entry(r.clone(), b"hi".to_vec());
/// let v = b.get(&r).unwrap().unwrap();
/// assert_eq!(expose_bytes(&v).as_slice(), b"hi");
/// ```
#[must_use]
pub fn expose_bytes(s: &SecretBytes) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(s.expose_secret().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_backend_round_trips() {
        let r = SecretRef::new("ns", "n").unwrap();
        let b = MemoryBackend::new();
        b.set(&r, b"v").unwrap();
        let got = b.get(&r).unwrap().unwrap();
        assert_eq!(expose_bytes(&got).as_slice(), b"v");
        assert!(b.list().unwrap().contains(&r));
        assert!(b.remove(&r).unwrap());
        assert!(b.get(&r).unwrap().is_none());
    }

    #[test]
    fn memory_backend_with_entries_constructs() {
        let a = SecretRef::new("a", "1").unwrap();
        let b = SecretRef::new("a", "2").unwrap();
        let backend = MemoryBackend::with_entries(vec![
            (a.clone(), b"a".to_vec()),
            (b.clone(), b"b".to_vec()),
        ]);
        let mut listed = backend.list().unwrap();
        listed.sort_by_key(std::string::ToString::to_string);
        assert_eq!(listed, vec![a, b]);
    }

    #[test]
    fn always_fail_backend_returns_error() {
        let b = AlwaysFailBackend::crypto_failed("nope");
        let r = SecretRef::new("a", "b").unwrap();
        assert!(matches!(b.get(&r), Err(Error::SecretCryptoFailed(_))));
        let b2 = AlwaysFailBackend::secret_unavailable("missing");
        assert!(matches!(b2.get(&r), Err(Error::SecretUnavailable { .. })));
    }

    #[test]
    fn recording_resolver_records_calls() {
        let inner = Arc::new(MemoryBackend::new());
        let rec = RecordingResolver::new(inner);
        let r1 = SecretRef::new("a", "1").unwrap();
        let r2 = SecretRef::new("b", "2").unwrap();
        let _ = rec.get(&r1);
        let _ = rec.get(&r2);
        assert_eq!(rec.calls(), vec![r1, r2]);
        rec.clear();
        assert!(rec.calls().is_empty());
    }

    #[test]
    fn seeded_keychain_round_trip() {
        use keyring::Entry;
        let _g = seeded_keychain();
        let e = Entry::new("spt-test-svc", "u1").expect("entry");
        e.set_secret(b"hello").expect("set");
        let got = e.get_secret().expect("get");
        assert_eq!(got, b"hello");
    }

    #[test]
    fn memory_backend_default_is_empty() {
        let b: MemoryBackend = MemoryBackend::default();
        assert!(b.list().unwrap().is_empty());
        assert_eq!(b.kind(), BackendKind::Vault);
    }

    #[test]
    fn memory_backend_with_kind_overrides() {
        let b = MemoryBackend::new().with_kind(BackendKind::Keychain);
        assert_eq!(b.kind(), BackendKind::Keychain);
    }

    #[test]
    fn memory_backend_doctor_is_ok() {
        let b = MemoryBackend::new();
        let d = b.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Ok));
        assert_eq!(d.kind, BackendKind::Vault);
    }

    #[test]
    fn always_fail_backend_set_list_remove_propagate() {
        let r = SecretRef::new("ns", "n").unwrap();
        let b = AlwaysFailBackend::secret_unavailable("absent");
        assert!(matches!(
            b.set(&r, b"x"),
            Err(Error::SecretUnavailable { .. })
        ));
        assert!(matches!(b.list(), Err(Error::SecretUnavailable { .. })));
        assert!(matches!(b.remove(&r), Err(Error::SecretUnavailable { .. })));
        let d = b.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Unavailable));
    }

    #[test]
    fn always_fail_backend_permission_denied_variant() {
        let r = SecretRef::new("ns", "n").unwrap();
        let b = AlwaysFailBackend::permission_denied("EACCES");
        assert_eq!(b.kind(), BackendKind::File);
        assert!(matches!(b.get(&r), Err(Error::PermissionDenied(_))));
    }

    #[test]
    fn always_fail_backend_unsupported_variant() {
        let r = SecretRef::new("ns", "n").unwrap();
        let b = AlwaysFailBackend::unsupported("haiku");
        assert_eq!(b.kind(), BackendKind::Keychain);
        assert!(matches!(b.get(&r), Err(Error::UnsupportedPlatform(_))));
    }

    #[test]
    fn always_fail_backend_with_kind_overrides() {
        let b = AlwaysFailBackend::secret_unavailable("x").with_kind(BackendKind::Env);
        assert_eq!(b.kind(), BackendKind::Env);
    }

    #[test]
    fn recording_resolver_pass_through_methods() {
        let inner: Arc<dyn SecretBackend> = Arc::new(MemoryBackend::new());
        let rec = RecordingResolver::new(inner);
        let r = SecretRef::new("ns", "n").unwrap();
        rec.set(&r, b"v").unwrap();
        assert_eq!(rec.kind(), BackendKind::Vault);
        let list = rec.list().unwrap();
        assert!(list.contains(&r));
        assert!(rec.remove(&r).unwrap());
        let d = rec.doctor();
        assert!(matches!(d.status, crate::BackendStatus::Ok));
        // Only `get` is recorded; the helpers above never touched `get`.
        assert!(rec.calls().is_empty());
    }

    #[test]
    fn expose_bytes_copies_inner() {
        let b = secret_bytes(b"hi".to_vec());
        let copy = expose_bytes(&b);
        assert_eq!(copy.as_slice(), b"hi");
    }

    // -----------------------------------------------------------------
    // MockKeychainGuard / fault injection
    //
    // These tests use `install_mock_keyring()` which unconditionally
    // overwrites the global keyring builder — so even if another module's
    // install ran first, the `keymock` store/fault map are guaranteed to
    // be the ones consulted on subsequent `Entry` calls within this test.
    //
    // Isolation is NOT achieved by the unique service prefixes alone: the
    // real hazard is that `install_mock_keyring()`/`seeded_keychain()` reset
    // the *global* store + fault map on setup and on drop, so a concurrent
    // guard would wipe this test's programmed state mid-run. The guard
    // returned below holds a process-wide `Mutex` (see `keyring_lock`) for the
    // whole test body, serializing every keyring-touching test in this binary
    // and eliminating that race. The unique prefixes remain as defense in
    // depth / readability.
    // -----------------------------------------------------------------

    #[test]
    fn install_mock_keyring_round_trip() {
        use keyring::Entry;
        let _g = install_mock_keyring();
        let e = Entry::new("spt-tmock-rt", "u").expect("entry");
        e.set_secret(b"data").expect("set");
        assert_eq!(e.get_secret().expect("get"), b"data");
    }

    #[test]
    fn install_mock_keyring_drop_clears_store() {
        use keyring::Entry;
        {
            let _g = install_mock_keyring();
            let e = Entry::new("spt-tmock-drop", "u").expect("entry");
            e.set_secret(b"x").unwrap();
            assert!(e.get_secret().is_ok());
        }
        // After drop, the store is wiped; a new guard sees no prior
        // entries even with the same service/user.
        let _g2 = install_mock_keyring();
        let e2 = Entry::new("spt-tmock-drop", "u").expect("entry");
        assert!(matches!(e2.get_secret(), Err(keyring::Error::NoEntry)));
    }

    #[test]
    fn mock_fault_kind_platform_failure_surfaces() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e = Entry::new("spt-tmock-pf", "u").expect("entry");
        g.set_fault("spt-tmock-pf", "u", MockFaultKind::PlatformFailure);
        assert!(matches!(
            e.get_secret(),
            Err(keyring::Error::PlatformFailure(_))
        ));
        assert!(matches!(
            e.set_secret(b"x"),
            Err(keyring::Error::PlatformFailure(_))
        ));
        assert!(matches!(
            e.delete_credential(),
            Err(keyring::Error::PlatformFailure(_))
        ));
    }

    #[test]
    fn mock_fault_kind_no_storage_access_surfaces() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e = Entry::new("spt-tmock-nsa", "u").expect("entry");
        g.set_fault("spt-tmock-nsa", "u", MockFaultKind::NoStorageAccess);
        assert!(matches!(
            e.get_secret(),
            Err(keyring::Error::NoStorageAccess(_))
        ));
    }

    #[test]
    fn mock_fault_kind_no_entry_surfaces() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e = Entry::new("spt-tmock-ne", "u").expect("entry");
        g.set_fault("spt-tmock-ne", "u", MockFaultKind::NoEntry);
        assert!(matches!(e.get_secret(), Err(keyring::Error::NoEntry)));
    }

    #[test]
    fn mock_fault_kind_bad_encoding_surfaces() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e = Entry::new("spt-tmock-be", "u").expect("entry");
        g.set_fault("spt-tmock-be", "u", MockFaultKind::BadEncoding);
        assert!(matches!(
            e.get_secret(),
            Err(keyring::Error::BadEncoding(_))
        ));
    }

    #[test]
    fn mock_fault_kind_invalid_surfaces() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e = Entry::new("spt-tmock-inv", "u").expect("entry");
        g.set_fault("spt-tmock-inv", "u", MockFaultKind::Invalid);
        assert!(matches!(e.get_secret(), Err(keyring::Error::Invalid(_, _))));
    }

    #[test]
    fn clear_fault_restores_normal_behavior() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e = Entry::new("spt-tmock-clear", "u").expect("entry");
        g.set_fault("spt-tmock-clear", "u", MockFaultKind::PlatformFailure);
        assert!(matches!(
            e.set_secret(b"v"),
            Err(keyring::Error::PlatformFailure(_))
        ));
        g.clear_fault("spt-tmock-clear", "u");
        // After clear, the entry behaves normally — write succeeds,
        // read returns the written bytes.
        e.set_secret(b"v").expect("set after clear");
        assert_eq!(e.get_secret().unwrap(), b"v");
    }

    #[test]
    fn fault_is_scoped_per_entry() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e_bad = Entry::new("spt-tmock-scope", "bad").expect("entry");
        let e_good = Entry::new("spt-tmock-scope", "good").expect("entry");
        g.set_fault("spt-tmock-scope", "bad", MockFaultKind::PlatformFailure);
        assert!(matches!(
            e_bad.get_secret(),
            Err(keyring::Error::PlatformFailure(_))
        ));
        // The other entry is unaffected.
        e_good.set_secret(b"g").unwrap();
        assert_eq!(e_good.get_secret().unwrap(), b"g");
    }

    #[test]
    fn delete_credential_fault_surfaces() {
        use keyring::Entry;
        let g = install_mock_keyring();
        let e = Entry::new("spt-tmock-del-fault", "u").expect("entry");
        // Seed first so the unfaulted path would have returned Ok.
        e.set_secret(b"v").unwrap();
        g.set_fault("spt-tmock-del-fault", "u", MockFaultKind::NoStorageAccess);
        assert!(matches!(
            e.delete_credential(),
            Err(keyring::Error::NoStorageAccess(_))
        ));
    }

    #[test]
    fn mock_fault_kind_from_round_trips_all_variants() {
        // Each MockFaultKind maps to a distinct keymock::FaultKind, and
        // each FaultKind reconstructs the matching keyring::Error.
        for (kind, label) in [
            (MockFaultKind::PlatformFailure, "platform"),
            (MockFaultKind::NoStorageAccess, "nsa"),
            (MockFaultKind::NoEntry, "ne"),
            (MockFaultKind::BadEncoding, "be"),
            (MockFaultKind::Invalid, "inv"),
        ] {
            let inner: keymock::FaultKind = kind.into();
            // We only need to prove conversion compiles and the inner
            // FaultKind builds a non-panicking keyring::Error.
            let err = inner.to_error();
            // Display impl is exhaustive in keyring; printing exercises
            // the matching arm. Use the label to keep the loop body alive
            // under release builds.
            let s = format!("{err}");
            assert!(!s.is_empty(), "label={label}");
        }
    }
}
