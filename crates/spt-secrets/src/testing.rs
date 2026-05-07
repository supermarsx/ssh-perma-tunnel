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
use std::sync::{Arc, Mutex};

use secrecy::ExposeSecret;
use spt_core::{Error, Result};
use zeroize::Zeroizing;

use crate::backend::{
    secret_bytes, BackendDoctor, BackendKind, SecretBackend, SecretBytes,
};
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
        Ok(self.entries.lock().unwrap().get(r).cloned().map(secret_bytes))
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
            AlwaysFailKind::SecretCryptoFailed => {
                Error::SecretCryptoFailed(self.reason.clone())
            }
            AlwaysFailKind::PermissionDenied => Error::PermissionDenied(self.reason.clone()),
            AlwaysFailKind::UnsupportedPlatform => {
                Error::UnsupportedPlatform(self.reason.clone())
            }
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
        Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi,
        CredentialPersistence,
    };
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

    type Store = Mutex<HashMap<(String, String), Vec<u8>>>;

    pub(super) fn shared_store() -> &'static Store {
        static S: OnceLock<Store> = OnceLock::new();
        S.get_or_init(|| Mutex::new(HashMap::new()))
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
            shared_store()
                .lock()
                .unwrap()
                .get(&(self.service.clone(), self.user.clone()))
                .cloned()
                .ok_or(keyring::Error::NoEntry)
        }
        fn delete_credential(&self) -> keyring::Result<()> {
            let mut g = shared_store().lock().unwrap();
            if g.remove(&(self.service.clone(), self.user.clone())).is_some() {
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

    pub(super) fn clear_store() {
        shared_store().lock().unwrap().clear();
    }
}

/// Install a process-wide `keyring` mock that uses a shared in-memory store.
///
/// Idempotent — installation runs at most once per process. Returns a guard
/// whose `Drop` impl clears the store so successive tests don't leak state
/// across each other. The mock itself remains installed (the `keyring` crate
/// only allows the default builder to be set once per process).
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
    keymock::install_once();
    keymock::clear_store();
    KeychainTestGuard { _priv: () }
}

/// RAII guard returned by [`seeded_keychain`]. Clears the shared mock store
/// on drop.
pub struct KeychainTestGuard {
    _priv: (),
}

impl Drop for KeychainTestGuard {
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
}
