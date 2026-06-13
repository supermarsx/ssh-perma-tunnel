//! Multi-backend resolver.
//!
//! The resolver consults a chain of backends in declared order. The first
//! `Ok(Some(_))` wins. `Ok(None)` is interpreted as "this backend has no
//! such reference" and resolution falls through. A backend returning an
//! `Err` short-circuits the chain — backend errors must surface, not be
//! masked by a later hit, so that misconfiguration is loud.
//!
//! Default chain used by the binary: `keychain -> vault -> env -> file`.

use std::sync::Arc;

use spt_core::{Error, Result};

use crate::backend::{BackendKind, SecretBackend, SecretBytes};
use crate::reference::SecretRef;

/// Chain of secret backends.
pub struct Resolver {
    backends: Vec<Arc<dyn SecretBackend>>,
}

impl Resolver {
    /// Build a resolver from an explicit list of backends.
    #[must_use]
    pub fn new(backends: Vec<Arc<dyn SecretBackend>>) -> Self {
        Self { backends }
    }

    /// Insert a backend at the end of the chain.
    pub fn push(&mut self, backend: Arc<dyn SecretBackend>) {
        self.backends.push(backend);
    }

    /// Iterate over the backends in chain order.
    pub fn backends(&self) -> impl Iterator<Item = &dyn SecretBackend> {
        self.backends.iter().map(std::convert::AsRef::as_ref)
    }

    /// Borrow the underlying `Arc`-wrapped backend chain. Callers that need
    /// to share ownership of the backends with another component (e.g. an
    /// `Ssh2Protocol::builder().backend(...)` chain) clone these `Arc`s.
    #[must_use]
    pub fn backend_arcs(&self) -> &[Arc<dyn SecretBackend>] {
        &self.backends
    }

    /// Resolve a reference. Returns the first backend hit. Errors with
    /// [`Error::SecretUnavailable`] when no backend has a value.
    pub fn resolve(&self, r: &SecretRef) -> Result<SecretBytes> {
        for backend in &self.backends {
            match backend.get(r) {
                Ok(Some(v)) => return Ok(v),
                Ok(None) => {} // 1.88 lint: redundant_continue
                Err(e) => return Err(e),
            }
        }
        Err(Error::SecretUnavailable {
            reference: r.to_string(),
            reason: format!(
                "no backend resolved the reference (chain: {})",
                self.chain_description()
            ),
        })
    }

    /// Try to resolve, returning `Ok(None)` rather than an error when the
    /// reference is missing. Backend failures still surface.
    pub fn try_resolve(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        for backend in &self.backends {
            match backend.get(r) {
                Ok(Some(v)) => return Ok(Some(v)),
                Ok(None) => {} // 1.88 lint: redundant_continue
                Err(e) => return Err(e),
            }
        }
        Ok(None)
    }

    fn chain_description(&self) -> String {
        self.backends
            .iter()
            .map(|b| match b.kind() {
                BackendKind::Keychain => "keychain",
                BackendKind::Vault => "vault",
                BackendKind::Env => "env",
                BackendKind::File => "file",
            })
            .collect::<Vec<_>>()
            .join(" → ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::{secret_bytes, BackendDoctor};
    use secrecy::ExposeSecret;
    use std::sync::Mutex;

    /// Mock backend with an in-memory map.
    struct Mock {
        kind: BackendKind,
        store: Mutex<std::collections::HashMap<String, Vec<u8>>>,
        fail_on_get: bool,
    }

    impl Mock {
        fn new(kind: BackendKind) -> Self {
            Self {
                kind,
                store: Mutex::new(std::collections::HashMap::new()),
                fail_on_get: false,
            }
        }
        fn fail(kind: BackendKind) -> Self {
            Self {
                kind,
                store: Mutex::new(std::collections::HashMap::new()),
                fail_on_get: true,
            }
        }
        fn put(&self, r: &SecretRef, v: &[u8]) {
            self.store.lock().unwrap().insert(r.to_string(), v.to_vec());
        }
    }

    impl SecretBackend for Mock {
        fn kind(&self) -> BackendKind {
            self.kind
        }
        fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
            if self.fail_on_get {
                return Err(Error::SecretUnavailable {
                    reference: r.to_string(),
                    reason: "mock failure".into(),
                });
            }
            Ok(self
                .store
                .lock()
                .unwrap()
                .get(&r.to_string())
                .cloned()
                .map(secret_bytes))
        }
        fn set(&self, r: &SecretRef, v: &[u8]) -> Result<()> {
            self.put(r, v);
            Ok(())
        }
        fn list(&self) -> Result<Vec<SecretRef>> {
            Ok(Vec::new())
        }
        fn remove(&self, _r: &SecretRef) -> Result<bool> {
            Ok(false)
        }
        fn doctor(&self) -> BackendDoctor {
            BackendDoctor::ok(self.kind, "mock")
        }
    }

    #[test]
    fn high_priority_wins() {
        let high = Arc::new(Mock::new(BackendKind::Keychain));
        let low = Arc::new(Mock::new(BackendKind::Vault));
        let r = SecretRef::new("ns", "n").unwrap();
        high.put(&r, b"high");
        low.put(&r, b"low");
        let res = Resolver::new(vec![high, low]);
        let got = res.resolve(&r).unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"high");
    }

    #[test]
    fn falls_through_on_miss() {
        let high = Arc::new(Mock::new(BackendKind::Keychain));
        let low = Arc::new(Mock::new(BackendKind::Vault));
        let r = SecretRef::new("ns", "n").unwrap();
        low.put(&r, b"low");
        let res = Resolver::new(vec![high, low]);
        let got = res.resolve(&r).unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"low");
    }

    #[test]
    fn missing_reports_secret_unavailable() {
        let res = Resolver::new(vec![Arc::new(Mock::new(BackendKind::Env))]);
        let r = SecretRef::new("ns", "absent").unwrap();
        let err = res.resolve(&r).unwrap_err();
        match err {
            Error::SecretUnavailable { reference, .. } => {
                assert_eq!(reference, "secret://ns/absent");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn try_resolve_returns_none_when_absent() {
        let res = Resolver::new(vec![Arc::new(Mock::new(BackendKind::Env))]);
        let r = SecretRef::new("ns", "absent").unwrap();
        assert!(res.try_resolve(&r).unwrap().is_none());
    }

    #[test]
    fn backend_error_short_circuits() {
        let bad = Arc::new(Mock::fail(BackendKind::Keychain));
        let good = Arc::new(Mock::new(BackendKind::Vault));
        let r = SecretRef::new("ns", "n").unwrap();
        good.put(&r, b"ok");
        let res = Resolver::new(vec![bad, good]);
        // The vault hit must NOT mask the keychain error.
        let err = res.resolve(&r).unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
    }

    #[test]
    fn try_resolve_propagates_backend_error() {
        let bad = Arc::new(Mock::fail(BackendKind::Keychain));
        let res = Resolver::new(vec![bad]);
        let r = SecretRef::new("ns", "n").unwrap();
        let err = res.try_resolve(&r).unwrap_err();
        assert!(matches!(err, Error::SecretUnavailable { .. }));
    }

    #[test]
    fn try_resolve_returns_hit_value() {
        let m = Arc::new(Mock::new(BackendKind::File));
        let r = SecretRef::new("ns", "n").unwrap();
        m.put(&r, b"hit");
        let res = Resolver::new(vec![m]);
        let got = res.try_resolve(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"hit");
    }

    #[test]
    fn push_appends_to_chain() {
        let mut res: Resolver = Resolver::new(vec![]);
        res.push(Arc::new(Mock::new(BackendKind::Env)));
        res.push(Arc::new(Mock::new(BackendKind::Vault)));
        let kinds: Vec<BackendKind> = res.backends().map(SecretBackend::kind).collect();
        assert_eq!(kinds, vec![BackendKind::Env, BackendKind::Vault]);
    }

    #[test]
    fn backend_arcs_returns_chain() {
        let a: Arc<dyn SecretBackend> = Arc::new(Mock::new(BackendKind::Keychain));
        let b: Arc<dyn SecretBackend> = Arc::new(Mock::new(BackendKind::Vault));
        let res = Resolver::new(vec![a, b]);
        let arcs = res.backend_arcs();
        assert_eq!(arcs.len(), 2);
        assert_eq!(arcs[0].kind(), BackendKind::Keychain);
        assert_eq!(arcs[1].kind(), BackendKind::Vault);
    }

    #[test]
    fn missing_reason_includes_full_chain_description() {
        let res = Resolver::new(vec![
            Arc::new(Mock::new(BackendKind::Keychain)),
            Arc::new(Mock::new(BackendKind::Vault)),
            Arc::new(Mock::new(BackendKind::Env)),
            Arc::new(Mock::new(BackendKind::File)),
        ]);
        let r = SecretRef::new("ns", "absent").unwrap();
        let err = res.resolve(&r).unwrap_err();
        let reason = match err {
            Error::SecretUnavailable { reason, .. } => reason,
            other => panic!("unexpected {other:?}"),
        };
        assert!(reason.contains("keychain"));
        assert!(reason.contains("vault"));
        assert!(reason.contains("env"));
        assert!(reason.contains("file"));
        assert!(reason.contains("→"));
    }

    #[test]
    fn empty_resolver_misses() {
        let res = Resolver::new(vec![]);
        let r = SecretRef::new("ns", "n").unwrap();
        assert!(res.try_resolve(&r).unwrap().is_none());
        assert!(matches!(
            res.resolve(&r).unwrap_err(),
            Error::SecretUnavailable { .. }
        ));
    }
}
