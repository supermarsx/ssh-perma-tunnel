//! Integration tests for [`spt_secrets::KeychainBackend`] driven by a
//! local mock `keyring` builder with per-entry fault injection.
//!
//! ## Process isolation
//!
//! Each file in `tests/` compiles to its own binary and therefore runs in
//! its own process. That means this binary fully owns the
//! `keyring::set_default_credential_builder` global state and the
//! per-entry fault map below — no risk of contention with the lib-test
//! binary's `vault::tests` module.
//!
//! The IT file inlines a minimal mock rather than depending on
//! `spt_secrets::testing` so that no `Cargo.toml` change (adding the
//! `testing` dev-dep feature) is required. The mock has the same shape
//! as the one in `crates/spt-secrets/src/testing.rs::keymock` plus a
//! fault map keyed on `(service, user)`.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use keyring::credential::{
    Credential, CredentialApi, CredentialBuilder, CredentialBuilderApi, CredentialPersistence,
};
use secrecy::ExposeSecret;
use spt_core::Error;
use spt_secrets::{BackendKind, BackendStatus, KeychainBackend, SecretBackend, SecretRef};

// ---------------------------------------------------------------------------
// Local mock with fault injection.
// ---------------------------------------------------------------------------

type Store = Mutex<HashMap<(String, String), Vec<u8>>>;
type FaultMap = Mutex<HashMap<(String, String), FaultKind>>;

#[derive(Debug, Clone, Copy)]
enum FaultKind {
    PlatformFailure,
    NoStorageAccess,
    NoEntry,
    BadEncoding,
    Invalid,
}

impl FaultKind {
    fn to_error(self) -> keyring::Error {
        match self {
            Self::PlatformFailure => {
                keyring::Error::PlatformFailure(Box::new(std::io::Error::other("mock plat")))
            }
            Self::NoStorageAccess => {
                keyring::Error::NoStorageAccess(Box::new(std::io::Error::other("mock nsa")))
            }
            Self::NoEntry => keyring::Error::NoEntry,
            Self::BadEncoding => keyring::Error::BadEncoding(Vec::new()),
            Self::Invalid => keyring::Error::Invalid("attr".to_owned(), "bad".to_owned()),
        }
    }
}

fn shared_store() -> &'static Store {
    static S: OnceLock<Store> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fault_map() -> &'static FaultMap {
    static F: OnceLock<FaultMap> = OnceLock::new();
    F.get_or_init(|| Mutex::new(HashMap::new()))
}

fn set_fault(service: &str, user: &str, kind: FaultKind) {
    fault_map()
        .lock()
        .unwrap()
        .insert((service.to_owned(), user.to_owned()), kind);
}

fn clear_fault(service: &str, user: &str) {
    fault_map()
        .lock()
        .unwrap()
        .remove(&(service.to_owned(), user.to_owned()));
}

fn current_fault(service: &str, user: &str) -> Option<FaultKind> {
    fault_map()
        .lock()
        .unwrap()
        .get(&(service.to_owned(), user.to_owned()))
        .copied()
}

#[derive(Debug)]
struct MockCred {
    service: String,
    user: String,
}

impl CredentialApi for MockCred {
    fn set_password(&self, password: &str) -> keyring::Result<()> {
        self.set_secret(password.as_bytes())
    }
    fn set_secret(&self, secret: &[u8]) -> keyring::Result<()> {
        if let Some(k) = current_fault(&self.service, &self.user) {
            return Err(k.to_error());
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
        if let Some(k) = current_fault(&self.service, &self.user) {
            return Err(k.to_error());
        }
        shared_store()
            .lock()
            .unwrap()
            .get(&(self.service.clone(), self.user.clone()))
            .cloned()
            .ok_or(keyring::Error::NoEntry)
    }
    fn delete_credential(&self) -> keyring::Result<()> {
        if let Some(k) = current_fault(&self.service, &self.user) {
            return Err(k.to_error());
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

struct MockBuilder;

impl CredentialBuilderApi for MockBuilder {
    fn build(
        &self,
        _target: Option<&str>,
        service: &str,
        user: &str,
    ) -> keyring::Result<Box<Credential>> {
        Ok(Box::new(MockCred {
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

/// Idempotent: installs the mock builder once per process. Subsequent
/// calls are no-ops (the `OnceLock` guards re-installation).
fn install_mock_once() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        keyring::set_default_credential_builder(Box::new(MockBuilder) as Box<CredentialBuilder>);
    });
}

/// Use a unique service per test to avoid cross-test bleed-through in the
/// shared store. Each test below picks a distinct prefix and clears its
/// own fault rows at the end via `clear_fault`.
fn setup(service: &str) {
    install_mock_once();
    // Wipe any pre-existing data for this service from previous test runs
    // in the same binary (Cargo may share a process when --test-threads=1).
    shared_store()
        .lock()
        .unwrap()
        .retain(|(s, _), _| s != service);
    let mut fmap = fault_map().lock().unwrap();
    fmap.retain(|(s, _), _| s != service);
}

fn fresh_ref(name: &str) -> SecretRef {
    SecretRef::new("kchn-it", name).expect("valid ref")
}

// ---------------------------------------------------------------------------
// Full lifecycle through the mock.
// ---------------------------------------------------------------------------

#[test]
fn full_lifecycle_set_get_remove() {
    let svc = "spt-kchn-it-lifecycle";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("token");

    // 1) absent → None
    assert!(kc.get(&r).unwrap().is_none());

    // 2) set → readable → list still empty (keychain backend's list
    //    is documented as a no-op).
    kc.set(&r, b"deadbeef").unwrap();
    let got = kc.get(&r).unwrap().expect("some");
    assert_eq!(got.expose_secret().as_slice(), b"deadbeef");
    assert!(kc.list().unwrap().is_empty());

    // 3) overwrite
    kc.set(&r, b"updated").unwrap();
    let got = kc.get(&r).unwrap().expect("some");
    assert_eq!(got.expose_secret().as_slice(), b"updated");

    // 4) remove (true), then remove (false), then get → None
    assert!(kc.remove(&r).unwrap());
    assert!(!kc.remove(&r).unwrap());
    assert!(kc.get(&r).unwrap().is_none());
}

// ---------------------------------------------------------------------------
// Fault injection: get / set / remove
// ---------------------------------------------------------------------------

#[test]
fn get_with_platform_failure_returns_secret_unavailable() {
    let svc = "spt-kchn-it-get-platfail";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("k");

    set_fault(svc, "kchn-it:k", FaultKind::PlatformFailure);
    let err = kc.get(&r).unwrap_err();
    match err {
        Error::SecretUnavailable { reference, reason } => {
            assert_eq!(reference, "secret://kchn-it/k");
            assert!(reason.contains("keychain get"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    clear_fault(svc, "kchn-it:k");
}

#[test]
fn get_with_no_storage_access_returns_secret_unavailable() {
    let svc = "spt-kchn-it-get-nsa";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("k");

    set_fault(svc, "kchn-it:k", FaultKind::NoStorageAccess);
    let err = kc.get(&r).unwrap_err();
    assert!(matches!(err, Error::SecretUnavailable { .. }));
    clear_fault(svc, "kchn-it:k");
}

#[test]
fn get_with_bad_encoding_returns_secret_unavailable() {
    let svc = "spt-kchn-it-get-badenc";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("k");

    set_fault(svc, "kchn-it:k", FaultKind::BadEncoding);
    let err = kc.get(&r).unwrap_err();
    assert!(matches!(err, Error::SecretUnavailable { .. }));
    clear_fault(svc, "kchn-it:k");
}

#[test]
fn get_with_no_entry_fault_returns_none() {
    let svc = "spt-kchn-it-get-noentry";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("k");

    // `NoEntry` is the short-circuit path: backend must translate to
    // `Ok(None)`, not an error.
    set_fault(svc, "kchn-it:k", FaultKind::NoEntry);
    assert!(kc.get(&r).unwrap().is_none());
    clear_fault(svc, "kchn-it:k");
}

#[test]
fn set_with_platform_failure_returns_secret_unavailable() {
    let svc = "spt-kchn-it-set-platfail";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("k");

    set_fault(svc, "kchn-it:k", FaultKind::PlatformFailure);
    let err = kc.set(&r, b"value").unwrap_err();
    match err {
        Error::SecretUnavailable { reference, reason } => {
            assert_eq!(reference, "secret://kchn-it/k");
            assert!(reason.contains("keychain set"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    clear_fault(svc, "kchn-it:k");
}

#[test]
fn set_with_invalid_fault_returns_secret_unavailable() {
    let svc = "spt-kchn-it-set-invalid";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("k");

    set_fault(svc, "kchn-it:k", FaultKind::Invalid);
    let err = kc.set(&r, b"v").unwrap_err();
    assert!(matches!(err, Error::SecretUnavailable { .. }));
    clear_fault(svc, "kchn-it:k");
}

#[test]
fn remove_with_platform_failure_returns_secret_unavailable() {
    let svc = "spt-kchn-it-rm-platfail";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let r = fresh_ref("k");

    // Seed first so the mock would otherwise return Ok(true).
    kc.set(&r, b"v").unwrap();
    set_fault(svc, "kchn-it:k", FaultKind::PlatformFailure);
    let err = kc.remove(&r).unwrap_err();
    match err {
        Error::SecretUnavailable { reference, reason } => {
            assert_eq!(reference, "secret://kchn-it/k");
            assert!(reason.contains("keychain remove"));
        }
        other => panic!("unexpected error: {other:?}"),
    }
    clear_fault(svc, "kchn-it:k");
}

// ---------------------------------------------------------------------------
// Fault injection: doctor() branches
// ---------------------------------------------------------------------------

#[test]
fn doctor_ok_path_through_mock() {
    let svc = "spt-kchn-it-doctor-ok";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    let d = kc.doctor();
    assert_eq!(d.kind, BackendKind::Keychain);
    assert!(matches!(d.status, BackendStatus::Ok));
    assert!(d.message.contains("reachable"));
    assert!(d.remediation.is_none());
}

#[test]
fn doctor_platform_failure_is_unavailable() {
    let svc = "spt-kchn-it-doctor-platfail";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    set_fault(svc, "spt-doctor-probe", FaultKind::PlatformFailure);
    let d = kc.doctor();
    assert_eq!(d.kind, BackendKind::Keychain);
    assert!(matches!(d.status, BackendStatus::Unavailable));
    assert!(d.message.contains("platform failure"));
    assert!(d.remediation.is_some());
    clear_fault(svc, "spt-doctor-probe");
}

#[test]
fn doctor_no_storage_access_is_unavailable() {
    let svc = "spt-kchn-it-doctor-nsa";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    set_fault(svc, "spt-doctor-probe", FaultKind::NoStorageAccess);
    let d = kc.doctor();
    assert!(matches!(d.status, BackendStatus::Unavailable));
    assert!(d.message.contains("no storage access"));
    assert!(d.remediation.is_some());
    clear_fault(svc, "spt-doctor-probe");
}

#[test]
fn doctor_other_error_is_degraded() {
    let svc = "spt-kchn-it-doctor-bad-encoding";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    // `BadEncoding` is neither NoEntry nor PlatformFailure nor
    // NoStorageAccess — falls into the wildcard "degraded" arm.
    set_fault(svc, "spt-doctor-probe", FaultKind::BadEncoding);
    let d = kc.doctor();
    assert!(matches!(d.status, BackendStatus::Degraded));
    assert!(d.message.contains("probe error"));
    clear_fault(svc, "spt-doctor-probe");
}

#[test]
fn doctor_invalid_error_is_degraded() {
    let svc = "spt-kchn-it-doctor-invalid";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);
    set_fault(svc, "spt-doctor-probe", FaultKind::Invalid);
    let d = kc.doctor();
    assert!(matches!(d.status, BackendStatus::Degraded));
    clear_fault(svc, "spt-doctor-probe");
}

// ---------------------------------------------------------------------------
// Combined: round-trip across multiple namespaces, then doctor still Ok.
// ---------------------------------------------------------------------------

#[test]
fn multiple_namespaces_coexist_under_one_service() {
    let svc = "spt-kchn-it-multi-ns";
    setup(svc);
    let kc = KeychainBackend::with_service(svc);

    let r1 = SecretRef::new("alpha", "one").unwrap();
    let r2 = SecretRef::new("beta", "two").unwrap();
    let r3 = SecretRef::new("alpha", "three").unwrap();
    kc.set(&r1, b"1").unwrap();
    kc.set(&r2, b"2").unwrap();
    kc.set(&r3, b"3").unwrap();

    assert_eq!(
        kc.get(&r1).unwrap().unwrap().expose_secret().as_slice(),
        b"1"
    );
    assert_eq!(
        kc.get(&r2).unwrap().unwrap().expose_secret().as_slice(),
        b"2"
    );
    assert_eq!(
        kc.get(&r3).unwrap().unwrap().expose_secret().as_slice(),
        b"3"
    );

    let d = kc.doctor();
    assert!(matches!(d.status, BackendStatus::Ok));
}
