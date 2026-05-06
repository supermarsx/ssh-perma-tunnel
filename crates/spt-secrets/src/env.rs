//! Process-environment backend.
//!
//! Looks up `SPT_SECRET_<NS_UPPER>__<NAME_UPPER>` for the requested
//! reference. `-` and `.` in either segment are normalized to `_`.

use spt_core::{Error, Result};

use crate::backend::{
    secret_bytes, BackendDoctor, BackendKind, SecretBackend, SecretBytes,
};
use crate::reference::SecretRef;

/// Process-environment backend.
#[derive(Default)]
pub struct EnvBackend;

impl EnvBackend {
    /// Construct an [`EnvBackend`].
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compute the expected env-var name for a reference.
    #[must_use]
    pub fn var_name(r: &SecretRef) -> String {
        let ns = normalize(r.ns());
        let name = normalize(r.name());
        format!("SPT_SECRET_{ns}__{name}")
    }
}

fn normalize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '-' | '.' => '_',
            other => other.to_ascii_uppercase(),
        })
        .collect()
}

impl SecretBackend for EnvBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Env
    }

    fn get(&self, r: &SecretRef) -> Result<Option<SecretBytes>> {
        let var = Self::var_name(r);
        match std::env::var(&var) {
            Ok(v) => Ok(Some(secret_bytes(v.into_bytes()))),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(Error::SecretUnavailable {
                reference: r.to_string(),
                reason: format!("env var `{var}` is not valid UTF-8"),
            }),
        }
    }

    fn set(&self, _r: &SecretRef, _value: &[u8]) -> Result<()> {
        Err(Error::UnsupportedPlatform(
            "EnvBackend is read-only; secrets cannot be written through env vars".into(),
        ))
    }

    fn list(&self) -> Result<Vec<SecretRef>> {
        // Enumeration would require parsing every `SPT_SECRET_*` env var
        // back into a (ns, name) tuple, which is ambiguous because `_` is
        // both the segment separator and the within-segment escape. We
        // intentionally return an empty list rather than guess.
        Ok(Vec::new())
    }

    fn remove(&self, _r: &SecretRef) -> Result<bool> {
        Err(Error::UnsupportedPlatform(
            "EnvBackend is read-only; secrets cannot be removed through env vars".into(),
        ))
    }

    fn doctor(&self) -> BackendDoctor {
        BackendDoctor::ok(BackendKind::Env, "process environment readable")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn var_name_table() {
        let cases = [
            (("ns", "name"), "SPT_SECRET_NS__NAME"),
            (("my-ns", "my.key"), "SPT_SECRET_MY_NS__MY_KEY"),
            (("Auth_v2", "Bearer-1"), "SPT_SECRET_AUTH_V2__BEARER_1"),
            (("a.b.c", "d-e-f"), "SPT_SECRET_A_B_C__D_E_F"),
        ];
        for ((ns, name), expected) in cases {
            let r = SecretRef::new(ns, name).unwrap();
            assert_eq!(EnvBackend::var_name(&r), expected, "ref={r}");
        }
    }

    #[test]
    fn get_returns_none_when_unset() {
        let r = SecretRef::new("envtest_unset", "value").unwrap();
        // Make sure it's actually not set.
        std::env::remove_var(EnvBackend::var_name(&r));
        let b = EnvBackend::new();
        assert!(b.get(&r).unwrap().is_none());
    }

    #[test]
    fn get_returns_value_when_set() {
        let r = SecretRef::new("envtest_set", "value").unwrap();
        let var = EnvBackend::var_name(&r);
        // SAFETY: env mutation is process-global; this test uses a unique
        // variable name to avoid collisions with siblings.
        std::env::set_var(&var, "hunter2");
        let b = EnvBackend::new();
        let got = b.get(&r).unwrap().unwrap();
        assert_eq!(got.expose_secret().as_slice(), b"hunter2");
        std::env::remove_var(&var);
    }

    #[test]
    fn set_and_remove_are_unsupported() {
        let r = SecretRef::new("envtest", "ro").unwrap();
        let b = EnvBackend::new();
        assert!(b.set(&r, b"x").is_err());
        assert!(b.remove(&r).is_err());
    }

    #[test]
    fn doctor_is_ok() {
        let b = EnvBackend::new();
        assert!(matches!(b.doctor().status, crate::BackendStatus::Ok));
    }
}
