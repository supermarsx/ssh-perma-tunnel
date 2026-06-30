//! `secret://ns/name` references.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

const SCHEME: &str = "secret://";

/// A typed `secret://<ns>/<name>` reference.
///
/// Both `ns` and `name` are restricted to ASCII alphanumerics plus `_`, `-`,
/// and `.`. Empty segments are rejected. Round-trips through
/// [`std::fmt::Display`] / [`std::str::FromStr`] without modification.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SecretRef {
    ns: String,
    name: String,
}

/// Errors produced while parsing a [`SecretRef`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReferenceError {
    /// String did not start with the `secret://` scheme.
    #[error("missing `secret://` scheme")]
    MissingScheme,
    /// Path part was not exactly `<ns>/<name>`.
    #[error("invalid path: expected `secret://<ns>/<name>`")]
    InvalidPath,
    /// Namespace was empty or contained disallowed characters.
    #[error("invalid namespace `{0}`: must be non-empty alphanumerics, `_`, `-`, or `.`")]
    InvalidNamespace(String),
    /// Name was empty or contained disallowed characters.
    #[error("invalid name `{0}`: must be non-empty alphanumerics, `_`, `-`, or `.`")]
    InvalidName(String),
}

impl SecretRef {
    /// Construct a reference, validating both segments.
    pub fn new(ns: impl Into<String>, name: impl Into<String>) -> Result<Self, ReferenceError> {
        let ns = ns.into();
        let name = name.into();
        if !is_valid_segment(&ns) {
            return Err(ReferenceError::InvalidNamespace(ns));
        }
        if !is_valid_segment(&name) {
            return Err(ReferenceError::InvalidName(name));
        }
        Ok(Self { ns, name })
    }

    /// Namespace segment.
    #[must_use]
    pub fn ns(&self) -> &str {
        &self.ns
    }

    /// Name segment.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Additional Authenticated Data used by the vault backend.
    ///
    /// Encodes `ns || 0x00 || name` so that ciphertexts cannot be silently
    /// rebound to a different reference.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.ns.len() + 1 + self.name.len());
        out.extend_from_slice(self.ns.as_bytes());
        out.push(0);
        out.extend_from_slice(self.name.as_bytes());
        out
    }
}

fn is_valid_segment(s: &str) -> bool {
    // Reject the path-traversal tokens `.` and `..` outright: a segment of
    // those would let `<root>/<ns>/<name>` escape the secrets root in the file
    // backend (`secret://../foo` → `<root>/../foo`). The ASCII allowlist below
    // already excludes every path separator (`/`, `\`), the drive/scheme marker
    // (`:`), and NUL, so a validated segment is always a single in-root
    // filesystem component and can never start an absolute path or traverse.
    if s.is_empty() || s == "." || s == ".." {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

impl fmt::Display for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "secret://{}/{}", self.ns, self.name)
    }
}

impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Reference is not itself a secret, but use the canonical form
        // rather than exposing field names.
        write!(f, "SecretRef({self})")
    }
}

impl FromStr for SecretRef {
    type Err = ReferenceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix(SCHEME)
            .ok_or(ReferenceError::MissingScheme)?;
        let mut parts = rest.splitn(2, '/');
        let ns = parts.next().unwrap_or("");
        let name = parts.next().ok_or(ReferenceError::InvalidPath)?;
        if name.contains('/') {
            return Err(ReferenceError::InvalidPath);
        }
        Self::new(ns.to_owned(), name.to_owned())
    }
}

impl TryFrom<String> for SecretRef {
    type Error = ReferenceError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<SecretRef> for String {
    fn from(r: SecretRef) -> Self {
        r.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical() {
        let r: SecretRef = "secret://ns/name".parse().unwrap();
        assert_eq!(r.ns(), "ns");
        assert_eq!(r.name(), "name");
    }

    #[test]
    fn display_round_trips() {
        let inputs = [
            "secret://a/b",
            "secret://my-ns/my.key",
            "secret://NS_1/name-1.v2",
        ];
        for s in inputs {
            let r: SecretRef = s.parse().unwrap();
            assert_eq!(r.to_string(), s);
            let r2: SecretRef = r.to_string().parse().unwrap();
            assert_eq!(r, r2);
        }
    }

    #[test]
    fn rejects_invalid_inputs() {
        let cases = [
            ("", ReferenceError::MissingScheme),
            ("https://a/b", ReferenceError::MissingScheme),
            ("secret://only", ReferenceError::InvalidPath),
            ("secret://ns/name/extra", ReferenceError::InvalidPath),
            (
                "secret:///name",
                ReferenceError::InvalidNamespace(String::new()),
            ),
            ("secret://ns/", ReferenceError::InvalidName(String::new())),
            (
                "secret://b@d/name",
                ReferenceError::InvalidNamespace("b@d".into()),
            ),
            (
                "secret://ns/n a m e",
                ReferenceError::InvalidName("n a m e".into()),
            ),
            ("secret://ns/na/me", ReferenceError::InvalidPath),
            (
                "secret://ñs/name",
                ReferenceError::InvalidNamespace("ñs".into()),
            ),
        ];
        for (input, expected) in cases {
            let err = input.parse::<SecretRef>().unwrap_err();
            assert_eq!(err, expected, "input={input:?}");
        }
    }

    #[test]
    fn rejects_path_traversal_segments() {
        // `secret://../foo` parses to ns="..", which must be rejected so the
        // file backend cannot resolve `<root>/../foo` outside the secrets root.
        assert_eq!(
            "secret://../foo".parse::<SecretRef>().unwrap_err(),
            ReferenceError::InvalidNamespace("..".into()),
        );
        // A `..` (or `.`) leaf name is rejected too.
        assert_eq!(
            "secret://ns/..".parse::<SecretRef>().unwrap_err(),
            ReferenceError::InvalidName("..".into()),
        );
        assert_eq!(
            "secret://ns/.".parse::<SecretRef>().unwrap_err(),
            ReferenceError::InvalidName(".".into()),
        );
        assert_eq!(
            "secret://./name".parse::<SecretRef>().unwrap_err(),
            ReferenceError::InvalidNamespace(".".into()),
        );
        // A nested traversal still trips the `/`-in-name guard first.
        assert_eq!(
            "secret://ns/../../etc/x".parse::<SecretRef>().unwrap_err(),
            ReferenceError::InvalidPath,
        );
    }

    #[test]
    fn new_rejects_traversal_separators_and_nul() {
        // Direct construction (bypassing the scheme parser) must reject the same
        // dangerous components: traversal tokens, both separators, an absolute
        // marker, and an embedded NUL.
        for bad in ["..", ".", "", "a/b", "a\\b", "/abs", "a\0b", "ns:name"] {
            assert!(
                SecretRef::new(bad, "name").is_err(),
                "ns segment {bad:?} must be rejected"
            );
            assert!(
                SecretRef::new("ns", bad).is_err(),
                "name segment {bad:?} must be rejected"
            );
        }
        // A normal reference is unaffected.
        let r = SecretRef::new("ns", "name").unwrap();
        assert_eq!((r.ns(), r.name()), ("ns", "name"));
        // Interior dots remain legal (only a bare `.`/`..` is rejected).
        assert!(SecretRef::new("a.b", "c.d.v2").is_ok());
    }

    #[test]
    fn aad_encodes_with_separator() {
        let r = SecretRef::new("ns", "name").unwrap();
        assert_eq!(r.aad(), b"ns\x00name");
    }

    #[test]
    fn debug_does_not_expose_inner_fields() {
        let r = SecretRef::new("ns", "name").unwrap();
        let dbg = format!("{r:?}");
        assert!(dbg.contains("secret://ns/name"));
        assert!(!dbg.contains("ns:"));
    }

    #[test]
    fn serde_round_trip() {
        let r = SecretRef::new("ns", "name").unwrap();
        let j = serde_json::to_string(&r).unwrap();
        assert_eq!(j, "\"secret://ns/name\"");
        let back: SecretRef = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
    }
}
