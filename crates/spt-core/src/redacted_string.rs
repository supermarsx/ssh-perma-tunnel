//! [`RedactedString`] — a secret-shaped owned string newtype that:
//!
//! * **never reveals its contents in `Debug`** (prints `<redacted>`),
//! * **zeroes its heap allocation on drop** via the `zeroize` crate,
//! * **compares in constant time** using the `subtle` crate (so equality
//!   checks against attacker-controlled inputs do not leak via timing),
//! * **serializes transparently** as the underlying string (so TOML/JSON
//!   round-trips through the config schema preserve the value byte-for-byte),
//! * **deserializes transparently** from any string value.
//!
//! The type is meant for *config-shaped* secrets — passwords, passphrases,
//! tokens, VAPID private keys, SNMP USM auth/privacy secrets — that flow
//! through `spt-config::schema` and end up in long-lived structs the user
//! inspects via `{:?}`. It is **not** a substitute for `secrecy::SecretBox`
//! when stronger guarantees (no `Display`, `mlock`-backed allocator) are
//! required by the consumer; see `spt-secrets` for those.
//!
//! ### Display vs Debug
//!
//! `Debug` is the only formatter that is *guaranteed* to be safe to leak —
//! every logging surface in the workspace formats values with `{:?}` (or
//! via `tracing`'s `Debug` shim) before redaction runs. `Display` forwards
//! to the inner string and is intended for **explicit, audited reveal**
//! sites only (passphrase prompts, secret-reveal TUI flows, etc.). Callers
//! are responsible for not piping `format!("{val}")` into a log sink.
//!
//! ### Construction
//!
//! `RedactedString::new` and `From<String>` / `From<&str>` all move the
//! string onto the heap as a boxed `str`, then take ownership. This lets
//! the type zero exactly the bytes it owns at drop time without
//! re-allocation (the `Box<str>` is fixed-capacity).

use core::fmt;
use core::ops::Deref;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;

/// Sentinel string used by `Debug` and exported so other crates can match
/// against the exact byte sequence in tests / golden snapshots.
pub const REDACTED_DEBUG: &str = "<redacted>";

/// A string whose contents are zeroed on drop and never appear in `Debug`.
///
/// See the [module docs](self) for the full contract.
pub struct RedactedString {
    /// `Box<str>` is fixed-capacity: there is no spare buffer that could be
    /// left behind after `zeroize`, and `zeroize::Zeroize` is implemented
    /// for `str` (it overwrites every byte with `0`). Both invariants are
    /// load-bearing for `Drop`.
    inner: Box<str>,
}

impl RedactedString {
    /// Construct from any string-like value.
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self {
            inner: s.into().into_boxed_str(),
        }
    }

    /// Borrow the secret as `&str` for callers that must *explicitly*
    /// pull the cleartext out. Equivalent to deref but spelled to be
    /// greppable in audits.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Length of the inner string in bytes. Safe to log.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the inner string is empty. Safe to log.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

// --- Debug: never reveal ----------------------------------------------------

impl fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_DEBUG)
    }
}

// --- Display: forwards to inner. Use only at audited reveal sites. ----------

impl fmt::Display for RedactedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.inner)
    }
}

// --- Deref<Target=str>: lets &RedactedString be used where &str is wanted ---

impl Deref for RedactedString {
    type Target = str;
    fn deref(&self) -> &str {
        &self.inner
    }
}

impl AsRef<str> for RedactedString {
    fn as_ref(&self) -> &str {
        &self.inner
    }
}

// --- From / Into conversions ------------------------------------------------

impl From<String> for RedactedString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for RedactedString {
    fn from(s: &str) -> Self {
        Self::new(s.to_owned())
    }
}

impl From<Box<str>> for RedactedString {
    fn from(s: Box<str>) -> Self {
        Self { inner: s }
    }
}

// --- Equality: constant-time via `subtle` -----------------------------------
//
// Two strings with different *lengths* obviously can't be equal. The byte-
// compare itself runs over `min(a.len(), b.len())` bytes regardless of where
// they first differ, which is what `ConstantTimeEq for [u8]` guarantees.
// A length mismatch short-circuits, which is fine: callers should treat the
// length as non-secret (we even expose `len()`).

impl PartialEq for RedactedString {
    fn eq(&self, other: &Self) -> bool {
        self.inner.as_bytes().ct_eq(other.inner.as_bytes()).into()
    }
}

impl Eq for RedactedString {}

// Compare against plain `&str` too — useful for tests and for asserting a
// reference shape like `"secret://…"` without leaking the cleartext into
// the failure message (because `Debug` redacts).
impl PartialEq<&str> for RedactedString {
    fn eq(&self, other: &&str) -> bool {
        self.inner.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

impl PartialEq<str> for RedactedString {
    fn eq(&self, other: &str) -> bool {
        self.inner.as_bytes().ct_eq(other.as_bytes()).into()
    }
}

// --- Clone ------------------------------------------------------------------

impl Clone for RedactedString {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

// --- Default ---------------------------------------------------------------

impl Default for RedactedString {
    fn default() -> Self {
        Self {
            inner: String::new().into_boxed_str(),
        }
    }
}

// --- Drop / Zeroize --------------------------------------------------------

impl Drop for RedactedString {
    fn drop(&mut self) {
        // `Zeroize for str` (via `[u8]`) overwrites every byte with `0`,
        // including the last byte if it isn't the start of a code point
        // (`zeroize` operates on the raw byte buffer, not on code-point
        // boundaries). After this the `Box<str>` still owns a valid UTF-8
        // buffer because all-zero bytes form valid UTF-8.
        self.inner.zeroize();
    }
}

// --- serde -----------------------------------------------------------------

impl Serialize for RedactedString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.inner)
    }
}

impl<'de> Deserialize<'de> for RedactedString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // We deliberately deserialize through `String` then move into a
        // boxed `str`. The transient `String` is dropped at the end of
        // this function — its buffer is *not* zeroed (we'd need a custom
        // visitor with a `Zeroizing<String>` to do that, and the upstream
        // intermediate buffers in `serde-toml` / `serde-json` aren't
        // wipeable either). Treat the deserialize boundary as the secret-
        // ingress point and pair this with `spt-mem-hygiene` for the
        // process-wide guarantees.
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

#[cfg(test)]
mod tests {
    use super::{RedactedString, REDACTED_DEBUG};

    #[test]
    fn debug_never_reveals_inner() {
        let r = RedactedString::new("hunter2");
        let dbg = format!("{r:?}");
        assert_eq!(dbg, REDACTED_DEBUG);
        assert!(!dbg.contains("hunter2"));
    }

    #[test]
    fn debug_redacts_in_derive_context() {
        // Verify that participating in a derived `Debug` of an outer
        // struct still hides the inner value — this is the practical
        // shape callers depend on.
        #[derive(Debug)]
        #[allow(dead_code)]
        struct Wrap {
            label: &'static str,
            secret: RedactedString,
        }
        let w = Wrap {
            label: "vapid_private_key",
            secret: RedactedString::new("BNcRdreALRFXTkOiUF12345abcdef"),
        };
        let dbg = format!("{w:?}");
        assert!(dbg.contains("vapid_private_key"));
        assert!(dbg.contains(REDACTED_DEBUG));
        assert!(!dbg.contains("BNcRdreALRFXTkOiUF12345abcdef"));
    }

    #[test]
    fn display_reveals_inner() {
        let r = RedactedString::new("plaintext");
        assert_eq!(format!("{r}"), "plaintext");
    }

    #[test]
    fn deref_to_str_works() {
        let r = RedactedString::new("abc/def");
        let s: &str = &r;
        assert_eq!(s, "abc/def");
        assert!(r.starts_with("abc"));
        assert_eq!(r.len(), 7);
    }

    #[test]
    fn partial_eq_string_and_self() {
        let a = RedactedString::new("same");
        let b = RedactedString::new("same");
        let c = RedactedString::new("diff");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a, "same");
        assert_ne!(a, "diff");
    }

    #[test]
    fn serde_serialize_is_transparent_json() {
        let r = RedactedString::new("token-xyz");
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(json, "\"token-xyz\"");
    }

    #[test]
    fn serde_deserialize_transparent_json() {
        let r: RedactedString = serde_json::from_str("\"value-1\"").unwrap();
        assert_eq!(r, "value-1");
    }

    #[test]
    fn toml_round_trip_preserves_value() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        struct Cfg {
            password: RedactedString,
        }
        let cfg = Cfg {
            password: RedactedString::new("p@ss w!th spaces & sym#bols"),
        };
        let s = toml::to_string(&cfg).unwrap();
        // The TOML output must contain the value verbatim (the type is
        // transparent; redaction is a render-time concern, not a Serialize-
        // time concern).
        assert!(s.contains("p@ss w!th spaces & sym#bols"));
        let parsed: Cfg = toml::from_str(&s).unwrap();
        assert_eq!(parsed.password, "p@ss w!th spaces & sym#bols");
    }

    #[test]
    fn serde_alias_works_for_backward_compat() {
        // Verify that `#[serde(alias = "old_name")]` on a containing struct
        // still allows a renamed field to deserialize correctly into a
        // RedactedString — this is the migration shape we'll use when
        // sweeping the config schema.
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        struct Cfg {
            #[serde(alias = "secret_token")]
            token: RedactedString,
        }
        // New name
        let new: Cfg = toml::from_str("token = \"abc123\"\n").unwrap();
        assert_eq!(new.token, "abc123");
        // Old name (via alias)
        let old: Cfg = toml::from_str("secret_token = \"abc123\"\n").unwrap();
        assert_eq!(old.token, "abc123");
    }

    #[test]
    fn debug_golden_insta_snapshot() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, Debug)]
        struct ConfigLike {
            password: RedactedString,
            token: RedactedString,
            non_secret: String,
        }
        let c = ConfigLike {
            password: RedactedString::new("hunter2"),
            token: RedactedString::new("sk_live_abcdef1234567890"),
            non_secret: "visible".to_owned(),
        };
        let dbg = format!("{c:?}");
        // None of the cleartext values may appear in Debug output.
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("sk_live_abcdef1234567890"));
        // The non-secret string must appear.
        assert!(dbg.contains("visible"));
        // Golden snapshot of the exact shape we promise to callers.
        insta::assert_snapshot!(
            &dbg,
            @r#"ConfigLike { password: <redacted>, token: <redacted>, non_secret: "visible" }"#
        );
    }

    #[test]
    fn drop_zeroes_inner_bytes() {
        // We can't dereference freed memory in safe Rust. The honest
        // test is: capture the pointer to the boxed buffer *before* drop,
        // explicitly invoke `Drop` via `std::mem::drop`, and then construct
        // a fresh `RedactedString` immediately — with the small-string
        // allocator path of glibc/jemalloc/system this *usually* reuses
        // the same buffer (the "realloc trick"). When it does, we can
        // observe the zeroed prefix.
        //
        // To make this deterministic without `unsafe` (the crate forbids
        // it), we instead verify the invariant the implementation *itself*
        // upholds: `zeroize::Zeroize for str` overwrites all bytes with 0.
        // We construct a `RedactedString`, hand-roll the same operation
        // the destructor would perform on the inner `Box<str>`, and
        // confirm the bytes are zero.
        use zeroize::Zeroize;
        let mut s: Box<str> = "secret-bytes-xyz".to_owned().into_boxed_str();
        let original_ptr = s.as_ptr();
        let original_len = s.len();
        s.zeroize();
        // After zeroize the buffer must be all zero, same pointer, same len.
        assert_eq!(s.as_ptr(), original_ptr);
        assert_eq!(s.len(), original_len);
        for &b in s.as_bytes() {
            assert_eq!(b, 0, "byte not zeroed after Zeroize::zeroize");
        }

        // And as a smoke check, drop a `RedactedString` and make sure
        // it doesn't panic / leak — this exercises the real Drop impl.
        {
            let r = RedactedString::new("transient");
            drop(r);
        }
    }

    #[test]
    fn cloning_is_independent() {
        let a = RedactedString::new("shared");
        let b = a.clone();
        assert_eq!(a, b);
        // Dropping the clone must not affect the original (each owns its
        // own Box<str>).
        drop(b);
        assert_eq!(a, "shared");
    }

    #[test]
    fn default_is_empty() {
        let r = RedactedString::default();
        assert!(r.is_empty());
        assert_eq!(r.len(), 0);
        assert_eq!(format!("{r:?}"), REDACTED_DEBUG);
    }

    #[test]
    fn empty_redacted_string_still_redacts_in_debug() {
        let r = RedactedString::new("");
        assert_eq!(format!("{r:?}"), REDACTED_DEBUG);
        // Display reveals (it is empty)
        assert_eq!(format!("{r}"), "");
    }

    #[test]
    fn expose_returns_inner_str() {
        let r = RedactedString::new("expose-me");
        assert_eq!(r.expose(), "expose-me");
    }
}
