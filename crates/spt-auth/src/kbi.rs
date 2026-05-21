//! Keyboard-interactive (KBI) responder primitives.
//!
//! Two layers:
//!
//! * [`KbiAnswer`] — *answer source*. What value to provide once a prompt has
//!   been matched. Variants cover static strings, secret references, RFC 6238
//!   TOTP codes, and `YubiKey` OATH-TOTP (feature-gated).
//! * [`KbiResponder`] — *prompt → answer binding*. A regex applied against the
//!   server-supplied prompt, plus the answer source to use on match.
//!
//! The pre-existing struct-shape was a substring matcher conflating both
//! concerns; this enum / regex split is required by spec §9.12 to express the
//! per-prompt regex example from `docs/auth.md`.

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::secret_ref::SecretRef;
use crate::totp::TotpAlgo;

/// Source of a single keyboard-interactive answer.
///
/// Serde representation is internally tagged via field name so TOML reads
/// naturally:
///
/// ```toml
/// answer = { totp = { secret_ref = "secret://ssh/totp", digits = 6, period = 30, algo = "sha1" } }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KbiAnswer {
    /// Literal string sent verbatim. Never use this for real passwords —
    /// it lives in plaintext in the config file. Suitable for fixed tokens
    /// like `yes` answers to legal-banner acknowledgements.
    Static(String),

    /// Resolve a [`SecretRef`] through the keychain/vault/env/file chain and
    /// send the value (UTF-8) as the answer.
    SecretRef(SecretRef),

    /// Compute an RFC 6238 TOTP code from a secret resolved via `secret_ref`.
    Totp {
        /// Reference to the raw OTP secret (decoded bytes, not base32).
        secret_ref: SecretRef,
        /// Number of OTP digits (commonly 6, sometimes 8).
        #[serde(default = "default_digits")]
        digits: u32,
        /// Step period in seconds (RFC 6238 §5.2 recommends 30).
        #[serde(default = "default_period")]
        period: u32,
        /// HMAC hash algorithm.
        #[serde(default)]
        algo: TotpAlgo,
    },

    /// Read an OATH-TOTP code from a `YubiKey` via `ykman oath accounts code`.
    /// Requires the `yubikey` Cargo feature; without it, evaluation returns
    /// [`spt_core::Error::UnsupportedPlatform`].
    YubikeyOath {
        /// Optional `YubiKey` serial number to disambiguate when multiple keys
        /// are attached.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        serial: Option<String>,
        /// Account name (the `<oath_name>` arg to ykman).
        oath_name: String,
    },
}

fn default_digits() -> u32 {
    6
}
fn default_period() -> u32 {
    30
}

/// One scripted prompt→answer binding for SSH2 keyboard-interactive auth.
///
/// `prompt_regex` is a regex applied (case-insensitively by default — wrap
/// with `(?i)` for clarity) against the prompt sent by the server. The first
/// responder in the responder list whose regex matches wins (ordered match).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KbiResponder {
    /// Regex pattern matched against the server-supplied prompt.
    pub prompt_regex: String,
    /// Source of the answer to provide on match.
    pub answer: KbiAnswer,
    /// Optional echo-flag hint logged as a soft warning on mismatch.
    #[serde(default)]
    pub echo: bool,
}

impl PartialEq for KbiResponder {
    fn eq(&self, other: &Self) -> bool {
        self.prompt_regex == other.prompt_regex
            && self.answer == other.answer
            && self.echo == other.echo
    }
}

impl Eq for KbiResponder {}

impl KbiResponder {
    /// Compile the `prompt_regex` field. Returns a typed config error on
    /// failure so callers can surface invalid regex at `config validate` time
    /// rather than at prompt time.
    pub fn compile(&self) -> spt_core::Result<Regex> {
        Regex::new(&self.prompt_regex).map_err(|e| {
            spt_core::Error::InvalidConfig(format!(
                "invalid keyboard-interactive prompt_regex `{}`: {e}",
                self.prompt_regex
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_ref::SecretRef;

    #[test]
    fn enum_roundtrip_static() {
        let a = KbiAnswer::Static("yes".into());
        let s = serde_json::to_string(&a).unwrap();
        let back: KbiAnswer = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enum_roundtrip_secret_ref() {
        let a = KbiAnswer::SecretRef(SecretRef::Env("PW".into()));
        let s = serde_json::to_string(&a).unwrap();
        let back: KbiAnswer = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enum_roundtrip_totp() {
        let a = KbiAnswer::Totp {
            secret_ref: SecretRef::Vault {
                namespace: "ssh".into(),
                name: "totp".into(),
            },
            digits: 6,
            period: 30,
            algo: TotpAlgo::Sha1,
        };
        let s = serde_json::to_string(&a).unwrap();
        let back: KbiAnswer = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn enum_roundtrip_yubikey() {
        let a = KbiAnswer::YubikeyOath {
            serial: Some("12345".into()),
            oath_name: "github".into(),
        };
        let s = serde_json::to_string(&a).unwrap();
        let back: KbiAnswer = serde_json::from_str(&s).unwrap();
        assert_eq!(a, back);
    }

    #[test]
    fn responder_compile_ok() {
        let r = KbiResponder {
            prompt_regex: "(?i)otp.*code:".into(),
            answer: KbiAnswer::Static("123456".into()),
            echo: false,
        };
        let re = r.compile().unwrap();
        assert!(re.is_match("OTP verification code:"));
    }

    #[test]
    fn responder_compile_errors_surface_typed() {
        let r = KbiResponder {
            prompt_regex: "(unclosed".into(),
            answer: KbiAnswer::Static("x".into()),
            echo: false,
        };
        let err = r.compile().unwrap_err();
        assert!(matches!(err, spt_core::Error::InvalidConfig(_)));
    }

    #[test]
    fn totp_uses_default_digits_and_period() {
        // omit digits, period, algo — defaults are digits=6, period=30, algo=sha1.
        let json = r#"{"totp":{"secret_ref":"env:T"}}"#;
        let a: KbiAnswer = serde_json::from_str(json).unwrap();
        match a {
            KbiAnswer::Totp {
                digits,
                period,
                algo,
                ..
            } => {
                assert_eq!(digits, 6);
                assert_eq!(period, 30);
                assert_eq!(algo, TotpAlgo::Sha1);
            }
            _ => panic!("expected Totp variant"),
        }
    }
}
