//! Log/event/MCP-response redaction primitives.
//!
//! Three modes are supported, matching spec §13.3:
//!
//! * [`RedactionMode::None`] — no redaction (intended for trusted local
//!   debugging; the runtime MUST NOT use it for any sink that leaves the
//!   process).
//! * [`RedactionMode::Standard`] — redact secrets-bearing tokens: bearer
//!   tokens, basic-auth pairs, password/key/passphrase fields, and PEM
//!   private-key blocks.
//! * [`RedactionMode::Strict`] — everything in `Standard` plus IP addresses
//!   and email addresses, used when hostname/address redaction is enabled.

use std::borrow::Cow;

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Selects how aggressively [`redact`] scrubs an input string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RedactionMode {
    /// No redaction.
    None,
    /// Redact secret-bearing tokens (default for log sinks).
    #[default]
    Standard,
    /// Redact secrets plus identifying network/user info.
    Strict,
}

const REDACTED: &str = "[REDACTED]";

// --- Standard patterns ------------------------------------------------------

/// `Authorization: Bearer <token>`
static BEARER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=\-]+)").unwrap());

/// `Authorization: Basic <b64>`
static BASIC: Lazy<Regex> = Lazy::new(|| Regex::new(r"(?i)(basic\s+)([A-Za-z0-9+/=]+)").unwrap());

/// `password = "..."`, `passphrase=...`, `key=...`, `secret=...`,
/// `token=...`, `api_key=...` — values are scrubbed but the key name is kept.
static KV_SECRET: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?ix)
            (password|passphrase|secret|api[_-]?key|token|key)
            \s*=\s*
            (?:
                "([^"]*)"        # double-quoted
              | '([^']*)'        # single-quoted
              | ([^\s,;)\]}]+)   # bareword
            )
        "#,
    )
    .unwrap()
});

/// PEM blocks containing private key material, including encrypted variants.
///
/// We don't enforce that the BEGIN/END labels match (regex crate has no
/// backreferences); the body between any private-key BEGIN and any
/// private-key END is replaced. PEM in the wild always pairs them.
static PEM_BLOCK: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.*?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----",
    )
    .unwrap()
});

// --- Strict-only patterns ---------------------------------------------------

/// IPv4 dotted quad.
static IPV4: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b",
    )
    .unwrap()
});

/// Best-effort IPv6 — matches typical addresses with at least two colons.
static IPV6: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|::1\b|::\b").unwrap());

/// Email address.
static EMAIL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap());

/// Redact `input` according to `mode`.
///
/// Returns a [`Cow::Borrowed`] when no patterns matched, so the no-op path
/// allocates nothing. Patterns are applied in a fixed order; later passes
/// see already-redacted text.
#[must_use]
pub fn redact(input: &str, mode: RedactionMode) -> Cow<'_, str> {
    if matches!(mode, RedactionMode::None) {
        return Cow::Borrowed(input);
    }

    let mut current: Cow<'_, str> = Cow::Borrowed(input);

    // Standard
    current = apply(current, &PEM_BLOCK, |_| {
        format!("-----BEGIN PRIVATE KEY-----{REDACTED}-----END PRIVATE KEY-----")
    });
    current = apply(current, &BEARER, |caps| format!("{}{REDACTED}", &caps[1]));
    current = apply(current, &BASIC, |caps| format!("{}{REDACTED}", &caps[1]));
    current = apply(current, &KV_SECRET, |caps| {
        format!("{}={REDACTED}", &caps[1])
    });

    if matches!(mode, RedactionMode::Strict) {
        current = apply(current, &EMAIL, |_| REDACTED.to_owned());
        current = apply(current, &IPV4, |_| REDACTED.to_owned());
        current = apply(current, &IPV6, |_| REDACTED.to_owned());
    }

    current
}

fn apply<'a>(
    current: Cow<'a, str>,
    re: &Regex,
    f: impl Fn(&regex::Captures<'_>) -> String,
) -> Cow<'a, str> {
    match current {
        Cow::Borrowed(s) => match re.replace_all(s, |c: &regex::Captures<'_>| f(c)) {
            Cow::Borrowed(_) => Cow::Borrowed(s),
            Cow::Owned(o) => Cow::Owned(o),
        },
        Cow::Owned(s) => {
            let replaced = re
                .replace_all(&s, |c: &regex::Captures<'_>| f(c))
                .into_owned();
            Cow::Owned(replaced)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{redact, RedactionMode};

    #[test]
    fn none_is_passthrough() {
        let s = "password=hunter2 1.2.3.4 a@b.com";
        let out = redact(s, RedactionMode::None);
        assert_eq!(out, s);
    }

    #[test]
    fn standard_redacts_eight_cases() {
        let cases: [(&str, &str); 8] = [
            ("Authorization: Bearer abc.def_123", "[REDACTED]"),
            ("authorization: bearer XYZ", "[REDACTED]"),
            ("Authorization: Basic dXNlcjpwYXNz", "[REDACTED]"),
            ("password = \"hunter2\"", "[REDACTED]"),
            ("passphrase='swordfish'", "[REDACTED]"),
            ("api_key=sk-12345", "[REDACTED]"),
            ("token=abcdef", "[REDACTED]"),
            (
                "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----",
                "[REDACTED]",
            ),
        ];
        for (input, must_contain) in cases {
            let out = redact(input, RedactionMode::Standard);
            assert!(out.contains(must_contain), "input={input:?} got={out:?}");
            assert!(!out.contains("hunter2"));
            assert!(!out.contains("swordfish"));
            assert!(!out.contains("sk-12345"));
            assert!(!out.contains("abcdef"));
            assert!(!out.contains("MIIEv"));
        }
    }

    #[test]
    fn standard_keeps_ip_and_email() {
        let s = "client 1.2.3.4 alice@example.com";
        let out = redact(s, RedactionMode::Standard);
        assert!(out.contains("1.2.3.4"));
        assert!(out.contains("alice@example.com"));
    }

    #[test]
    fn strict_redacts_eight_extras() {
        let cases: [&str; 8] = [
            "1.2.3.4",
            "[2001:db8::1]:443",
            "::1",
            "alice@example.com",
            "bob+filter@sub.domain.org",
            "10.0.0.1",
            "fe80::abcd:1",
            "user@host.tld",
        ];
        for input in cases {
            let out = redact(input, RedactionMode::Strict);
            assert!(out.contains("[REDACTED]"), "input={input:?} got={out:?}");
        }
    }

    #[test]
    fn standard_no_match_returns_borrowed() {
        let s = "nothing secret here";
        match redact(s, RedactionMode::Standard) {
            std::borrow::Cow::Borrowed(b) => assert_eq!(b, s),
            std::borrow::Cow::Owned(_) => panic!("expected borrowed Cow"),
        }
    }

    #[test]
    fn pem_block_redacted_keeps_markers() {
        let pem = "before\n-----BEGIN OPENSSH PRIVATE KEY-----\nAAA\nBBB\n-----END OPENSSH PRIVATE KEY-----\nafter";
        let out = redact(pem, RedactionMode::Standard);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("AAA"));
        assert!(out.contains("before"));
        assert!(out.contains("after"));
    }

    #[test]
    fn default_mode_is_standard() {
        assert_eq!(RedactionMode::default(), RedactionMode::Standard);
    }

    #[test]
    fn strict_redacts_combination() {
        let s = "user=alice token=secret-tok password=\"hunter2\" 1.2.3.4 a@b.com";
        let out = redact(s, RedactionMode::Strict);
        assert!(!out.contains("secret-tok"));
        assert!(!out.contains("hunter2"));
        assert!(!out.contains("1.2.3.4"));
        assert!(!out.contains("a@b.com"));
        assert!(out.contains("token="));
        assert!(out.contains("password="));
    }
}
