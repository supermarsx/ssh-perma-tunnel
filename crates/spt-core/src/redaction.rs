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
// 1.88 lint: clippy::non_std_lazy_statics — std `LazyLock` is stable on 1.88,
// so the lazy statics below use it instead of `once_cell::sync::Lazy`.
use regex::{Regex, RegexSet};
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

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
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(bearer\s+)([A-Za-z0-9._~+/=\-]+)").unwrap());

/// `Authorization: Basic <b64>`
static BASIC: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)(basic\s+)([A-Za-z0-9+/=]+)").unwrap());

/// `password = "..."`, `passphrase=...`, `key=...`, `secret=...`,
/// `token=...`, `api_key=...` — values are scrubbed but the key name is kept.
static KV_SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?ix)
            (password|passphrase|secret|api[_-]?key|token|key)
            \s*=\s*
            (?:
                "([^"]*)"        # double-quoted
              | '([^']*)'        # single-quoted
              | ([^\s,;)]+) # bareword (includes brackets/braces so bracketed
                              # secret values are fully redacted; already-redacted
                              # markers remain fixed points because the whole
                              # marker is consumed and re-emitted unchanged)
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
static PEM_BLOCK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----.*?-----END [A-Z0-9 ]*PRIVATE KEY[A-Z0-9 ]*-----",
    )
    .unwrap()
});

// --- Strict-only patterns ---------------------------------------------------

/// IPv4 dotted quad.
static IPV4: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b",
    )
    .unwrap()
});

/// Best-effort IPv6 — matches typical addresses with at least two colons.
static IPV6: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b|::1\b|::\b").unwrap()
});

/// Email address.
static EMAIL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b").unwrap());

/// `RegexSet` over every pattern used by `Strict` mode (standard + email + IP).
///
/// Used as a no-match precheck for `Strict` only. We deliberately do **not**
/// build an equivalent set for `Standard`: every `Standard` pattern carries a
/// strong literal anchor (`bearer`, `basic`, `password|passphrase|…`,
/// `BEGIN PRIVATE KEY`), and the regex crate's per-pattern literal prefilter
/// dispatches each `replace_all` no-op pass via Aho-Corasick / memmem at
/// ~1.2 GiB/s. A combined `RegexSet` loses that prefilter, drops to ~520 MiB/s
/// NFA traversal, and is a measured **regression** for `Standard`. `Strict`'s
/// extra `EMAIL` / `IPV4` / `IPV6` patterns have no fast literal anchor, so
/// the OLD path runs at ~320 MiB/s, the combined NFA wins (~540 MiB/s), and
/// the precheck is a net +40 % win on the no-match path.
static STRICT_SET: LazyLock<RegexSet> = LazyLock::new(|| {
    RegexSet::new([
        PEM_BLOCK.as_str(),
        BEARER.as_str(),
        BASIC.as_str(),
        KV_SECRET.as_str(),
        EMAIL.as_str(),
        IPV4.as_str(),
        IPV6.as_str(),
    ])
    .expect("strict redaction patterns compile as a RegexSet")
});

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

    // Fast path for `Strict` only: a single combined NFA pass over the input
    // rejects in O(n) when no Strict pattern can match, skipping the seven
    // per-pattern `replace_all` scans below. `Standard` is deliberately NOT
    // prechecked — its patterns are dominated by literal-anchor scanners that
    // the regex crate already dispatches via Aho-Corasick at ~1.2 GiB/s, so
    // a combined RegexSet is a measured regression there. See `STRICT_SET`
    // docs for the measured numbers.
    if matches!(mode, RedactionMode::Strict) && !STRICT_SET.is_match(input) {
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

/// Neutralize control characters in a string destined for a terminal or a log
/// line, returning a display-safe form.
///
/// Untrusted data — filenames, addresses, error banners, stderr — handed to a
/// server or peer can carry C0/C1 control bytes. Written raw to a log they
/// forge new log lines (embedded `\n`/`\r`); written raw to an operator's
/// terminal they emit ANSI escape sequences (cursor moves, color, title-set,
/// clipboard, hyperlink injection) via `ESC` (`0x1b`). This function renders
/// every such byte as a visible Rust-style escape (`\n`, `\r`, `\t`,
/// `\u{0}`, `\u{1b}`, …) so the bytes are seen, not executed.
///
/// Specifically neutralized: all C0 controls `0x00..=0x1f` (including ESC, CR,
/// LF, TAB, BEL `0x07`, backspace `0x08`), DEL `0x7f`, and the C1 range
/// `0x80..=0x9f` (which can act as escapes on some terminals).
///
/// Printable ASCII and printable multi-byte UTF-8 (e.g. `世界`, `café`) pass
/// through unchanged — this only touches control/escape bytes, never legitimate
/// text. Returns [`Cow::Borrowed`] (zero allocation) when the input is already
/// clean.
///
/// This is *additive* to [`redact`]: it neutralizes control characters but does
/// not scrub secrets. Apply [`redact`] for secret-bearing data and
/// `escape_control` for display safety; they compose.
#[must_use]
pub fn escape_control(input: &str) -> Cow<'_, str> {
    fn needs_escape(c: char) -> bool {
        let u = c as u32;
        // C0 controls (incl. ESC/CR/LF/TAB/BEL/BS/NUL), DEL, and C1 controls.
        u < 0x20 || u == 0x7f || (0x80..=0x9f).contains(&u)
    }

    if !input.chars().any(needs_escape) {
        return Cow::Borrowed(input);
    }

    let mut out = String::with_capacity(input.len() + 8);
    for c in input.chars() {
        if needs_escape(c) {
            // `char::escape_default` renders control chars as `\n`, `\r`,
            // `\t`, `\u{0}`, or `\u{1b}` — all visible, all ASCII.
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    Cow::Owned(out)
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
    use super::{
        escape_control, redact, RedactionMode, BASIC, BEARER, EMAIL, IPV4, IPV6, KV_SECRET,
        PEM_BLOCK, STRICT_SET,
    };
    use regex::Regex;

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
    fn regex_set_agrees_with_union_of_is_match() {
        // Corpus blends positives (one per pattern), negatives (no secrets),
        // and combinations so we exercise the "any-matches" disjunction
        // against the per-pattern oracle.
        let corpus: &[&str] = &[
            // negatives — must agree as "no match"
            "",
            "nothing secret here",
            "lorem ipsum dolor sit amet",
            "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
            "status=ok elapsed=12ms route=/foo/bar",
            "user=alice action=login result=success",
            "ssh connection established to backend pool",
            // standard positives
            "Authorization: Bearer abc.def_123",
            "authorization: bearer XYZ",
            "Authorization: Basic dXNlcjpwYXNz",
            "password = \"hunter2\"",
            "passphrase='swordfish'",
            "api_key=sk-12345",
            "token=abcdef",
            "secret = topsecret",
            "-----BEGIN PRIVATE KEY-----\nMIIEv...\n-----END PRIVATE KEY-----",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAA\n-----END OPENSSH PRIVATE KEY-----",
            // strict-only positives
            "client 1.2.3.4 connecting",
            "peer=10.0.0.1",
            "addr 2001:db8::1",
            "[fe80::abcd:1]",
            "::1",
            "alice@example.com",
            "bob+filter@sub.domain.org",
            // combinations
            "user=alice 1.2.3.4 token=secret bob@example.com",
            "password=\"x\" 9.9.9.9",
            // tricky non-matches that look superficially close
            "bear with me",                         // not "bearer "
            "the basic idea is...",                 // not "Basic <b64>"
            "the password to success is hard work", // no '='
            "see ./key=ring/file",                  // bareword has slash chars
            "version 1.2.3",                        // not a full dotted quad
            "single colon a:b",                     // not IPv6
        ];

        // Per-pattern oracle for Strict (Strict is the only mode with a
        // RegexSet precheck — see `STRICT_SET` docs for the rationale).
        let strict_patterns: &[&Regex] = &[
            &*PEM_BLOCK,
            &*BEARER,
            &*BASIC,
            &*KV_SECRET,
            &*EMAIL,
            &*IPV4,
            &*IPV6,
        ];

        for input in corpus {
            let oracle_strict = strict_patterns.iter().any(|re| re.is_match(input));
            let set_strict = STRICT_SET.is_match(input);
            assert_eq!(
                set_strict, oracle_strict,
                "STRICT_SET disagreed with union(is_match) on {input:?}: set={set_strict} oracle={oracle_strict}"
            );
        }
    }

    #[test]
    fn strict_no_match_returns_borrowed() {
        let s = "nothing secret here, just plain text";
        match redact(s, RedactionMode::Strict) {
            std::borrow::Cow::Borrowed(b) => assert_eq!(b, s),
            std::borrow::Cow::Owned(_) => panic!("expected borrowed Cow"),
        }
    }

    #[test]
    fn regex_set_precheck_preserves_output_for_matches() {
        // Each input must produce the same redacted output regardless of
        // whether the precheck short-circuits or falls through. The precheck
        // is a strict early-return on no-match, so all matching inputs must
        // be byte-identical to the prior behavior (verified by the other
        // tests). Spot-check a few combinations here.
        let cases: &[(&str, RedactionMode)] = &[
            ("Authorization: Bearer xyz123", RedactionMode::Standard),
            ("password=hunter2", RedactionMode::Standard),
            (
                "client 1.2.3.4 alice@example.com token=t",
                RedactionMode::Strict,
            ),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nbody\n-----END OPENSSH PRIVATE KEY-----",
                RedactionMode::Standard,
            ),
        ];
        for (input, mode) in cases.iter().copied() {
            let out = redact(input, mode);
            assert!(out.contains("[REDACTED]"), "case {input:?} mode={mode:?}");
            assert_ne!(out.as_ref(), input, "case {input:?} mode={mode:?}");
        }
    }

    #[test]
    fn redact_is_idempotent_kv_bareword() {
        // Regression: previously `password="hunter2"` -> `password=[REDACTED]`
        // on pass 1, then pass 2 would re-match only part of the marker and
        // emit `password=[REDACTED]]`. The bareword character class now
        // consumes the whole marker, so replacing it is a fixed point.
        let input = "password=\"hunter2\"";
        let p1 = redact(input, RedactionMode::Standard).into_owned();
        let p2 = redact(&p1, RedactionMode::Standard).into_owned();
        assert_eq!(p1, "password=[REDACTED]");
        assert_eq!(p1, p2, "redact must be idempotent on KV-bareword markers");

        // Feeding the marker directly through `redact` is also a no-op
        // (idempotent at pass 1, not just pass 2).
        let marker = "password=[REDACTED]";
        assert_eq!(
            redact(marker, RedactionMode::Standard).as_ref(),
            marker,
            "already-redacted marker must be a fixed point"
        );
    }

    #[test]
    fn redact_idempotent_synthetic_strict_inputs() {
        // Lock the invariant across a variety of shapes in Strict mode.
        let cases: &[&str] = &[
            "password=\"hunter2\"",
            "passphrase='swordfish'",
            "api_key=sk-12345",
            "token=abcdef",
            "secret=topsecret",
            "Authorization: Bearer abc.def_123",
            "Authorization: Basic dXNlcjpwYXNz",
            "client 1.2.3.4 alice@example.com",
            "[2001:db8::1]:443 user=alice token=xyz",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nAAA\n-----END OPENSSH PRIVATE KEY-----",
            "mixed: password=hunter2 1.2.3.4 a@b.com Authorization: Bearer T",
        ];
        for input in cases {
            for mode in [RedactionMode::Standard, RedactionMode::Strict] {
                let p1 = redact(input, mode).into_owned();
                let p2 = redact(&p1, mode).into_owned();
                assert_eq!(
                    p1, p2,
                    "not idempotent for mode={mode:?} input={input:?}\n p1={p1:?}\n p2={p2:?}"
                );
            }
        }
    }

    #[test]
    fn kv_bareword_redacts_bracketed_values_fully() {
        let cases = [
            "secret=foo[bar]",
            "password=[hunter2]",
            "secret={token}",
            "api_key=foo{bar}[baz]",
        ];

        for input in cases {
            for mode in [RedactionMode::Standard, RedactionMode::Strict] {
                let out = redact(input, mode).into_owned();
                assert_eq!(
                    out,
                    input.split_once('=').unwrap().0.to_owned() + "=[REDACTED]"
                );
                assert!(
                    !out.contains("hunter2"),
                    "input={input:?} mode={mode:?} out={out:?}"
                );
                assert!(
                    !out.contains("token"),
                    "input={input:?} mode={mode:?} out={out:?}"
                );
                assert!(
                    !out.contains("bar"),
                    "input={input:?} mode={mode:?} out={out:?}"
                );
                let twice = redact(&out, mode).into_owned();
                assert_eq!(out, twice, "redaction must stay idempotent for {input:?}");
            }
        }
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

    // --- escape_control ----------------------------------------------------

    #[test]
    fn escape_control_neutralizes_esc_cr_lf_nul_bel_bs() {
        // Each control byte must render to a visible escape and must NOT
        // survive as its raw form in the output.
        let cases: &[(&str, &str)] = &[
            ("a\x1bb", "\\u{1b}"), // ESC
            ("a\rb", "\\r"),       // CR
            ("a\nb", "\\n"),       // LF
            ("a\x00b", "\\u{0}"),  // NUL
            ("a\x07b", "\\u{7}"),  // BEL
            ("a\x08b", "\\u{8}"),  // backspace
            ("a\tb", "\\t"),       // TAB
        ];
        for (input, expect_marker) in cases {
            let out = escape_control(input);
            assert!(
                out.contains(expect_marker),
                "input={input:?} expected marker {expect_marker:?} in {out:?}"
            );
            // No raw control byte may remain.
            assert!(
                !out.chars().any(|c| (c as u32) < 0x20),
                "raw control byte survived for input={input:?}: {out:?}"
            );
        }
    }

    #[test]
    fn escape_control_neutralizes_real_ansi_clear_screen() {
        // `ESC [ 2J` (clear screen) must not reach the terminal as raw bytes.
        let evil = "innocent\x1b[2Jhidden";
        let out = escape_control(evil);
        assert!(!out.contains('\x1b'), "raw ESC survived: {out:?}");
        assert!(out.contains("\\u{1b}[2J"), "got {out:?}");
        // The visible-text parts are preserved.
        assert!(out.contains("innocent"));
        assert!(out.contains("hidden"));
    }

    #[test]
    fn escape_control_neutralizes_osc_title_set() {
        // OSC window-title set: ESC ] 0 ; pwned BEL
        let evil = "file\x1b]0;pwned\x07.txt";
        let out = escape_control(evil);
        assert!(!out.contains('\x1b'));
        assert!(!out.contains('\x07'));
        assert!(out.contains("\\u{1b}]0;pwned\\u{7}.txt"), "got {out:?}");
    }

    #[test]
    fn escape_control_neutralizes_osc8_hyperlink() {
        // OSC 8 hyperlink injection: ESC ] 8 ; ; http://evil ESC \
        let evil = "link\x1b]8;;http://evil.example\x1b\\text";
        let out = escape_control(evil);
        assert!(!out.contains('\x1b'), "raw ESC survived: {out:?}");
        assert!(out.contains("http://evil.example"));
    }

    #[test]
    fn escape_control_forges_log_line_neutralized() {
        // A would-be forged log line with an embedded newline becomes a single
        // line carrying a visible `\n`.
        let evil = "ok\nfake-auth: succeeded";
        let out = escape_control(evil);
        assert!(!out.contains('\n'), "embedded newline survived: {out:?}");
        assert_eq!(out, "ok\\nfake-auth: succeeded");
    }

    #[test]
    fn escape_control_neutralizes_del_and_c1() {
        // DEL (0x7f) and a C1 control (0x9b = CSI) are both neutralized.
        let evil = "a\x7fb\u{9b}c";
        let out = escape_control(evil);
        assert!(!out.contains('\x7f'));
        assert!(!out.contains('\u{9b}'));
        assert!(out.contains("\\u{7f}"));
        assert!(out.contains("\\u{9b}"));
    }

    #[test]
    fn escape_control_leaves_printable_ascii_unchanged() {
        let s = "plain text 123 -_./:@ OK!";
        match escape_control(s) {
            std::borrow::Cow::Borrowed(b) => assert_eq!(b, s),
            std::borrow::Cow::Owned(o) => panic!("expected borrowed, got owned {o:?}"),
        }
    }

    #[test]
    fn escape_control_leaves_utf8_unchanged() {
        // Printable multi-byte UTF-8 must pass through untouched.
        let s = "café 世界 naïve Ω π";
        match escape_control(s) {
            std::borrow::Cow::Borrowed(b) => assert_eq!(b, s),
            std::borrow::Cow::Owned(o) => panic!("expected borrowed, got owned {o:?}"),
        }
    }

    #[test]
    fn escape_control_empty_is_borrowed() {
        match escape_control("") {
            std::borrow::Cow::Borrowed(b) => assert_eq!(b, ""),
            std::borrow::Cow::Owned(_) => panic!("expected borrowed"),
        }
    }

    #[test]
    fn escape_control_does_not_redact_secrets() {
        // escape_control is additive — it must NOT scrub secret content; that
        // is `redact`'s job. A clean secret string passes through verbatim.
        let s = "password=hunter2";
        assert_eq!(escape_control(s).as_ref(), s);
    }

    #[test]
    fn escape_control_is_idempotent() {
        let evil = "x\x1b[2J\ny\r\x00";
        let once = escape_control(evil).into_owned();
        let twice = escape_control(&once).into_owned();
        assert_eq!(once, twice, "escape_control must be idempotent");
        // The escaped form is pure printable ASCII, so a second pass borrows.
        assert!(matches!(
            escape_control(&once),
            std::borrow::Cow::Borrowed(_)
        ));
    }
}
