//! Minimal Mustache-like `{{field}}` template substitution.
//!
//! Two forms are supported:
//!
//! * `{{name}}` — replaced with the JSON-stringified value of the named
//!   field on the [`Event`] (looked up via [`Event::lookup_field_str`], the
//!   allocation-light borrowed-string accessor). Strings are inserted
//!   verbatim (without surrounding quotes); other types are JSON-encoded.
//! * `{{ name }}` — leading/trailing ASCII whitespace inside the braces is
//!   ignored.
//!
//! Unknown fields render as the literal placeholder including the braces;
//! callers receive a list of unresolved names so they can warn if needed.

use crate::event::Event;

/// Output context that a substituted field value lands in.
///
/// Field values are partly attacker-influenced (SSH banners, remote
/// hostnames, error strings). Substituting them **verbatim** into a
/// structured sink payload lets a value break out of its slot and alter the
/// payload structure (JSON key injection, SMS form-parameter override, URL
/// query/path injection). Each variant escapes the substituted value for the
/// destination so a value can only ever be *data*, never *structure*.
///
/// Only the substituted value is escaped — the surrounding literal template
/// text (operator-controlled) is emitted unchanged, so the template syntax
/// the operator sees is preserved exactly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EscapeMode {
    /// No escaping — values are substituted verbatim. Correct for
    /// plain-text destinations (email subject/body, individual `argv`
    /// elements of a command sink, free-form `mcp_notify` text) where the
    /// value cannot alter any structure.
    #[default]
    None,
    /// The value sits inside a JSON **string literal** (between double
    /// quotes). Escapes `"`, `\`, and control characters per RFC 8259 so the
    /// value can never terminate the string and inject sibling keys/values.
    JsonString,
    /// The value is a URL path/query component. Percent-encodes everything
    /// outside the RFC 3986 unreserved set (space ⇒ `%20`) so a value cannot
    /// introduce `?`, `&`, `#`, or extra path segments.
    Url,
    /// The value is an `application/x-www-form-urlencoded` parameter value.
    /// Percent-encodes outside the unreserved set with space ⇒ `+` so a value
    /// cannot inject/override sibling form parameters (`&`, `=`).
    Form,
}

/// Render `template` against the named fields of `event`, substituting field
/// values verbatim. See [`render_template_escaped`] for context-aware
/// escaping of the substituted values.
///
/// Returns `(rendered_string, missing_fields)`. `missing_fields` collects
/// any `{{name}}` whose lookup returned `None`.
#[must_use]
pub fn render_template(template: &str, event: &Event) -> (String, Vec<String>) {
    render_template_escaped(template, event, EscapeMode::None)
}

/// Render `template` against the named fields of `event`, escaping every
/// substituted field value for the supplied output `context`.
///
/// Returns `(rendered_string, missing_fields)`. `missing_fields` collects
/// any `{{name}}` whose lookup returned `None`.
///
/// Implementation: a byte-level detection loop locates `{{` / `}}` markers
/// (a tight, branch-predictable two-byte compare), and literal spans between
/// placeholders are emitted in bulk via [`String::push_str`] over `&str`
/// slices of the original template. This is both UTF-8 correct (no
/// `byte as char` casts — slice indices land only on ASCII `{` and `}`
/// bytes, which are guaranteed UTF-8 boundaries) and substantially faster
/// than the previous per-byte `push(c)` loop. Only the substituted value is
/// run through `context`; literal spans are emitted unchanged.
#[must_use]
pub fn render_template_escaped(
    template: &str,
    event: &Event,
    context: EscapeMode,
) -> (String, Vec<String>) {
    let mut out = String::with_capacity(template.len());
    let mut missing = Vec::new();
    let bytes = template.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    // Start of the current literal span (in template byte indices). Any byte
    // not consumed by a placeholder will be flushed by a single `push_str`
    // either at the next placeholder hit or at the end of the input.
    let mut span_start = 0;
    while i + 1 < len {
        if bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end_rel) = find_close(&bytes[i + 2..]) {
                // Flush the literal span up to (but not including) this `{{`.
                // `i` is a UTF-8 boundary because `{` is ASCII, so slicing
                // `template[span_start..i]` is safe.
                if span_start < i {
                    out.push_str(&template[span_start..i]);
                }
                // `i + 2 + end_rel` likewise lands on the leading `}` of `}}`
                // (also ASCII / UTF-8 boundary).
                let raw_end = i + 2 + end_rel;
                // SAFETY-equivalent: `template[i + 2..raw_end]` slices on
                // ASCII boundaries, so this is always valid UTF-8.
                let raw = template[i + 2..raw_end].trim();
                match event.lookup_field_str(raw) {
                    // Only the substituted VALUE is escaped per the output
                    // context — literal template text is operator-controlled
                    // and emitted unchanged, preserving the template syntax.
                    Some(v) => append_escaped(&mut out, &v, context),
                    None => {
                        missing.push(raw.to_owned());
                        out.push_str("{{");
                        out.push_str(raw);
                        out.push_str("}}");
                    }
                }
                i = raw_end + 2;
                span_start = i;
                continue;
            }
            // Unmatched `{{`: leave it in the literal span; nothing past it
            // can ever match (`find_close` already scanned the rest), so
            // break out and let the tail flush emit the verbatim remainder.
            break;
        }
        i += 1;
    }
    // Flush any trailing literal span (including the case where `template`
    // had no placeholders at all, an unmatched `{{`, or a normal tail after
    // the last `}}`). Slicing `template[span_start..]` is UTF-8 safe because
    // `span_start` is always either `0` or one past a closing ASCII `}`.
    out.push_str(&template[span_start..]);
    (out, missing)
}

/// Scan `haystack` for the first `}}` and return its starting byte offset.
/// Byte-level, branch-predictable, identical to the previous private helper.
fn find_close(haystack: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + 1 < haystack.len() {
        if haystack[i] == b'}' && haystack[i + 1] == b'}' {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Append `value` to `out`, escaped for the output `context`.
fn append_escaped(out: &mut String, value: &str, context: EscapeMode) {
    match context {
        EscapeMode::None => out.push_str(value),
        EscapeMode::JsonString => append_json_escaped(out, value),
        EscapeMode::Url => append_percent_encoded(out, value, false),
        EscapeMode::Form => append_percent_encoded(out, value, true),
    }
}

/// Escape `value` for a JSON string-literal context per RFC 8259 (§7) and
/// append it to `out`. Escapes `"`, `\`, and all control characters
/// (`U+0000..=U+001F`); everything else (including non-ASCII) passes through
/// unchanged, which is valid inside a JSON string. The value therefore can
/// never terminate the enclosing string and inject sibling keys/values.
fn append_json_escaped(out: &mut String, value: &str) {
    use std::fmt::Write as _;
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                // Other C0 control characters: \u00XX form.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
}

/// Percent-encode `value` for a URL component / form parameter value and
/// append it to `out`. Bytes in the RFC 3986 *unreserved* set
/// (`A-Z a-z 0-9 - . _ ~`) pass through; every other byte becomes `%XX`
/// (upper-hex). When `space_as_plus` is set, a literal space is emitted as
/// `+` (the `application/x-www-form-urlencoded` convention); otherwise it is
/// percent-encoded as `%20`. Operating on raw UTF-8 bytes keeps multi-byte
/// characters correctly percent-encoded.
fn append_percent_encoded(out: &mut String, value: &str, space_as_plus: bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char);
            }
            b' ' if space_as_plus => out.push('+'),
            _ => {
                out.push('%');
                out.push(HEX[(b >> 4) as usize] as char);
                out.push(HEX[(b & 0x0f) as usize] as char);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;
    use spt_core::ProfileId;

    fn ev() -> Event {
        Event::builder("profile.connected", Severity::Info)
            .profile(ProfileId::new("smtp-relay").unwrap())
            .field("count", 5)
            .message("hello")
            .build()
    }

    #[test]
    fn basic_substitution() {
        let (s, missing) = render_template("profile {{profile_id}} count={{count}}", &ev());
        assert_eq!(s, "profile smtp-relay count=5");
        assert!(missing.is_empty());
    }

    #[test]
    fn whitespace_inside_braces_ok() {
        let (s, _) = render_template("hi {{ message }}", &ev());
        assert_eq!(s, "hi hello");
    }

    #[test]
    fn missing_keeps_placeholder_and_collects_name() {
        let (s, missing) = render_template("{{nope}} {{message}}", &ev());
        assert_eq!(s, "{{nope}} hello");
        assert_eq!(missing, vec!["nope".to_string()]);
    }

    #[test]
    fn unmatched_open_braces_pass_through() {
        let (s, _) = render_template("oops {{ broken", &ev());
        assert_eq!(s, "oops {{ broken");
    }

    #[test]
    fn golden_subject_line() {
        let (s, _) = render_template(
            "[{{severity}}] {{kind}} on {{profile_id}}: {{message}}",
            &ev(),
        );
        assert_eq!(s, "[info] profile.connected on smtp-relay: hello");
    }

    /// Regression test for the prior `bytes[i] as char` UTF-8 corruption bug:
    /// non-ASCII bytes in the template literal must pass through unchanged.
    #[test]
    fn non_ascii_literal_passthrough() {
        let (s, missing) = render_template("hi {{ message }} 世界", &ev());
        assert_eq!(s, "hi hello 世界");
        assert!(missing.is_empty());
        // Byte-level equality guards against any latent code-point mangling.
        assert_eq!(s.as_bytes(), b"hi hello \xe4\xb8\x96\xe7\x95\x8c");
    }

    /// Non-ASCII values resolved from the event must also flow through
    /// `push_str` cleanly without splitting multi-byte sequences.
    #[test]
    fn non_ascii_placeholder_value() {
        let event = Event::builder("profile.connected", Severity::Info)
            .profile(ProfileId::new("smtp-relay").unwrap())
            .field("greeting", "héllo, wörld 🌍")
            .build();
        let (s, missing) = render_template("msg: {{greeting}}", &event);
        assert_eq!(s, "msg: héllo, wörld 🌍");
        assert!(missing.is_empty());
    }

    /// Mixed ASCII + non-ASCII with multiple placeholders surrounding
    /// multi-byte runs (covers boundary crossings around `{{`/`}}`).
    #[test]
    fn mixed_ascii_and_unicode_template() {
        let (s, _) = render_template("[α] {{kind}} → {{profile_id}}: {{message}} ✔", &ev());
        assert_eq!(s, "[α] profile.connected → smtp-relay: hello ✔");
    }

    /// Multiple placeholders + literal spans across a realistic subject line.
    #[test]
    fn multi_placeholder_realistic_subject() {
        let event = Event::builder("forward.connection_failed", Severity::Error)
            .profile(ProfileId::new("smtp-relay").unwrap())
            .field("error", "connect timeout")
            .field("attempt", 3)
            .message("connection refused")
            .build();
        let (s, missing) = render_template(
            "[{{severity}}] {{kind}} on {{profile_id}} (attempt={{attempt}}): {{error}}",
            &event,
        );
        assert_eq!(
            s,
            "[error] forward.connection_failed on smtp-relay (attempt=3): connect timeout"
        );
        assert!(missing.is_empty());
    }

    /// Adjacent placeholders with no literal text between them must render
    /// back-to-back without producing a stray `{{...}}` or eating bytes.
    #[test]
    fn adjacent_placeholders() {
        let (s, missing) = render_template("{{kind}}{{message}}", &ev());
        assert_eq!(s, "profile.connectedhello");
        assert!(missing.is_empty());
    }

    /// Template with no placeholders at all is returned verbatim — including
    /// any non-ASCII bytes — through the `out.push_str(remaining)` tail.
    #[test]
    fn template_without_placeholders() {
        let (s, missing) = render_template("plain ünicode τέξτ", &ev());
        assert_eq!(s, "plain ünicode τέξτ");
        assert!(missing.is_empty());
    }

    /// `}}` without a preceding `{{` is just literal text (no special handling).
    #[test]
    fn stray_close_braces_are_literal() {
        let (s, _) = render_template("ok }} done", &ev());
        assert_eq!(s, "ok }} done");
    }

    /// `append_value` semantics: bool/number/array fields must render
    /// identically to the previous `render_value` implementation
    /// (`Display` for scalars, `serde_json` `to_string` for composites).
    #[test]
    fn placeholder_value_type_semantics() {
        let event = Event::builder("profile.connected", Severity::Info)
            .profile(ProfileId::new("smtp-relay").unwrap())
            .field("active", true)
            .field("count", 42)
            .field("ratio", 1.5)
            .field("tags", serde_json::json!(["a", "b"]))
            .build();
        let (s, missing) = render_template(
            "active={{active}} count={{count}} ratio={{ratio}} tags={{tags}}",
            &event,
        );
        assert_eq!(s, "active=true count=42 ratio=1.5 tags=[\"a\",\"b\"]");
        assert!(missing.is_empty());
    }

    /// Empty template returns empty output.
    #[test]
    fn empty_template() {
        let (s, missing) = render_template("", &ev());
        assert_eq!(s, "");
        assert!(missing.is_empty());
    }

    // ---------------------------------------------------------------
    // Output-context escaping (template-injection hardening).
    // ---------------------------------------------------------------

    /// A field value that attempts to break out of a JSON string and inject
    /// an `"admin":true` key must be escaped so the rendered body still parses
    /// as the original single-key object — `msg` is a STRING, not a structure.
    #[test]
    fn json_escape_blocks_key_injection() {
        let event = Event::builder("k", Severity::Info)
            .field("evil", r#"","admin":true,"x":""#)
            .build();
        let (s, _) =
            render_template_escaped(r#"{"msg":"{{evil}}"}"#, &event, EscapeMode::JsonString);
        let v: serde_json::Value = serde_json::from_str(&s).expect("rendered JSON must parse");
        // Exactly one key, and it is a string value (no injected `admin`).
        assert!(v.get("admin").is_none(), "admin key was injected: {s}");
        assert!(v["msg"].is_string(), "msg must be a string, got {s}");
        assert_eq!(v["msg"], r#"","admin":true,"x":""#);
        assert_eq!(v.as_object().unwrap().len(), 1);
    }

    /// Quotes, backslashes and newlines are escaped, not passed through.
    #[test]
    fn json_escape_handles_quotes_backslash_newline() {
        let event = Event::builder("k", Severity::Info)
            .field("v", "a\"b\\c\nd\te")
            .build();
        let (s, _) = render_template_escaped(r#"{"v":"{{v}}"}"#, &event, EscapeMode::JsonString);
        assert_eq!(s, r#"{"v":"a\"b\\c\nd\te"}"#);
        let parsed: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(parsed["v"], "a\"b\\c\nd\te");
    }

    /// C0 control characters fall back to the `\u00XX` form.
    #[test]
    fn json_escape_control_char_uses_unicode_escape() {
        let event = Event::builder("k", Severity::Info)
            .field("v", "x\u{01}y")
            .build();
        let (s, _) = render_template_escaped("{{v}}", &event, EscapeMode::JsonString);
        assert_eq!(s, "x\\u0001y");
    }

    /// Benign JSON values are byte-identical to the verbatim render — the
    /// escape pass must not perturb the common case.
    #[test]
    fn json_escape_benign_value_is_unchanged() {
        let event = Event::builder("profile.connected", Severity::Info)
            .message("up")
            .build();
        let (s, _) = render_template_escaped(
            r#"{"k":"{{kind}}","m":"{{message}}"}"#,
            &event,
            EscapeMode::JsonString,
        );
        assert_eq!(s, r#"{"k":"profile.connected","m":"up"}"#);
    }

    /// A URL-context value containing `&`, `?`, `#`, `/` and `=` must be
    /// percent-encoded so it cannot inject query params or path segments.
    #[test]
    fn url_escape_percent_encodes_reserved() {
        let event = Event::builder("k", Severity::Info)
            .field("inject", "a&b=c?d#e/f")
            .build();
        let (s, _) = render_template_escaped("https://host/p/{{inject}}", &event, EscapeMode::Url);
        assert_eq!(s, "https://host/p/a%26b%3Dc%3Fd%23e%2Ff");
        // No structural URL metacharacters survive in the substituted span.
        let tail = s.strip_prefix("https://host/p/").unwrap();
        for bad in ['&', '?', '#', '=', '/'] {
            assert!(!tail.contains(bad), "metachar {bad} survived: {s}");
        }
    }

    /// URL escaping leaves unreserved characters (and space ⇒ `%20`) intact.
    #[test]
    fn url_escape_space_is_percent20_and_unreserved_pass() {
        let event = Event::builder("k", Severity::Info)
            .field("v", "a b-c.d_e~f")
            .build();
        let (s, _) = render_template_escaped("{{v}}", &event, EscapeMode::Url);
        assert_eq!(s, "a%20b-c.d_e~f");
    }

    /// SMS/form-context value containing `&`/`=` cannot inject sibling params;
    /// space becomes `+` per the form-urlencoded convention.
    #[test]
    fn form_escape_blocks_param_injection() {
        let event = Event::builder("k", Severity::Info)
            .field("msg", "hi&To=+1900&x=1")
            .build();
        let (s, _) = render_template_escaped("Body={{msg}}", &event, EscapeMode::Form);
        assert_eq!(s, "Body=hi%26To%3D%2B1900%26x%3D1");
        // The literal `Body=` is the only `=`/`&`-bearing structure.
        let value = s.strip_prefix("Body=").unwrap();
        assert!(!value.contains('&') && !value.contains('='));
    }

    /// Form escaping maps a real space to `+` and percent-encodes a literal
    /// `+` so the two are unambiguous on the receiver.
    #[test]
    fn form_escape_space_plus_and_literal_plus() {
        let event = Event::builder("k", Severity::Info)
            .field("v", "a b+c")
            .build();
        let (s, _) = render_template_escaped("{{v}}", &event, EscapeMode::Form);
        assert_eq!(s, "a+b%2Bc");
    }

    /// `EscapeMode::None` is the documented default and renders verbatim.
    #[test]
    fn escape_mode_none_is_verbatim_default() {
        assert_eq!(EscapeMode::default(), EscapeMode::None);
        let event = Event::builder("k", Severity::Info)
            .field("v", "a\"b&c")
            .build();
        let (s, _) = render_template_escaped("{{v}}", &event, EscapeMode::None);
        assert_eq!(s, "a\"b&c");
    }
}
