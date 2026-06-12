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

/// Render `template` against the named fields of `event`.
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
/// than the previous per-byte `push(c)` loop.
#[must_use]
pub fn render_template(template: &str, event: &Event) -> (String, Vec<String>) {
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
                    Some(v) => out.push_str(&v),
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
}
