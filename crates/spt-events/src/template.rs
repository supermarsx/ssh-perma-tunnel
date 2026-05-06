//! Minimal Mustache-like `{{field}}` template substitution.
//!
//! Two forms are supported:
//!
//! * `{{name}}` — replaced with the JSON-stringified value of the named
//!   field on the [`Event`] (looked up via [`Event::lookup_field`]).
//!   Strings are inserted verbatim (without surrounding quotes); other
//!   types are JSON-encoded.
//! * `{{ name }}` — leading/trailing ASCII whitespace inside the braces is
//!   ignored.
//!
//! Unknown fields render as the literal placeholder including the braces;
//! callers receive a list of unresolved names so they can warn if needed.

use serde_json::Value;

use crate::event::Event;

/// Render `template` against the named fields of `event`.
///
/// Returns `(rendered_string, missing_fields)`. `missing_fields` collects
/// any `{{name}}` whose lookup returned `None`.
#[must_use]
pub fn render_template(template: &str, event: &Event) -> (String, Vec<String>) {
    let mut out = String::with_capacity(template.len());
    let mut missing = Vec::new();
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Look for `{{`.
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            // Find closing `}}`.
            if let Some(end_rel) = find_close(&bytes[i + 2..]) {
                let raw = std::str::from_utf8(&bytes[i + 2..i + 2 + end_rel])
                    .unwrap_or("")
                    .trim();
                match event.lookup_field(raw) {
                    Some(v) => out.push_str(&render_value(&v)),
                    None => {
                        missing.push(raw.to_owned());
                        out.push_str(&format!("{{{{{raw}}}}}"));
                    }
                }
                i += 2 + end_rel + 2;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    (out, missing)
}

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

fn render_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        other => other.to_string(),
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
}
