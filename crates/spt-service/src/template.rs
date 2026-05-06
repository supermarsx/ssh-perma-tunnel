//! Tiny `{{var}}` template renderer.
//!
//! Deliberately not a templating engine. The packaging templates under
//! `/packaging/<scheme>/` use a single substitution syntax: `{{name}}` is
//! replaced by the matching string from a `BTreeMap`. Unknown placeholders
//! are replaced with the empty string and a `tracing::warn!` is emitted —
//! this matches the behaviour expected by the golden tests, where missing
//! optional fields render as blanks.

use std::collections::BTreeMap;

/// Render a template by substituting every `{{key}}` with `vars[key]`.
/// Missing keys substitute the empty string.
#[must_use]
pub fn render(template: &str, vars: &BTreeMap<&str, String>) -> String {
    let mut out = String::with_capacity(template.len());
    let bytes = template.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 1 < bytes.len() && bytes[i] == b'{' && bytes[i + 1] == b'{' {
            if let Some(end) = find_close(bytes, i + 2) {
                let key = std::str::from_utf8(&bytes[i + 2..end]).unwrap_or("").trim();
                if let Some(val) = vars.get(key) {
                    out.push_str(val);
                } else {
                    tracing::warn!(key, "spt-service template: unknown placeholder");
                }
                i = end + 2;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn find_close(bytes: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 1 < bytes.len() {
        if bytes[i] == b'}' && bytes[i + 1] == b'}' {
            return Some(i);
        }
        i += 1;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitutes_known_keys() {
        let mut v = BTreeMap::new();
        v.insert("name", "spt".to_string());
        v.insert("desc", "perma tunnel".to_string());
        let out = render("name={{name}} desc={{desc}}", &v);
        assert_eq!(out, "name=spt desc=perma tunnel");
    }

    #[test]
    fn unknown_key_renders_empty() {
        let v: BTreeMap<&str, String> = BTreeMap::new();
        let out = render("hello {{nobody}}!", &v);
        assert_eq!(out, "hello !");
    }

    #[test]
    fn unterminated_placeholder_passthrough() {
        let v: BTreeMap<&str, String> = BTreeMap::new();
        let out = render("{{open with no close", &v);
        assert_eq!(out, "{{open with no close");
    }

    #[test]
    fn multi_line_template() {
        let mut v = BTreeMap::new();
        v.insert("a", "1".to_string());
        v.insert("b", "2".to_string());
        let t = "line a={{a}}\nline b={{b}}\n";
        assert_eq!(render(t, &v), "line a=1\nline b=2\n");
    }
}
