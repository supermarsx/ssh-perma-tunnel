//! Render a [`Config`] back to canonical TOML.
//!
//! Renders are deterministic (stable key ordering, no extra whitespace) and
//! redact secret-bearing fields according to the requested
//! [`RedactionMode`].
//!
//! Determinism is provided by `toml::to_string_pretty` plus `Serialize` order
//! of the schema fields. We re-deserialize the rendered output via
//! `toml_edit` to apply secret-field redaction in-place without breaking
//! ordering or arrays.

use spt_core::{Error, RedactionMode, Result};
use toml_edit::{DocumentMut, Item, Value};

use crate::schema::Config;

/// Render a [`Config`] as canonical TOML.
///
/// `redact` controls how secret-bearing fields are emitted:
///
/// * [`RedactionMode::None`] — verbatim. Use only for trusted local debugging.
/// * [`RedactionMode::Standard`] (default) — replace all `secret://…` values
///   with `secret://[REDACTED]`. Inline plaintext password/token fields are
///   replaced with `[REDACTED]`.
/// * [`RedactionMode::Strict`] — `Standard` plus replace any IP-address-like
///   `host` and `endpoint` field values with `[REDACTED]`.
pub fn render(c: &Config, redact: RedactionMode) -> String {
    let raw = match toml::to_string_pretty(c) {
        Ok(s) => s,
        Err(e) => {
            // Schema is constructed entirely from owned strings/numbers — the
            // only way `to_string_pretty` can fail is a serialize-after-key
            // ordering bug, which is unreachable for our value types.
            return format!("# render error: {e}\n");
        }
    };

    if matches!(redact, RedactionMode::None) {
        return raw;
    }

    let mut doc: DocumentMut = match raw.parse() {
        Ok(d) => d,
        Err(_) => return raw,
    };

    redact_doc(doc.as_table_mut(), redact);

    doc.to_string()
}

/// Recurse through every item in `tbl` and apply secret redaction.
fn redact_doc(tbl: &mut toml_edit::Table, mode: RedactionMode) {
    let keys: Vec<String> = tbl.iter().map(|(k, _)| k.to_owned()).collect();
    for key in keys {
        let strict = matches!(mode, RedactionMode::Strict);
        if let Some(item) = tbl.get_mut(&key) {
            redact_item(&key, item, strict);
        }
    }
}

fn redact_item(key: &str, item: &mut Item, strict: bool) {
    match item {
        Item::Value(v) => redact_value(key, v, strict),
        Item::Table(t) => {
            let keys: Vec<String> = t.iter().map(|(k, _)| k.to_owned()).collect();
            for k in keys {
                if let Some(child) = t.get_mut(&k) {
                    redact_item(&k, child, strict);
                }
            }
        }
        Item::ArrayOfTables(arr) => {
            for tbl in arr.iter_mut() {
                let keys: Vec<String> = tbl.iter().map(|(k, _)| k.to_owned()).collect();
                for k in keys {
                    if let Some(child) = tbl.get_mut(&k) {
                        redact_item(&k, child, strict);
                    }
                }
            }
        }
        Item::None => {}
    }
}

fn redact_value(key: &str, value: &mut Value, strict: bool) {
    if let Value::String(formatted) = value {
        let s = formatted.value().clone();
        if let Some(replacement) = redacted_replacement(key, &s, strict) {
            *value = Value::from(replacement);
        }
    }
}

/// Returns `Some(replacement)` if the string at `key` should be redacted.
fn redacted_replacement(key: &str, raw: &str, strict: bool) -> Option<String> {
    if raw.starts_with("secret://") {
        return Some("secret://[REDACTED]".to_owned());
    }
    if matches!(
        key,
        "passphrase"
            | "password"
            | "token"
            | "auth"
            | "auth_secret"
            | "privacy_secret"
            | "fingerprint_sha256"
    ) {
        return Some("[REDACTED]".to_owned());
    }
    if strict && matches!(key, "host" | "endpoint" | "url" | "from" | "to" | "smtp") {
        return Some("[REDACTED]".to_owned());
    }
    None
}

/// Render a config to TOML, returning an error if the schema is somehow
/// non-serializable. This is the strict variant used by tests where any
/// failure is significant.
pub fn try_render(c: &Config, redact: RedactionMode) -> Result<String> {
    toml::to_string_pretty(c)
        .map(|raw| {
            if matches!(redact, RedactionMode::None) {
                return raw;
            }
            let mut doc: DocumentMut = raw.parse().expect("re-parse own output");
            redact_doc(doc.as_table_mut(), redact);
            doc.to_string()
        })
        .map_err(|e| Error::InvalidConfig(format!("render: {e}")))
}

#[cfg(test)]
mod tests {
    use super::render;
    use crate::load::load_str;
    use spt_core::RedactionMode;

    #[test]
    fn round_trip_minimum() {
        let raw = r#"
            version = 1
            [[profiles]]
            name = "p"
            protocol = "ssh2"
        "#;
        let (c, _) = load_str(raw, false).unwrap();
        let rendered = render(&c, RedactionMode::None);
        let (c2, _) = load_str(&rendered, false).unwrap();
        assert_eq!(c, c2, "load -> render -> load identity");
    }

    #[test]
    fn redacts_secret_uri() {
        let raw = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
[profiles.auth]
method = "public_key"
passphrase = "secret://ssh/p/passphrase"
"#;
        let (c, _) = load_str(raw, false).unwrap();
        let out = render(&c, RedactionMode::Standard);
        assert!(out.contains("secret://[REDACTED]"));
        assert!(!out.contains("ssh/p/passphrase"));
    }

    #[test]
    fn redacts_inline_plaintext_token() {
        let raw = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh3"
acknowledge_experimental = true
endpoint = "https://x.example.com:443/ssh3"
[profiles.auth]
method = "bearer_token"
token = "tok_123"
"#;
        let (c, _) = load_str(raw, false).unwrap();
        let out = render(&c, RedactionMode::Standard);
        assert!(out.contains("[REDACTED]"));
        assert!(!out.contains("tok_123"));
    }

    #[test]
    fn none_mode_passthrough() {
        let raw = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
[profiles.auth]
method = "password"
password = "secret://x/y"
"#;
        let (c, _) = load_str(raw, false).unwrap();
        let out = render(&c, RedactionMode::None);
        assert!(out.contains("secret://x/y"));
    }

    #[test]
    fn strict_redacts_endpoint() {
        let raw = r#"
version = 1
[[profiles]]
name = "p"
protocol = "ssh3"
endpoint = "https://api.example.com/ssh3"
acknowledge_experimental = true
[profiles.auth]
method = "bearer_token"
token = "secret://t/k"
"#;
        let (c, _) = load_str(raw, false).unwrap();
        let out = render(&c, RedactionMode::Strict);
        assert!(!out.contains("api.example.com"));
        assert!(out.contains("[REDACTED]"));
    }
}
