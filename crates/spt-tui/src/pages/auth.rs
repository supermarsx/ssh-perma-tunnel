//! "Auth" page — auth method + per-method secret references.
//!
//! Spec §9.12: auth method is a tagged enum. The TUI persists the choice
//! into [`Profile::auth.method`] (string form) and exposes the relevant
//! reference fields (identity_file, passphrase, password, token, ...).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_bool, opt_choice, opt_secret, opt_text, FieldList};
use crate::pages::Page;

const METHODS: &[&str] = &[
    "public_key",
    "agent",
    "password",
    "keyboard_interactive",
    "certificate",
    "bearer",
    "basic",
    "oidc_device_flow",
];

/// Auth method + secret refs.
pub struct AuthPage {
    list: FieldList,
}

impl AuthPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_choice(
                "auth.method",
                "Spec §9.12 auth method",
                METHODS,
                |p| p.auth.as_ref().map(|a| a.method.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).method = v.unwrap_or_default(),
            ),
            opt_text(
                "auth.identity_file",
                "Path to OpenSSH PEM private key (public_key, certificate)",
                |p| p.auth.as_ref().and_then(|a| a.identity_file.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).identity_file = v,
            ),
            opt_text(
                "auth.certificate_file",
                "Path to OpenSSH user certificate (`*-cert.pub`)",
                |p| p.auth.as_ref().and_then(|a| a.certificate_file.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).certificate_file = v,
            ),
            // The schema stores these as `Option<RedactedString>` (t5-e7) so the
            // value zeroes on drop and never leaks through derived `Debug`.
            // The TUI form layer still works on `Option<String>`, so the
            // getter exposes the cleartext (Display via `.to_string()`) and
            // the setter wraps incoming text back into `RedactedString`. The
            // cleartext lives in `FieldValue::SecretRef(String)` only for the
            // duration of a single edit-and-commit; redaction at render-time
            // still applies via the `FieldValue::SecretRef` variant.
            opt_secret(
                "auth.passphrase",
                "Secret ref for an encrypted private key — `secret://ns/name`",
                |p| {
                    p.auth
                        .as_ref()
                        .and_then(|a| a.passphrase.as_ref().map(|r| r.expose().to_owned()))
                },
                |p, v| {
                    p.auth.get_or_insert_with(Default::default).passphrase =
                        v.map(spt_core::RedactedString::from);
                },
            ),
            opt_secret(
                "auth.password",
                "Secret ref for password auth — `secret://ns/name`",
                |p| {
                    p.auth
                        .as_ref()
                        .and_then(|a| a.password.as_ref().map(|r| r.expose().to_owned()))
                },
                |p, v| {
                    p.auth.get_or_insert_with(Default::default).password =
                        v.map(spt_core::RedactedString::from);
                },
            ),
            opt_secret(
                "auth.token",
                "Secret ref for SSH3 bearer token — `secret://ns/name`",
                |p| {
                    p.auth
                        .as_ref()
                        .and_then(|a| a.token.as_ref().map(|r| r.expose().to_owned()))
                },
                |p, v| {
                    p.auth.get_or_insert_with(Default::default).token =
                        v.map(spt_core::RedactedString::from);
                },
            ),
            opt_bool(
                "auth.agent",
                "Try SSH agent (`SSH_AUTH_SOCK` / Pageant)",
                |p| p.auth.as_ref().and_then(|a| a.agent),
                |p, v| p.auth.get_or_insert_with(Default::default).agent = v,
            ),
            opt_text(
                "auth.identity_hint",
                "Agent identity hint string",
                |p| p.auth.as_ref().and_then(|a| a.identity_hint.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).identity_hint = v,
            ),
            opt_bool(
                "auth.keyboard_interactive",
                "Allow SSH2 keyboard-interactive fallback",
                |p| p.auth.as_ref().and_then(|a| a.keyboard_interactive),
                |p, v| {
                    p.auth
                        .get_or_insert_with(Default::default)
                        .keyboard_interactive = v;
                },
            ),
            opt_text(
                "auth.oidc_issuer",
                "OIDC issuer URL (SSH3 OIDC device flow)",
                |p| p.auth.as_ref().and_then(|a| a.oidc_issuer.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).oidc_issuer = v,
            ),
            opt_text(
                "auth.oidc_client_id",
                "OIDC client id",
                |p| p.auth.as_ref().and_then(|a| a.oidc_client_id.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).oidc_client_id = v,
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for AuthPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        self.list.render(area, buf, model.profile());
    }
    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if self.list.editing {
            self.list.on_edit_key(key, model.profile_mut())
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn model() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        )
    }

    #[test]
    fn builds_with_expected_method_choices() {
        let p = AuthPage::new();
        // First field is auth.method choice.
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        assert!(labels.contains(&"auth.method"));
        assert!(labels.contains(&"auth.identity_file"));
        assert!(labels.contains(&"auth.passphrase"));
        assert!(labels.contains(&"auth.token"));
    }

    #[test]
    fn renders_without_panic() {
        let mut p = AuthPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 50);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn invalid_secret_ref_blocks_commit() {
        let mut p = AuthPage::new();
        let mut m = model();
        // Move to auth.passphrase (index 3).
        for _ in 0..3 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "garbage".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert!(p.list.fields[3].last_error().is_some());
        assert!(p.list.editing);
    }

    #[test]
    fn valid_secret_ref_commits() {
        let mut p = AuthPage::new();
        let mut m = model();
        // Move to auth.passphrase (index 3).
        for _ in 0..3 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "secret://ns/key".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert!(!p.list.editing);
        let v = m.profile().auth.as_ref().and_then(|a| a.passphrase.clone());
        assert_eq!(v.as_deref(), Some("secret://ns/key"));
    }

    #[test]
    fn method_choice_cycles_via_down_arrow() {
        let mut p = AuthPage::new();
        let mut m = model();
        // Index 0 is auth.method (Choice).
        p.on_key(k(KeyCode::Enter), &mut m); // edit
                                             // Press Down then Enter to pick the next option.
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // commit selection
        let method = m
            .profile()
            .auth
            .as_ref()
            .map(|a| a.method.clone())
            .unwrap_or_default();
        // First option is "public_key"; Down moves index to 1 = "agent".
        assert_eq!(method, "agent");
    }
}
