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
            opt_secret(
                "auth.passphrase",
                "Secret ref for an encrypted private key — `secret://ns/name`",
                |p| p.auth.as_ref().and_then(|a| a.passphrase.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).passphrase = v,
            ),
            opt_secret(
                "auth.password",
                "Secret ref for password auth — `secret://ns/name`",
                |p| p.auth.as_ref().and_then(|a| a.password.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).password = v,
            ),
            opt_secret(
                "auth.token",
                "Secret ref for SSH3 bearer token — `secret://ns/name`",
                |p| p.auth.as_ref().and_then(|a| a.token.clone()),
                |p, v| p.auth.get_or_insert_with(Default::default).token = v,
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
