//! "Auth" page — auth method + per-method secret references.
//!
//! Spec §9.12: auth method is a tagged enum. The TUI persists the choice
//! into [`Profile::auth.method`] (string form) and exposes the relevant
//! reference fields (identity_file, passphrase, password, token, ...).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use spt_config::schema::{Auth, Profile};

use crate::model::Model;
use crate::pages::field::{
    opt_bool_with_help, opt_choice_with_help, opt_secret, opt_text, FieldDef, FieldList,
};
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
const METHODS_HELP: &[&str] = &[
    "OpenSSH public-key auth. Set `identity_file` and (optionally) `passphrase`.",
    "Delegate to ssh-agent (SSH_AUTH_SOCK / Pageant). No private-key material needed here.",
    "Password auth. Set `password` to a `secret://ns/name` reference.",
    "Server-driven challenge prompts (PAM, OTP). Set `password` for the canned response.",
    "OpenSSH user certificate. Set `identity_file` AND `certificate_file`.",
    "SSH3 bearer token. Set `token` to a `secret://ns/name` reference.",
    "HTTP Basic auth for SSH3. Set `user` + `password`. Avoid over plain HTTP.",
    "OIDC device-code flow (SSH3). Set `oidc_issuer` + `oidc_client_id`.",
];

/// Build the shared set of auth credential fields (method + identity/
/// certificate files + passphrase/password/token secrets + agent +
/// keyboard-interactive + OIDC issuer/client-id) for an `Option<Auth>`
/// target reachable from a [`Profile`].
///
/// This is the **single source of truth** for the auth editor used by
/// both [`AuthPage`] (global `[profiles.auth]`, via `|p| &mut p.auth`)
/// and the per-endpoint override on the Endpoints page (via
/// `|p| &mut p.endpoints[i].auth`). Centralising it guarantees the same
/// secret redaction (`opt_secret` → `FieldValue::SecretRef`) and
/// `secret://` validation everywhere a credential field is shown.
///
/// `get` borrows the target `Option<Auth>` immutably; `get_mut` borrows
/// it mutably. Both are `Copy` (function-pointer-friendly) closures so
/// they can be cloned into each per-field getter/setter. The `prefix`
/// is prepended to every label (e.g. `"auth"` → `"auth.method"`).
///
/// The labels are leaked to `&'static str` because [`FieldDef::label`]
/// requires `'static`; a small, bounded one-time leak per distinct
/// prefix is acceptable for a TUI page built once.
pub(crate) fn auth_fields<GR, GM>(prefix: &str, get: GR, get_mut: GM) -> Vec<FieldDef>
where
    GR: Fn(&Profile) -> Option<&Auth> + Copy + 'static,
    GM: Fn(&mut Profile) -> &mut Option<Auth> + Copy + 'static,
{
    // Helper: build a `&'static` label `"{prefix}.{suffix}"`.
    let lbl =
        |suffix: &str| -> &'static str { Box::leak(format!("{prefix}.{suffix}").into_boxed_str()) };

    vec![
        opt_choice_with_help(
            lbl("method"),
            "Spec §9.12 auth method",
            METHODS,
            METHODS_HELP,
            move |p| get(p).map(|a| a.method.clone()),
            move |p, v| {
                get_mut(p).get_or_insert_with(Default::default).method = v.unwrap_or_default();
            },
        ),
        opt_text(
            lbl("identity_file"),
            "Path to OpenSSH PEM private key (public_key, certificate)",
            move |p| get(p).and_then(|a| a.identity_file.clone()),
            move |p, v| {
                get_mut(p)
                    .get_or_insert_with(Default::default)
                    .identity_file = v;
            },
        ),
        opt_text(
            lbl("certificate_file"),
            "Path to OpenSSH user certificate (`*-cert.pub`)",
            move |p| get(p).and_then(|a| a.certificate_file.clone()),
            move |p, v| {
                get_mut(p)
                    .get_or_insert_with(Default::default)
                    .certificate_file = v;
            },
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
            lbl("passphrase"),
            "Secret ref for an encrypted private key — `secret://ns/name`",
            move |p| get(p).and_then(|a| a.passphrase.as_ref().map(|r| r.expose().to_owned())),
            move |p, v| {
                get_mut(p).get_or_insert_with(Default::default).passphrase =
                    v.map(spt_core::RedactedString::from);
            },
        ),
        opt_secret(
            lbl("password"),
            "Secret ref for password auth — `secret://ns/name`",
            move |p| get(p).and_then(|a| a.password.as_ref().map(|r| r.expose().to_owned())),
            move |p, v| {
                get_mut(p).get_or_insert_with(Default::default).password =
                    v.map(spt_core::RedactedString::from);
            },
        ),
        opt_secret(
            lbl("token"),
            "Secret ref for SSH3 bearer token — `secret://ns/name`",
            move |p| get(p).and_then(|a| a.token.as_ref().map(|r| r.expose().to_owned())),
            move |p, v| {
                get_mut(p).get_or_insert_with(Default::default).token =
                    v.map(spt_core::RedactedString::from);
            },
        ),
        opt_bool_with_help(
            lbl("agent"),
            "Try SSH agent (`SSH_AUTH_SOCK` / Pageant)",
            "Skip the SSH agent. Use when the agent is untrusted or out of scope.",
            "Try the SSH agent first, falling back to `identity_file`. Recommended.",
            move |p| get(p).and_then(|a| a.agent),
            move |p, v| get_mut(p).get_or_insert_with(Default::default).agent = v,
        ),
        opt_text(
            lbl("identity_hint"),
            "Agent identity hint string",
            move |p| get(p).and_then(|a| a.identity_hint.clone()),
            move |p, v| {
                get_mut(p)
                    .get_or_insert_with(Default::default)
                    .identity_hint = v;
            },
        ),
        opt_bool_with_help(
            lbl("keyboard_interactive"),
            "Allow SSH2 keyboard-interactive fallback",
            "Keyboard-interactive challenges refused. Safer — no human-style prompts.",
            "Permit keyboard-interactive prompts (PAM, OTP). Needed for some MFA setups.",
            move |p| get(p).and_then(|a| a.keyboard_interactive),
            move |p, v| {
                get_mut(p)
                    .get_or_insert_with(Default::default)
                    .keyboard_interactive = v;
            },
        ),
        opt_text(
            lbl("oidc_issuer"),
            "OIDC issuer URL (SSH3 OIDC device flow)",
            move |p| get(p).and_then(|a| a.oidc_issuer.clone()),
            move |p, v| get_mut(p).get_or_insert_with(Default::default).oidc_issuer = v,
        ),
        opt_text(
            lbl("oidc_client_id"),
            "OIDC client id",
            move |p| get(p).and_then(|a| a.oidc_client_id.clone()),
            move |p, v| {
                get_mut(p)
                    .get_or_insert_with(Default::default)
                    .oidc_client_id = v;
            },
        ),
    ]
}

/// Auth method + secret refs.
pub struct AuthPage {
    list: FieldList,
}

impl AuthPage {
    /// Build the page.
    ///
    /// This is the **global** default auth editor (`[profiles.auth]`).
    /// Individual endpoints may override it on the Endpoints page; when
    /// an endpoint sets its own auth, that whole block replaces this one
    /// for that endpoint.
    pub fn new() -> Self {
        let mut fields = vec![opt_text(
            "user",
            "Remote login user — global default; per-endpoint `user` overrides it",
            |p| p.user.clone(),
            |p, v| p.user = v,
        )];
        // Shared credential fields targeting the global `[profiles.auth]`.
        fields.extend(auth_fields(
            "auth",
            |p: &Profile| p.auth.as_ref(),
            |p: &mut Profile| &mut p.auth,
        ));
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
            let changed = self.list.on_edit_key(key, model.profile_mut_silent());
            if changed {
                model.mark_dirty();
            }
            changed
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }

    fn focused_help(&self) -> Option<&str> {
        self.list.focused_help()
    }
    fn focused_help_dynamic(&self, model: &Model) -> Option<&str> {
        self.list.focused_help_dynamic(model.profile())
    }
    fn focused_position(&self) -> Option<(usize, usize)> {
        self.list.focus_position()
    }
    fn is_editing(&self) -> bool {
        self.list.editing
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
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        // First field is `user` (moved from the deleted Connection page).
        assert_eq!(labels[0], "user");
        // Second field is auth.method choice.
        assert_eq!(labels[1], "auth.method");
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
        // Move to auth.passphrase (index 4: user, auth.method,
        // auth.identity_file, auth.certificate_file, auth.passphrase).
        for _ in 0..4 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "garbage".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert!(p.list.fields[4].last_error().is_some());
        assert!(p.list.editing);
    }

    #[test]
    fn valid_secret_ref_commits() {
        let mut p = AuthPage::new();
        let mut m = model();
        // Move to auth.passphrase (index 4).
        for _ in 0..4 {
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
        // Index 0 is `user` (Text); index 1 is auth.method (Choice). Skip past
        // `user` to land on the method field before entering edit mode.
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // edit auth.method
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
