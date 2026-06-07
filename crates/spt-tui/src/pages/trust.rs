//! "Trust" page — known_hosts file, SHA-256 host pins, TLS pins.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_bool, opt_choice, opt_list, opt_text, FieldList};
use crate::pages::Page;

const TRUST_MODE: &[&str] = &["known_hosts", "pinned"];

/// Trust verification settings.
pub struct TrustPage {
    list: FieldList,
}

impl TrustPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_choice(
                "trust.mode",
                "How host identity is verified (§9.13)",
                TRUST_MODE,
                |p| p.trust.as_ref().and_then(|t| t.mode.clone()),
                |p, v| p.trust.get_or_insert_with(Default::default).mode = v,
            ),
            opt_text(
                "trust.known_hosts_file",
                "Path to OpenSSH known_hosts file",
                |p| p.trust.as_ref().and_then(|t| t.known_hosts_file.clone()),
                |p, v| {
                    p.trust
                        .get_or_insert_with(Default::default)
                        .known_hosts_file = v;
                },
            ),
            opt_bool(
                "trust.strict",
                "Strict verification (no TOFU)",
                |p| p.trust.as_ref().and_then(|t| t.strict),
                |p, v| p.trust.get_or_insert_with(Default::default).strict = v,
            ),
            opt_bool(
                "trust.accept_new",
                "Trust-on-first-use for new keys",
                |p| p.trust.as_ref().and_then(|t| t.accept_new),
                |p, v| p.trust.get_or_insert_with(Default::default).accept_new = v,
            ),
            opt_list(
                "trust.pin_sha256",
                "Comma-separated SHA-256 host-key pins",
                |p| {
                    p.trust
                        .as_ref()
                        .and_then(|t| t.pin_sha256.clone())
                        .unwrap_or_default()
                },
                |p, v| {
                    p.trust.get_or_insert_with(Default::default).pin_sha256 =
                        if v.is_empty() { None } else { Some(v) };
                },
            ),
            opt_text(
                "tls.server_name",
                "SNI / verification name for SSH3 TLS",
                |p| p.tls.as_ref().and_then(|t| t.server_name.clone()),
                |p, v| p.tls.get_or_insert_with(Default::default).server_name = v,
            ),
            opt_text(
                "tls.ca_file",
                "Optional CA bundle file for SSH3 TLS",
                |p| p.tls.as_ref().and_then(|t| t.ca_file.clone()),
                |p, v| p.tls.get_or_insert_with(Default::default).ca_file = v,
            ),
            opt_list(
                "tls.pin_sha256",
                "Comma-separated SHA-256 cert pins",
                |p| {
                    p.tls
                        .as_ref()
                        .and_then(|t| t.pin_sha256.clone())
                        .unwrap_or_default()
                },
                |p, v| {
                    p.tls.get_or_insert_with(Default::default).pin_sha256 =
                        if v.is_empty() { None } else { Some(v) };
                },
            ),
            opt_bool(
                "tls.allow_self_signed",
                "Allow self-signed certs (requires pin or `ca_file`)",
                |p| p.tls.as_ref().and_then(|t| t.allow_self_signed),
                |p, v| p.tls.get_or_insert_with(Default::default).allow_self_signed = v,
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for TrustPage {
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
    fn builds_with_known_fields() {
        let p = TrustPage::new();
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        assert!(labels.contains(&"trust.mode"));
        assert!(labels.contains(&"trust.known_hosts_file"));
        assert!(labels.contains(&"trust.pin_sha256"));
        assert!(labels.contains(&"tls.pin_sha256"));
    }

    #[test]
    fn renders_without_panic() {
        let mut p = TrustPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 50);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn known_hosts_path_round_trip() {
        let mut p = TrustPage::new();
        let mut m = model();
        // Focus index 1 (trust.known_hosts_file).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "/etc/spt/known_hosts".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile()
                .trust
                .as_ref()
                .and_then(|t| t.known_hosts_file.clone()),
            Some("/etc/spt/known_hosts".to_owned())
        );
    }

    #[test]
    fn pin_sha256_list_round_trip() {
        let mut p = TrustPage::new();
        let mut m = model();
        // pin_sha256 is index 4.
        for _ in 0..4 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (List)
        for c in "aa, bb, cc".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        let pins = m
            .profile()
            .trust
            .as_ref()
            .and_then(|t| t.pin_sha256.clone())
            .unwrap_or_default();
        assert_eq!(pins, vec!["aa", "bb", "cc"]);
    }
}
