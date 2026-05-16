//! "Crypto" page — cipher / kex / mac / hostkey allow-lists.
//!
//! Defaults are the modern policy (spec §9.11).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_bool, opt_choice, opt_multi, FieldList};
use crate::pages::Page;

const POLICIES: &[&str] = &["modern", "interop", "legacy"];
const CIPHERS: &[&str] = &[
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes128-ctr",
];
const KEX: &[&str] = &[
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "ecdh-sha2-nistp256",
];
const MACS: &[&str] = &[
    "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com",
    "hmac-sha2-256",
    "hmac-sha2-512",
];
const HOSTKEYS: &[&str] = &[
    "ssh-ed25519",
    "rsa-sha2-512",
    "rsa-sha2-256",
    "ecdsa-sha2-nistp256",
];
const COMPRESSION: &[&str] = &["none", "zlib@openssh.com"];

/// Crypto allow-lists.
pub struct CryptoPage {
    list: FieldList,
}

impl CryptoPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_choice(
                "crypto.policy",
                "Named policy preset (`modern`, `interop`, `legacy`)",
                POLICIES,
                |p| p.crypto.as_ref().and_then(|c| c.policy.clone()),
                |p, v| p.crypto.get_or_insert_with(Default::default).policy = v,
            ),
            opt_bool(
                "crypto.allow_deprecated",
                "Permit deprecated algorithms in negotiation",
                |p| p.crypto.as_ref().and_then(|c| c.allow_deprecated),
                |p, v| {
                    p.crypto
                        .get_or_insert_with(Default::default)
                        .allow_deprecated = v;
                },
            ),
            opt_bool(
                "crypto.warn_on_deprecated",
                "Warn when a deprecated algorithm is used",
                |p| p.crypto.as_ref().and_then(|c| c.warn_on_deprecated),
                |p, v| {
                    p.crypto
                        .get_or_insert_with(Default::default)
                        .warn_on_deprecated = v;
                },
            ),
            opt_multi(
                "crypto.ciphers",
                "Cipher allow-list (space toggles, Esc commits)",
                CIPHERS,
                |p| {
                    p.crypto
                        .as_ref()
                        .and_then(|c| c.ciphers.clone())
                        .unwrap_or_default()
                },
                |p, v| {
                    p.crypto.get_or_insert_with(Default::default).ciphers =
                        if v.is_empty() { None } else { Some(v) };
                },
            ),
            opt_multi(
                "crypto.kex_algorithms",
                "KEX allow-list (space toggles)",
                KEX,
                |p| {
                    p.crypto
                        .as_ref()
                        .and_then(|c| c.kex_algorithms.clone())
                        .unwrap_or_default()
                },
                |p, v| {
                    p.crypto.get_or_insert_with(Default::default).kex_algorithms =
                        if v.is_empty() { None } else { Some(v) };
                },
            ),
            opt_multi(
                "crypto.macs",
                "MAC allow-list (space toggles)",
                MACS,
                |p| {
                    p.crypto
                        .as_ref()
                        .and_then(|c| c.macs.clone())
                        .unwrap_or_default()
                },
                |p, v| {
                    p.crypto.get_or_insert_with(Default::default).macs =
                        if v.is_empty() { None } else { Some(v) };
                },
            ),
            opt_multi(
                "crypto.host_key_algorithms",
                "Host-key algorithm allow-list (space toggles)",
                HOSTKEYS,
                |p| {
                    p.crypto
                        .as_ref()
                        .and_then(|c| c.host_key_algorithms.clone())
                        .unwrap_or_default()
                },
                |p, v| {
                    p.crypto
                        .get_or_insert_with(Default::default)
                        .host_key_algorithms = if v.is_empty() { None } else { Some(v) };
                },
            ),
            opt_multi(
                "crypto.compression",
                "Compression list",
                COMPRESSION,
                |p| {
                    p.crypto
                        .as_ref()
                        .and_then(|c| c.compression.clone())
                        .unwrap_or_default()
                },
                |p, v| {
                    p.crypto.get_or_insert_with(Default::default).compression =
                        if v.is_empty() { None } else { Some(v) };
                },
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for CryptoPage {
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
    fn builds_with_all_lists() {
        let p = CryptoPage::new();
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        assert!(labels.contains(&"crypto.ciphers"));
        assert!(labels.contains(&"crypto.kex_algorithms"));
        assert!(labels.contains(&"crypto.macs"));
        assert!(labels.contains(&"crypto.host_key_algorithms"));
        assert!(labels.contains(&"crypto.compression"));
    }

    #[test]
    fn renders_without_panic() {
        let mut p = CryptoPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 50);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn policy_choice_selects() {
        let mut p = CryptoPage::new();
        let mut m = model();
        // Index 0 is crypto.policy (Choice).
        p.on_key(k(KeyCode::Enter), &mut m);
        p.on_key(k(KeyCode::Down), &mut m); // index 1 = "interop"
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.profile()
                .crypto
                .as_ref()
                .and_then(|c| c.policy.clone())
                .as_deref(),
            Some("interop")
        );
    }

    #[test]
    fn multiselect_toggles_then_commits_on_s() {
        let mut p = CryptoPage::new();
        let mut m = model();
        // Index 3 is crypto.ciphers (Multi).
        for _ in 0..3 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (Multi)
        // Toggle the first option (Space) then commit via 's'.
        p.on_key(k(KeyCode::Char(' ')), &mut m);
        p.on_key(k(KeyCode::Char('s')), &mut m);
        let ciphers = m
            .profile()
            .crypto
            .as_ref()
            .and_then(|c| c.ciphers.clone())
            .unwrap_or_default();
        assert_eq!(ciphers, vec!["chacha20-poly1305@openssh.com"]);
    }
}
