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
                |p, v| p.trust.get_or_insert_with(Default::default).known_hosts_file = v,
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
            self.list.on_edit_key(key, model.profile_mut())
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }
}
