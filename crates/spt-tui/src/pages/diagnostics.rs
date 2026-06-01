//! "Diagnostics / observability" page — diagnostic tags + custom metric labels.
//!
//! Spec §13.12 / §13.8: every profile contributes its `tags` to log /
//! metric / event labels. SSH3-related observability flags also live here.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_bool, opt_list, opt_text, FieldList};
use crate::pages::Page;

/// Diagnostics / observability tags.
pub struct DiagnosticsPage {
    list: FieldList,
}

impl DiagnosticsPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_list(
                "tags",
                "Tags applied as labels on logs / metrics / events (CSV)",
                |p| p.tags.clone().unwrap_or_default(),
                |p, v| p.tags = if v.is_empty() { None } else { Some(v) },
            ),
            opt_bool(
                "acknowledge_experimental",
                "Required for SSH3 profiles to start without a warning",
                |p| p.acknowledge_experimental,
                |p, v| p.acknowledge_experimental = v,
            ),
            opt_text(
                "ssh3.idle_timeout",
                "QUIC idle timeout (SSH3 profiles only)",
                |p| p.ssh3.as_ref().and_then(|s| s.idle_timeout.clone()),
                |p, v| p.ssh3.get_or_insert_with(Default::default).idle_timeout = v,
            ),
            opt_text(
                "ssh3.keepalive",
                "QUIC keepalive interval (SSH3)",
                |p| p.ssh3.as_ref().and_then(|s| s.keepalive.clone()),
                |p, v| p.ssh3.get_or_insert_with(Default::default).keepalive = v,
            ),
            opt_bool(
                "ssh3.enable_datagrams",
                "QUIC datagrams (UDP forwarding) for SSH3",
                |p| p.ssh3.as_ref().and_then(|s| s.enable_datagrams),
                |p, v| p.ssh3.get_or_insert_with(Default::default).enable_datagrams = v,
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for DiagnosticsPage {
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
    fn builds_with_expected_fields() {
        let p = DiagnosticsPage::new();
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        assert!(labels.contains(&"tags"));
        assert!(labels.contains(&"acknowledge_experimental"));
        assert!(labels.contains(&"ssh3.idle_timeout"));
    }

    #[test]
    fn renders_without_panic() {
        let mut p = DiagnosticsPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn tags_list_round_trip() {
        let mut p = DiagnosticsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "alpha, beta".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        let tags = m.profile().tags.clone().unwrap_or_default();
        assert_eq!(tags, vec!["alpha", "beta"]);
    }

    #[test]
    fn ack_experimental_toggle() {
        let mut p = DiagnosticsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Down), &mut m); // focus index 1
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (Bool false)
        p.on_key(k(KeyCode::Enter), &mut m); // flip+commit
        assert_eq!(m.profile().acknowledge_experimental, Some(true));
    }
}
