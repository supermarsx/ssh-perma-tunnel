//! "Keepalive" page (spec §11.3).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_text, opt_u32, FieldList};
use crate::pages::Page;

/// Keepalive timing.
pub struct KeepalivePage {
    list: FieldList,
}

impl KeepalivePage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_text(
                "keepalive.interval",
                "Time between keepalive probes (e.g. `30s`)",
                |p| p.keepalive.as_ref().and_then(|k| k.interval.clone()),
                |p, v| p.keepalive.get_or_insert_with(Default::default).interval = v,
            ),
            opt_text(
                "keepalive.timeout",
                "Per-probe response deadline",
                |p| p.keepalive.as_ref().and_then(|k| k.timeout.clone()),
                |p, v| p.keepalive.get_or_insert_with(Default::default).timeout = v,
            ),
            opt_u32(
                "keepalive.max_missed",
                "Maximum missed probes before session reset",
                |p| p.keepalive.as_ref().and_then(|k| k.max_missed),
                |p, v| p.keepalive.get_or_insert_with(Default::default).max_missed = v,
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for KeepalivePage {
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
    fn three_fields_built() {
        let p = KeepalivePage::new();
        assert_eq!(p.list.fields.len(), 3);
    }

    #[test]
    fn renders() {
        let mut p = KeepalivePage::new();
        let m = model();
        let area = Rect::new(0, 0, 80, 20);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn interval_round_trip() {
        let mut p = KeepalivePage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "30s".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile()
                .keepalive
                .as_ref()
                .and_then(|kk| kk.interval.clone())
                .as_deref(),
            Some("30s")
        );
    }

    #[test]
    fn max_missed_numeric() {
        let mut p = KeepalivePage::new();
        let mut m = model();
        for _ in 0..2 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "5".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile().keepalive.as_ref().and_then(|kk| kk.max_missed),
            Some(5)
        );
    }
}
