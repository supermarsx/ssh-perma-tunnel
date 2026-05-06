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
            self.list.on_edit_key(key, model.profile_mut())
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }
}
