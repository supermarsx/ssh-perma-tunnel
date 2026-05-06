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
}
