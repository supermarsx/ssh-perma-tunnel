//! "Limits" page — connection caps, byte/packet throttles.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_choice, opt_text, opt_u32, FieldList};
use crate::pages::Page;

const ALGORITHMS: &[&str] = &["token_bucket", "leaky_bucket"];

/// Per-profile limits.
pub struct LimitsPage {
    list: FieldList,
}

impl LimitsPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_u32(
                "limits.max_active_connections",
                "Maximum active forwarded connections",
                |p| p.limits.as_ref().and_then(|l| l.max_active_connections),
                |p, v| {
                    p.limits.get_or_insert_with(Default::default).max_active_connections = v;
                },
            ),
            opt_u32(
                "limits.max_new_connections_per_second",
                "Accept rate (per second)",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_new_connections_per_second)
                },
                |p, v| {
                    p.limits.get_or_insert_with(Default::default).max_new_connections_per_second = v;
                },
            ),
            opt_text(
                "limits.max_bytes_per_second_in",
                "Inbound byte rate (e.g. `20MiB`)",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_bytes_per_second_in.clone())
                },
                |p, v| {
                    p.limits.get_or_insert_with(Default::default).max_bytes_per_second_in = v;
                },
            ),
            opt_text(
                "limits.max_bytes_per_second_out",
                "Outbound byte rate",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_bytes_per_second_out.clone())
                },
                |p, v| {
                    p.limits.get_or_insert_with(Default::default).max_bytes_per_second_out = v;
                },
            ),
            opt_choice(
                "limits.throttle_algorithm",
                "Throttle algorithm",
                ALGORITHMS,
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.throttle_algorithm.clone())
                },
                |p, v| {
                    p.limits.get_or_insert_with(Default::default).throttle_algorithm = v;
                },
            ),
            opt_text(
                "limits.max_connection_lifetime",
                "Maximum lifetime of a single forwarded connection",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_connection_lifetime.clone())
                },
                |p, v| {
                    p.limits.get_or_insert_with(Default::default).max_connection_lifetime = v;
                },
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for LimitsPage {
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
