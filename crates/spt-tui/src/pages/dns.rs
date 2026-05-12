//! "DNS" page — `dns_names` per forward, plus a summary view of the
//! global `[[dns.records]]` bound to this profile (for orientation only —
//! editing global records is out of scope for the per-profile wizard).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

use crate::model::Model;
use crate::pages::field::{opt_list, FieldList};
use crate::pages::Page;

/// DNS names registered by this profile's forwards.
pub struct DnsPage {
    list: FieldList,
}

impl DnsPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![opt_list(
            "forward[0].dns_names",
            "DNS names registered by the first forward (CSV)",
            |p| {
                p.forwards
                    .first()
                    .and_then(|f| f.dns_names.clone())
                    .unwrap_or_default()
            },
            |p, v| {
                if let Some(f) = p.forwards.first_mut() {
                    f.dns_names = if v.is_empty() { None } else { Some(v) };
                }
            },
        )];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for DnsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(5), Constraint::Min(0)])
            .split(area);
        self.list.render(chunks[0], buf, model.profile());

        // Show global [[dns.records]] for orientation.
        let lines: Vec<Line<'_>> = model
            .config()
            .dns
            .as_ref()
            .map(|d| {
                d.records
                    .iter()
                    .map(|r| Line::from(format!("{:<32} {:<5} {}", r.name, r.kind, r.value)))
                    .collect()
            })
            .unwrap_or_default();
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Global [[dns.records]] (read-only here — edit via `spt config render`)");
        Paragraph::new(lines).block(block).render(chunks[1], buf);
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
