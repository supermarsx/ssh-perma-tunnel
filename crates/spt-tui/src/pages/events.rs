//! "Events" page — per-profile binding tags.
//!
//! The global `[[events.bindings]]` table targets profiles by tag. This page
//! lets the user edit `Profile.tags` (which event bindings match against)
//! and shows a read-only view of which global bindings would fire for this
//! profile.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

use crate::model::Model;
use crate::pages::field::{opt_list, FieldList};
use crate::pages::Page;

/// Event tags + binding overview.
pub struct EventsPage {
    list: FieldList,
}

impl EventsPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![opt_list(
            "tags",
            "Free-form tags (CSV); event bindings can match by tag",
            |p| p.tags.clone().unwrap_or_default(),
            |p, v| p.tags = if v.is_empty() { None } else { Some(v) },
        )];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for EventsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(5), Constraint::Min(0)])
            .split(area);
        self.list.render(chunks[0], buf, model.profile());

        // Read-only summary of global bindings.
        let lines: Vec<Line<'_>> = model
            .config()
            .events
            .as_ref()
            .map(|e| {
                e.bindings
                    .iter()
                    .map(|b| {
                        Line::from(format!(
                            "{:<24} on=[{}] actions=[{}]",
                            b.name,
                            b.on.join(","),
                            b.actions.join(",")
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Global [[events.bindings]] (read-only here)");
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
