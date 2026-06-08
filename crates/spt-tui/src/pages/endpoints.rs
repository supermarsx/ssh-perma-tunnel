//! "Endpoints" page — add/edit/remove `[[profiles.endpoints]]` entries.
//!
//! Mirrors [`crate::pages::forwards::ForwardsPage`] structurally. The page
//! has two modes:
//!
//! * **list mode** — shows all endpoints as rows; `j/k` moves between them,
//!   `a` adds a new entry, `d` deletes the focused entry, `Enter` opens the
//!   editor.
//! * **edit mode** — a [`FieldList`] for the focused endpoint.
//!
//! Per-spec, endpoint `name` uniqueness is enforced at canonicalisation time
//! by `spt_config::validate` (the per-field validator does not see the full
//! profile), and is surfaced on the Review page.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Widget};
use spt_config::schema::{Endpoint, Profile};

use crate::model::Model;
use crate::pages::field::{opt_u32, FieldDef, FieldList, FieldValue};
use crate::pages::Page;

/// Endpoints list page.
pub struct EndpointsPage {
    /// Index of selected endpoint in the list view.
    selected: usize,
    /// `Some` when editor is open.
    editor: Option<EndpointEditor>,
    /// Cached list state for rendering.
    list_state: ListState,
}

struct EndpointEditor {
    /// Index of the endpoint being edited within `Profile.endpoints`.
    #[allow(dead_code)]
    endpoint_index: usize,
    /// Field list for the editor.
    fields: FieldList,
}

impl EndpointsPage {
    /// Build the page.
    pub fn new() -> Self {
        Self {
            selected: 0,
            editor: None,
            list_state: ListState::default(),
        }
    }

    fn open_editor(&mut self, profile: &Profile, idx: usize) {
        if idx >= profile.endpoints.len() {
            return;
        }
        let fields = endpoint_fields(idx);
        self.editor = Some(EndpointEditor {
            endpoint_index: idx,
            fields: FieldList::new(fields),
        });
    }
}

impl Default for EndpointsPage {
    fn default() -> Self {
        Self::new()
    }
}

fn endpoint_fields(idx: usize) -> Vec<FieldDef> {
    let i = idx;
    vec![
        // name — Text. Non-empty required; uniqueness deferred to validate.
        FieldDef {
            label: "name",
            help: "Endpoint identifier (must be unique — checked on Review)",
            get: Box::new(move |p: &Profile| {
                FieldValue::Text(
                    p.endpoints
                        .get(i)
                        .map(|e| e.name.clone())
                        .unwrap_or_default(),
                )
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Text(s) = v {
                    if let Some(e) = p.endpoints.get_mut(i) {
                        e.name = s;
                    }
                }
            }),
            validate: Some(Box::new(|v| {
                if let FieldValue::Text(s) = v {
                    if s.is_empty() {
                        return Some("name must not be empty".into());
                    }
                }
                None
            })),
            bool_option_help: None,
        },
        // host — Text. Non-empty required.
        FieldDef {
            label: "host",
            help: "Hostname or IP",
            get: Box::new(move |p: &Profile| {
                FieldValue::Text(
                    p.endpoints
                        .get(i)
                        .map(|e| e.host.clone())
                        .unwrap_or_default(),
                )
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Text(s) = v {
                    if let Some(e) = p.endpoints.get_mut(i) {
                        e.host = s;
                    }
                }
            }),
            validate: Some(Box::new(|v| {
                if let FieldValue::Text(s) = v {
                    if s.is_empty() {
                        return Some("host must not be empty".into());
                    }
                }
                None
            })),
            bool_option_help: None,
        },
        // port — Numeric(u16). Required (struct field is u16, not Option).
        // Reject empty, parse failures, and 0.
        FieldDef {
            label: "port",
            help: "Port (1-65535)",
            get: Box::new(move |p: &Profile| {
                FieldValue::Numeric(
                    p.endpoints
                        .get(i)
                        .map(|e| e.port.to_string())
                        .unwrap_or_default(),
                )
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Numeric(s) = v {
                    if let Ok(n) = s.parse::<u16>() {
                        if n >= 1 {
                            if let Some(e) = p.endpoints.get_mut(i) {
                                e.port = n;
                            }
                        }
                    }
                }
            }),
            validate: Some(Box::new(|v| {
                if let FieldValue::Numeric(s) = v {
                    match s.parse::<u16>() {
                        Ok(n) if n >= 1 => None,
                        _ => Some(format!("`{s}` is not a valid TCP port (1-65535)")),
                    }
                } else {
                    None
                }
            })),
            bool_option_help: None,
        },
        // priority — Option<u32>.
        opt_u32(
            "priority",
            "Priority (lower = preferred; failover mode 'priority' picks lowest)",
            move |p| p.endpoints.get(i).and_then(|e| e.priority),
            move |p, v| {
                if let Some(e) = p.endpoints.get_mut(i) {
                    e.priority = v;
                }
            },
        ),
        // weight — Option<u32>.
        opt_u32(
            "weight",
            "Weight (random-weighted within priority tier in mode 'weighted')",
            move |p| p.endpoints.get(i).and_then(|e| e.weight),
            move |p, v| {
                if let Some(e) = p.endpoints.get_mut(i) {
                    e.weight = v;
                }
            },
        ),
    ]
}

impl Page for EndpointsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        // Left: list of endpoints.
        let items: Vec<ListItem<'_>> = model
            .profile()
            .endpoints
            .iter()
            .map(|e| {
                let priority = e.priority.map_or_else(|| "-".into(), |n| n.to_string());
                let weight = e.weight.map_or_else(|| "-".into(), |n| n.to_string());
                ListItem::new(format!(
                    "{:>12} {}:{}  p={} w={}",
                    e.name, e.host, e.port, priority, weight
                ))
            })
            .collect();
        self.list_state
            .select(Some(self.selected.min(items.len().saturating_sub(1))));

        let style = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Endpoints (a=add, d=del, Enter=edit)");
        let list = List::new(items)
            .block(block)
            .highlight_style(style)
            .highlight_symbol("▶ ");
        ratatui::widgets::StatefulWidget::render(list, chunks[0], buf, &mut self.list_state);

        // Right: editor (if open) or summary.
        if let Some(ed) = self.editor.as_mut() {
            ed.fields.render(chunks[1], buf, model.profile());
        } else if let Some(e) = model.profile().endpoints.get(self.selected) {
            let lines = vec![
                Line::from(format!("name:     {}", e.name)),
                Line::from(format!("host:     {}", e.host)),
                Line::from(format!("port:     {}", e.port)),
                Line::from(format!(
                    "priority: {}",
                    e.priority.map(|n| n.to_string()).unwrap_or_default()
                )),
                Line::from(format!(
                    "weight:   {}",
                    e.weight.map(|n| n.to_string()).unwrap_or_default()
                )),
            ];
            let block = Block::default().borders(Borders::ALL).title("Detail");
            Paragraph::new(lines).block(block).render(chunks[1], buf);
        } else {
            let block = Block::default().borders(Borders::ALL).title("Detail");
            Paragraph::new("(no endpoints — press `a` to add)")
                .block(block)
                .render(chunks[1], buf);
        }
    }

    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        // Editor mode delegates everything except Esc.
        if let Some(ed) = self.editor.as_mut() {
            match key.code {
                KeyCode::Esc if !ed.fields.editing => {
                    self.editor = None;
                    return false;
                }
                _ => {
                    if ed.fields.editing {
                        let changed = ed.fields.on_edit_key(key, model.profile_mut_silent());
                        if changed {
                            model.mark_dirty();
                        }
                        return changed;
                    }
                    let p = model.profile().clone();
                    ed.fields.on_nav_key(key, &p);
                    return false;
                }
            }
        }

        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = model.profile().endpoints.len();
                if self.selected + 1 < n {
                    self.selected += 1;
                }
                false
            }
            KeyCode::Char('a') => {
                let e = Endpoint {
                    name: format!("endpoint-{}", model.profile().endpoints.len() + 1),
                    host: "example.com".into(),
                    port: 22,
                    priority: None,
                    weight: None,
                };
                model.profile_mut().endpoints.push(e);
                let idx = model.profile().endpoints.len() - 1;
                self.selected = idx;
                self.open_editor(&model.profile().clone(), idx);
                true
            }
            KeyCode::Char('d') => {
                let n = model.profile().endpoints.len();
                if self.selected < n {
                    model.profile_mut().endpoints.remove(self.selected);
                    if self.selected >= model.profile().endpoints.len() && self.selected > 0 {
                        self.selected -= 1;
                    }
                    return true;
                }
                false
            }
            KeyCode::Enter => {
                let p = model.profile().clone();
                self.open_editor(&p, self.selected);
                false
            }
            _ => false,
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
name = "demo"
protocol = "ssh2"
host = "h.example.com"
"#,
        )
    }

    #[test]
    fn add_pushes_new_endpoint_and_opens_editor() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        assert_eq!(m.profile().endpoints.len(), 0);
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(m.profile().endpoints.len(), 1);
        let e = &m.profile().endpoints[0];
        assert_eq!(e.name, "endpoint-1");
        assert_eq!(e.host, "example.com");
        assert_eq!(e.port, 22);
        assert!(e.priority.is_none());
        assert!(e.weight.is_none());
        assert!(p.editor.is_some());
    }

    #[test]
    fn delete_removes_focused_endpoint() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        // Close the editor so 'd' is interpreted as the list-mode delete.
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
        p.on_key(k(KeyCode::Char('d')), &mut m);
        assert_eq!(m.profile().endpoints.len(), 0);
    }

    #[test]
    fn esc_closes_editor() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert!(p.editor.is_some());
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
    }

    #[test]
    fn renders_with_no_endpoints() {
        let mut p = EndpointsPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        // The empty-state copy invites the user to add.
        assert!(s.contains("press"));
    }

    #[test]
    fn renders_with_one_endpoint() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        // Close editor so the left list-detail render is exercised, not just
        // the editor pane.
        p.on_key(k(KeyCode::Esc), &mut m);
        let area = Rect::new(0, 0, 120, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(s.contains("endpoint-1"));
        assert!(s.contains("example.com"));
    }

    #[test]
    fn down_does_not_go_past_end() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m); // close editor
                                           // Only one endpoint; Down should stay at 0.
        p.on_key(k(KeyCode::Down), &mut m);
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn up_at_zero_is_noop() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Up), &mut m);
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn editor_field_count() {
        let fields = endpoint_fields(0);
        // 5 fields: name, host, port, priority, weight.
        assert_eq!(fields.len(), 5);
    }

    #[test]
    fn enter_opens_editor() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
        p.on_key(k(KeyCode::Enter), &mut m);
        assert!(p.editor.is_some());
    }

    #[test]
    fn editor_field_edit_updates_host() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open editor
                                                 // Move focus inside editor to "host" (index 1).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
                                             // Erase existing value via End + N backspaces.
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..30 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "edge.example.org".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().endpoints[0].host, "edge.example.org");
    }

    #[test]
    fn port_validation_rejects_overflow() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add (port = 22)
                                                 // Move focus to "port" (index 2).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
                                             // Clear current "22" then type a u16 overflow.
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..4 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "99999".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit (must fail validation)
        let ed = p
            .editor
            .as_ref()
            .expect("editor still open after failed commit");
        assert!(
            ed.fields.fields[2].last_error().is_some(),
            "port validator must reject u16 overflow"
        );
        // Profile port unchanged.
        assert_eq!(m.profile().endpoints[0].port, 22);
    }

    #[test]
    fn port_validation_rejects_zero() {
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add (port = 22)
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..4 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        p.on_key(k(KeyCode::Char('0')), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // commit (must fail validation)
        let ed = p
            .editor
            .as_ref()
            .expect("editor still open after failed commit");
        assert!(
            ed.fields.fields[2].last_error().is_some(),
            "port validator must reject 0"
        );
        assert_eq!(m.profile().endpoints[0].port, 22);
    }
}
