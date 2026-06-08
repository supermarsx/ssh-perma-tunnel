//! "Forwards" page — add/edit/remove `[[profiles.forwards]]` entries.
//!
//! The page has two modes:
//!
//! * **list mode** — shows all forwards as rows; `j/k` moves between them,
//!   `a` adds a new entry, `d` deletes the focused entry, `Enter` opens the
//!   editor.
//! * **edit mode** — a [`FieldList`] for the focused forward.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Widget};
use spt_config::schema::{Forward, Profile};

use crate::model::Model;
use crate::pages::field::{
    opt_bool, opt_choice, opt_multi, opt_text, opt_u32, FieldDef, FieldList, FieldValue,
};
use crate::pages::Page;

const KIND: &[&str] = &["local", "remote", "dynamic"];
const TRANSPORT: &[&str] = &["tcp", "udp"];
const BIND_MODE: &[&str] = &[
    "loopback",
    "specific_ip",
    "specific_interface",
    "all_interfaces",
    "auto_interface",
];
const PROXY_PROTOCOLS: &[&str] = &["socks4", "socks4a", "socks5", "http_connect"];

/// Forwards list page.
pub struct ForwardsPage {
    /// Index of selected forward in the list view.
    selected: usize,
    /// `Some` when editor is open.
    editor: Option<ForwardEditor>,
    /// Cached list state for rendering.
    list_state: ListState,
}

struct ForwardEditor {
    /// Index of the forward being edited within `Profile.forwards`.
    #[allow(dead_code)]
    forward_index: usize,
    /// Field list for the editor.
    fields: FieldList,
}

impl ForwardsPage {
    /// Build the page.
    pub fn new() -> Self {
        Self {
            selected: 0,
            editor: None,
            list_state: ListState::default(),
        }
    }

    fn open_editor(&mut self, profile: &Profile, idx: usize) {
        if idx >= profile.forwards.len() {
            return;
        }
        let fields = forward_fields(idx);
        self.editor = Some(ForwardEditor {
            forward_index: idx,
            fields: FieldList::new(fields),
        });
    }
}

fn forward_fields(idx: usize) -> Vec<FieldDef> {
    // Each closure indexes into `profile.forwards[idx]`. Captures by value.
    let i = idx;
    vec![
        FieldDef {
            label: "name",
            help: "Forward identifier (unique within profile)",
            get: Box::new(move |p: &Profile| {
                FieldValue::Text(
                    p.forwards
                        .get(i)
                        .map(|f| f.name.clone())
                        .unwrap_or_default(),
                )
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Text(s) = v {
                    if let Some(f) = p.forwards.get_mut(i) {
                        f.name = s;
                    }
                }
            }),
            validate: None,
        },
        FieldDef {
            label: "type",
            help: "`local` (listen here) or `remote` (listen on peer)",
            get: Box::new(move |p: &Profile| FieldValue::Choice {
                value: p
                    .forwards
                    .get(i)
                    .map(|f| f.kind.clone())
                    .unwrap_or_default(),
                options: KIND,
                display: None,
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    if let Some(f) = p.forwards.get_mut(i) {
                        f.kind = value;
                    }
                }
            }),
            validate: None,
        },
        FieldDef {
            label: "transport",
            help: "`tcp` always; `udp` only with SSH3",
            get: Box::new(move |p: &Profile| FieldValue::Choice {
                value: p
                    .forwards
                    .get(i)
                    .map(|f| f.transport.clone())
                    .unwrap_or_default(),
                options: TRANSPORT,
                display: None,
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    if let Some(f) = p.forwards.get_mut(i) {
                        f.transport = value;
                    }
                }
            }),
            validate: None,
        },
        opt_text(
            "bind",
            "Listener address (e.g. `127.0.0.1:5432`)",
            move |p| p.forwards.get(i).and_then(|f| f.bind.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.bind = v;
                }
            },
        ),
        opt_text(
            "target",
            "Forwarding target (`host:port`)",
            move |p| p.forwards.get(i).and_then(|f| f.target.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.target = v;
                }
            },
        ),
        opt_choice(
            "bind_mode",
            "Bind mode (loopback, specific_ip, ...)",
            BIND_MODE,
            move |p| p.forwards.get(i).and_then(|f| f.bind_mode.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.bind_mode = v;
                }
            },
        ),
        opt_text(
            "bind_interface",
            "Bind to a named interface (when `bind_mode = specific_interface`)",
            move |p| p.forwards.get(i).and_then(|f| f.bind_interface.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.bind_interface = v;
                }
            },
        ),
        opt_bool(
            "expose",
            "Required for non-loopback binds (§9.14)",
            move |p| p.forwards.get(i).and_then(|f| f.expose),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.expose = v;
                }
            },
        ),
        opt_text(
            "idle_timeout",
            "Idle timeout (TCP/UDP)",
            move |p| p.forwards.get(i).and_then(|f| f.idle_timeout.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.idle_timeout = v;
                }
            },
        ),
        opt_u32(
            "max_connections",
            "Per-forward connection cap",
            move |p| p.forwards.get(i).and_then(|f| f.max_connections),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.max_connections = v;
                }
            },
        ),
        opt_multi(
            "proxy_protocols",
            "Dynamic proxy protocols (empty = all)",
            PROXY_PROTOCOLS,
            move |p| {
                p.forwards
                    .get(i)
                    .and_then(|f| f.proxy_protocols.clone())
                    .unwrap_or_default()
            },
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.proxy_protocols = if v.is_empty() { None } else { Some(v) };
                }
            },
        ),
        opt_u32(
            "max_packets_per_second",
            "UDP packet rate (SSH3)",
            move |p| p.forwards.get(i).and_then(|f| f.max_packets_per_second),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.max_packets_per_second = v;
                }
            },
        ),
    ]
}

impl Page for ForwardsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        // Left: list of forwards.
        let items: Vec<ListItem<'_>> = model
            .profile()
            .forwards
            .iter()
            .map(|f| {
                let target = if f.kind == "dynamic" {
                    f.proxy_protocols
                        .clone()
                        .unwrap_or_else(|| {
                            PROXY_PROTOCOLS.iter().map(|s| (*s).to_owned()).collect()
                        })
                        .join(",")
                } else {
                    f.target.clone().unwrap_or_else(|| "-".into())
                };
                ListItem::new(format!(
                    "{:>8} {:>5}  {} → {}",
                    f.kind,
                    f.transport,
                    f.bind.clone().unwrap_or_else(|| "-".into()),
                    target
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
            .title("Forwards (a=add, d=del, Enter=edit)");
        let list = List::new(items)
            .block(block)
            .highlight_style(style)
            .highlight_symbol("▶ ");
        ratatui::widgets::StatefulWidget::render(list, chunks[0], buf, &mut self.list_state);

        // Right: editor (if open) or summary.
        if let Some(ed) = self.editor.as_mut() {
            ed.fields.render(chunks[1], buf, model.profile());
        } else if let Some(f) = model.profile().forwards.get(self.selected) {
            let mut lines = vec![
                Line::from(format!("name:           {}", f.name)),
                Line::from(format!("type:           {}", f.kind)),
                Line::from(format!("transport:      {}", f.transport)),
                Line::from(format!(
                    "bind:           {}",
                    f.bind.clone().unwrap_or_default()
                )),
                Line::from(format!(
                    "target:         {}",
                    f.target.clone().unwrap_or_default()
                )),
            ];
            if f.kind == "dynamic" {
                lines.push(Line::from(format!(
                    "proxy_protocols: {}",
                    f.proxy_protocols
                        .clone()
                        .unwrap_or_else(|| PROXY_PROTOCOLS
                            .iter()
                            .map(|s| (*s).to_owned())
                            .collect())
                        .join(", ")
                )));
            }
            lines.extend([
                Line::from(format!(
                    "bind_mode:      {}",
                    f.bind_mode.clone().unwrap_or_default()
                )),
                Line::from(format!(
                    "expose:         {}",
                    f.expose.map(|b| b.to_string()).unwrap_or_default()
                )),
            ]);
            let block = Block::default().borders(Borders::ALL).title("Detail");
            Paragraph::new(lines).block(block).render(chunks[1], buf);
        } else {
            let block = Block::default().borders(Borders::ALL).title("Detail");
            Paragraph::new("(no forwards — press `a` to add)")
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
                let n = model.profile().forwards.len();
                if self.selected + 1 < n {
                    self.selected += 1;
                }
                false
            }
            KeyCode::Char('a') => {
                let f = Forward {
                    name: format!("forward-{}", model.profile().forwards.len() + 1),
                    kind: "local".into(),
                    transport: "tcp".into(),
                    bind: Some("127.0.0.1:0".into()),
                    target: Some("example.com:22".into()),
                    ..Default::default()
                };
                model.profile_mut().forwards.push(f);
                let idx = model.profile().forwards.len() - 1;
                self.selected = idx;
                self.open_editor(&model.profile().clone(), idx);
                true
            }
            KeyCode::Char('d') => {
                let n = model.profile().forwards.len();
                if self.selected < n {
                    model.profile_mut().forwards.remove(self.selected);
                    if self.selected >= model.profile().forwards.len() && self.selected > 0 {
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
name = "p"
protocol = "ssh2"
"#,
        )
    }

    #[test]
    fn add_pushes_new_forward_and_opens_editor() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        assert_eq!(m.profile().forwards.len(), 0);
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(m.profile().forwards.len(), 1);
        let f = &m.profile().forwards[0];
        assert_eq!(f.name, "forward-1");
        assert_eq!(f.kind, "local");
        assert_eq!(f.transport, "tcp");
        assert!(p.editor.is_some());
    }

    #[test]
    fn delete_removes_focused_forward() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        // Close the editor so 'd' is interpreted as the list-mode delete.
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
        p.on_key(k(KeyCode::Char('d')), &mut m);
        assert_eq!(m.profile().forwards.len(), 0);
    }

    #[test]
    fn esc_closes_editor() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert!(p.editor.is_some());
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
    }

    #[test]
    fn renders_with_no_forwards() {
        let mut p = ForwardsPage::new();
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
        // "no forwards" copy is shown.
        assert!(s.contains("press"));
    }

    #[test]
    fn renders_with_one_forward() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        let area = Rect::new(0, 0, 120, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(s.contains("local"));
    }

    #[test]
    fn down_does_not_go_past_end() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m); // close editor
                                           // Only one forward; Down should stay at 0.
        p.on_key(k(KeyCode::Down), &mut m);
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn up_at_zero_is_noop() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Up), &mut m);
        assert_eq!(p.selected, 0);
    }

    #[test]
    fn editor_field_count() {
        let fields = forward_fields(0);
        // 12 fields: name, type, transport, bind, target, bind_mode,
        //   bind_interface, expose, idle_timeout, max_connections,
        //   proxy_protocols, max_packets_per_second.
        assert_eq!(fields.len(), 12);
    }

    #[test]
    fn enter_opens_editor() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
        p.on_key(k(KeyCode::Enter), &mut m);
        assert!(p.editor.is_some());
    }

    #[test]
    fn editor_field_edit_updates_target() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open editor
                                                 // Move focus inside editor to "target" (index 4).
        for _ in 0..4 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
                                             // Erase existing value via End + N backspaces.
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..20 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "db:5432".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().forwards[0].target.as_deref(), Some("db:5432"));
    }
}
