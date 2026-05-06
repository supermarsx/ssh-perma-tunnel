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
use crate::pages::field::{opt_bool, opt_choice, opt_text, opt_u32, FieldDef, FieldList, FieldValue};
use crate::pages::Page;

const KIND: &[&str] = &["local", "remote"];
const TRANSPORT: &[&str] = &["tcp", "udp"];
const BIND_MODE: &[&str] = &[
    "loopback",
    "specific_ip",
    "specific_interface",
    "all_interfaces",
    "auto_interface",
];

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
                FieldValue::Text(p.forwards.get(i).map(|f| f.name.clone()).unwrap_or_default())
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
                value: p.forwards.get(i).map(|f| f.kind.clone()).unwrap_or_default(),
                options: KIND,
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
                ListItem::new(format!(
                    "{:>8} {:>5}  {} → {}",
                    f.kind,
                    f.transport,
                    f.bind.clone().unwrap_or_else(|| "-".into()),
                    f.target.clone().unwrap_or_else(|| "-".into())
                ))
            })
            .collect();
        self.list_state.select(Some(self.selected.min(items.len().saturating_sub(1))));

        let style = Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD);
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
            let lines = vec![
                Line::from(format!("name:           {}", f.name)),
                Line::from(format!("type:           {}", f.kind)),
                Line::from(format!("transport:      {}", f.transport)),
                Line::from(format!("bind:           {}", f.bind.clone().unwrap_or_default())),
                Line::from(format!("target:         {}", f.target.clone().unwrap_or_default())),
                Line::from(format!(
                    "bind_mode:      {}",
                    f.bind_mode.clone().unwrap_or_default()
                )),
                Line::from(format!(
                    "expose:         {}",
                    f.expose.map(|b| b.to_string()).unwrap_or_default()
                )),
            ];
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
                        return ed.fields.on_edit_key(key, model.profile_mut());
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
                    if self.selected >= model.profile().forwards.len()
                        && self.selected > 0
                    {
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
