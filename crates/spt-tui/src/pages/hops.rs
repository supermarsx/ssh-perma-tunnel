//! "Hops" page — add/edit/remove `[[profiles.hops]]` entries (multi-hop /
//! proxy-jump, §8.2).
//!
//! Structurally mirrors [`crate::pages::endpoints::EndpointsPage`]: a two-pane
//! list + per-hop [`FieldList`] editor.
//!
//! * **list mode** — shows all hops; `j/k` moves, `a` adds, `d` deletes,
//!   `Enter`/`→` opens the editor.
//! * **edit mode** — a [`FieldList`] for the focused hop.
//!
//! Editable per hop: `name`, `protocol`, `host`, `port`, `user`, `kind`
//! (ssh / socks5 / http-connect), `target_resolve`, and `proxy_username`.
//! The `proxy_password_ref` (a `spt_secrets::SecretRef`) is preserved on save
//! but is not editable here — that secret type is not constructible from the
//! TUI crate without a new dependency.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Widget};
use spt_config::schema::{Hop, HopKind, Profile};

use crate::model::Model;
use crate::pages::field::{opt_choice_with_help, opt_text, FieldDef, FieldList, FieldValue};
use crate::pages::Page;

const HOP_PROTOCOLS: &[&str] = &["ssh2", "ssh3"];
const HOP_PROTOCOLS_HELP: &[&str] = &[
    "Classic SSH over TCP to reach this hop.",
    "francoismichel/ssh3 (QUIC/HTTP-3) to reach this hop.",
];
const HOP_KINDS: &[&str] = &["ssh", "socks5", "http-connect"];
const HOP_KINDS_HELP: &[&str] = &[
    "Re-establish an SSH session through this hop (classic proxy-jump).",
    "SOCKS5 proxy hop (RFC 1928; optional username/password auth).",
    "HTTP CONNECT proxy hop (optional Basic Proxy-Authorization).",
];
const TARGET_RESOLVE: &[&str] = &["local", "remote", "previous-hop"];
const TARGET_RESOLVE_HELP: &[&str] = &[
    "Resolve the next hop's name on this client.",
    "Resolve the next hop's name on this hop (remote resolution).",
    "Resolve using the previous hop in the chain.",
];

/// Map [`HopKind`] to its canonical kebab-case string.
fn hopkind_str(k: HopKind) -> &'static str {
    match k {
        HopKind::Ssh => "ssh",
        HopKind::Socks5 => "socks5",
        HopKind::HttpConnect => "http-connect",
    }
}

/// Map a canonical string back to [`HopKind`] (defaulting to `Ssh`).
fn str_hopkind(s: &str) -> HopKind {
    match s {
        "socks5" => HopKind::Socks5,
        "http-connect" => HopKind::HttpConnect,
        _ => HopKind::Ssh,
    }
}

/// Hops list page.
pub struct HopsPage {
    /// Index of selected hop in the list view.
    selected: usize,
    /// `Some` when the editor is open.
    editor: Option<HopEditor>,
    /// Cached list state for rendering.
    list_state: ListState,
}

struct HopEditor {
    /// Index of the hop being edited within `Profile.hops`.
    #[allow(dead_code)]
    hop_index: usize,
    /// Field list for the editor.
    fields: FieldList,
}

impl HopsPage {
    /// Build the page.
    pub fn new() -> Self {
        Self {
            selected: 0,
            editor: None,
            list_state: ListState::default(),
        }
    }

    fn open_editor(&mut self, profile: &Profile, idx: usize) {
        if idx >= profile.hops.len() {
            return;
        }
        self.editor = Some(HopEditor {
            hop_index: idx,
            fields: FieldList::new(hop_fields(idx)),
        });
    }
}

impl Default for HopsPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the editor field list for hop `idx`.
fn hop_fields(idx: usize) -> Vec<FieldDef> {
    let i = idx;
    vec![
        // name — Text, required (uniqueness deferred to validate).
        FieldDef {
            label: "name",
            help: "Hop identifier (unique within the chain)",
            get: Box::new(move |p: &Profile| {
                FieldValue::Text(p.hops.get(i).map(|h| h.name.clone()).unwrap_or_default())
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Text(s) = v {
                    if let Some(h) = p.hops.get_mut(i) {
                        h.name = s;
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
        // protocol — Choice ssh2/ssh3 (required String on the schema).
        FieldDef {
            label: "protocol",
            help: "SSH protocol used to reach this hop",
            get: Box::new(move |p: &Profile| FieldValue::Choice {
                value: p
                    .hops
                    .get(i)
                    .map(|h| h.protocol.clone())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "ssh2".to_owned()),
                options: HOP_PROTOCOLS,
                display: None,
                option_help: Some(HOP_PROTOCOLS_HELP),
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    if let Some(h) = p.hops.get_mut(i) {
                        h.protocol = value;
                    }
                }
            }),
            validate: None,
            bool_option_help: None,
        },
        // host — Text, required.
        FieldDef {
            label: "host",
            help: "Hop hostname or IP",
            get: Box::new(move |p: &Profile| {
                FieldValue::Text(p.hops.get(i).map(|h| h.host.clone()).unwrap_or_default())
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Text(s) = v {
                    if let Some(h) = p.hops.get_mut(i) {
                        h.host = s;
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
        // port — Numeric(u16), required (1-65535).
        FieldDef {
            label: "port",
            help: "Hop port (1-65535)",
            get: Box::new(move |p: &Profile| {
                FieldValue::Numeric(
                    p.hops
                        .get(i)
                        .map(|h| h.port.to_string())
                        .unwrap_or_default(),
                )
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Numeric(s) = v {
                    if let Ok(n) = s.parse::<u16>() {
                        if n >= 1 {
                            if let Some(h) = p.hops.get_mut(i) {
                                h.port = n;
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
        // user — Option<String>.
        opt_text(
            "user",
            "Remote user on this hop (blank = inherit profile user)",
            move |p| p.hops.get(i).and_then(|h| h.user.clone()),
            move |p, v| {
                if let Some(h) = p.hops.get_mut(i) {
                    h.user = v;
                }
            },
        ),
        // kind — Choice ssh/socks5/http-connect (HopKind).
        FieldDef {
            label: "kind",
            help: "Hop transport: ssh (proxy-jump), socks5, or http-connect",
            get: Box::new(move |p: &Profile| FieldValue::Choice {
                value: p
                    .hops
                    .get(i)
                    .map_or_else(|| "ssh".to_owned(), |h| hopkind_str(h.kind).to_owned()),
                options: HOP_KINDS,
                display: None,
                option_help: Some(HOP_KINDS_HELP),
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    if let Some(h) = p.hops.get_mut(i) {
                        h.kind = str_hopkind(&value);
                    }
                }
            }),
            validate: None,
            bool_option_help: None,
        },
        // target_resolve — Option<String> choice.
        opt_choice_with_help(
            "target_resolve",
            "Where to resolve the next hop's name",
            TARGET_RESOLVE,
            TARGET_RESOLVE_HELP,
            move |p| p.hops.get(i).and_then(|h| h.target_resolve.clone()),
            move |p, v| {
                if let Some(h) = p.hops.get_mut(i) {
                    h.target_resolve = v;
                }
            },
        ),
        // proxy_username — Option<RedactedString>, exposed as plain text (a
        // username, not a password). Only meaningful for socks5/http-connect.
        opt_text(
            "proxy_username",
            "Proxy username for socks5 / http-connect hops (blank = none)",
            move |p| {
                p.hops
                    .get(i)
                    .and_then(|h| h.proxy_username.as_ref().map(|r| r.expose().to_owned()))
            },
            move |p, v| {
                if let Some(h) = p.hops.get_mut(i) {
                    h.proxy_username = v.map(spt_core::RedactedString::from);
                }
            },
        ),
    ]
}

impl Page for HopsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        // Left: list of hops.
        let items: Vec<ListItem<'_>> = model
            .profile()
            .hops
            .iter()
            .map(|h| {
                ListItem::new(format!(
                    "{:>10} {}:{}  {}",
                    h.name,
                    h.host,
                    h.port,
                    hopkind_str(h.kind)
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
            .title("Hops (a=add, d=del, Enter=edit)");
        let list = List::new(items)
            .block(block)
            .highlight_style(style)
            .highlight_symbol("▶ ");
        ratatui::widgets::StatefulWidget::render(list, chunks[0], buf, &mut self.list_state);

        // Right: editor (if open) or summary.
        if let Some(ed) = self.editor.as_mut() {
            ed.fields.render(chunks[1], buf, model.profile());
        } else if let Some(h) = model.profile().hops.get(self.selected) {
            let lines = vec![
                Line::from(format!("name:     {}", h.name)),
                Line::from(format!("protocol: {}", h.protocol)),
                Line::from(format!("host:     {}", h.host)),
                Line::from(format!("port:     {}", h.port)),
                Line::from(format!("user:     {}", h.user.clone().unwrap_or_default())),
                Line::from(format!("kind:     {}", hopkind_str(h.kind))),
                Line::from(format!(
                    "resolve:  {}",
                    h.target_resolve.clone().unwrap_or_default()
                )),
            ];
            let block = Block::default().borders(Borders::ALL).title("Detail");
            Paragraph::new(lines).block(block).render(chunks[1], buf);
        } else {
            let block = Block::default().borders(Borders::ALL).title("Detail");
            Paragraph::new("(no hops — press `a` to add)")
                .block(block)
                .render(chunks[1], buf);
        }
    }

    fn focused_help(&self) -> Option<&str> {
        if let Some(ed) = self.editor.as_ref() {
            ed.fields.focused_help()
        } else {
            Some("Hops list: a=add, d=del, Enter=edit")
        }
    }

    fn focused_help_dynamic(&self, model: &Model) -> Option<&str> {
        if let Some(ed) = self.editor.as_ref() {
            ed.fields.focused_help_dynamic(model.profile())
        } else {
            Some("Hops list: a=add, d=del, Enter=edit")
        }
    }

    fn focused_position(&self) -> Option<(usize, usize)> {
        self.editor
            .as_ref()
            .and_then(|ed| ed.fields.focus_position())
    }

    fn is_editing(&self) -> bool {
        self.editor.as_ref().is_some_and(|ed| ed.fields.editing)
    }

    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        // Two-pane navigation contract (mirrors EndpointsPage).
        if let Some(ed) = self.editor.as_mut() {
            if ed.fields.editing {
                let changed = ed.fields.on_edit_key(key, model.profile_mut_silent());
                if changed {
                    model.mark_dirty();
                }
                return changed;
            }
            match key.code {
                KeyCode::Esc | KeyCode::Left => {
                    self.editor = None;
                    return false;
                }
                _ => {
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
                let n = model.profile().hops.len();
                if self.selected + 1 < n {
                    self.selected += 1;
                }
                false
            }
            KeyCode::Right => {
                if self.selected < model.profile().hops.len() {
                    let p = model.profile().clone();
                    self.open_editor(&p, self.selected);
                }
                false
            }
            KeyCode::Char('a') => {
                let h = Hop {
                    name: format!("hop-{}", model.profile().hops.len() + 1),
                    protocol: "ssh2".into(),
                    host: "example.com".into(),
                    port: 22,
                    ..Default::default()
                };
                model.profile_mut().hops.push(h);
                let idx = model.profile().hops.len() - 1;
                self.selected = idx;
                self.open_editor(&model.profile().clone(), idx);
                true
            }
            KeyCode::Char('d') => {
                let n = model.profile().hops.len();
                if self.selected < n {
                    model.profile_mut().hops.remove(self.selected);
                    if self.selected >= model.profile().hops.len() && self.selected > 0 {
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
    fn add_pushes_new_hop_and_opens_editor() {
        let mut p = HopsPage::new();
        let mut m = model();
        assert_eq!(m.profile().hops.len(), 0);
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(m.profile().hops.len(), 1);
        let h = &m.profile().hops[0];
        assert_eq!(h.name, "hop-1");
        assert_eq!(h.host, "example.com");
        assert_eq!(h.port, 22);
        assert_eq!(h.kind, HopKind::Ssh);
        assert!(p.editor.is_some());
    }

    #[test]
    fn delete_removes_focused_hop() {
        let mut p = HopsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
        p.on_key(k(KeyCode::Char('d')), &mut m);
        assert_eq!(m.profile().hops.len(), 0);
    }

    #[test]
    fn editor_field_count_and_labels() {
        let fields = hop_fields(0);
        let labels: Vec<&str> = fields.iter().map(|f| f.label).collect();
        assert_eq!(
            labels,
            [
                "name",
                "protocol",
                "host",
                "port",
                "user",
                "kind",
                "target_resolve",
                "proxy_username",
            ]
        );
    }

    #[test]
    fn editor_edits_host_round_trip() {
        let mut p = HopsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open editor
                                                 // Move to host (index 2).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..20 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "jump.example.org".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().hops[0].host, "jump.example.org");
    }

    #[test]
    fn kind_choice_commits_socks5() {
        let mut p = HopsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open editor
                                                 // Move to kind (index 5).
        for _ in 0..5 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (ssh)
        p.on_key(k(KeyCode::Right), &mut m); // → socks5
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().hops[0].kind, HopKind::Socks5);
    }

    #[test]
    fn proxy_username_round_trip() {
        let mut p = HopsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        for _ in 0..7 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // edit proxy_username
        for c in "alice".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile().hops[0]
                .proxy_username
                .as_ref()
                .map(|r| r.expose().to_owned()),
            Some("alice".to_owned())
        );
    }

    #[test]
    fn renders_without_panic() {
        let mut p = HopsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m);
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(s.contains("hop-1"));
    }
}
