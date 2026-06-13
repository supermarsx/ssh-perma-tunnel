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
use crate::pages::auth::auth_fields;
use crate::pages::field::{opt_bool_with_help, opt_text, opt_u32, FieldDef, FieldList, FieldValue};
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
        let fields = endpoint_fields(idx, profile);
        self.editor = Some(EndpointEditor {
            endpoint_index: idx,
            fields: FieldList::new(fields),
        });
    }
}

/// `true` when endpoint `idx` carries a per-endpoint auth override.
fn endpoint_override_on(profile: &Profile, idx: usize) -> bool {
    profile.endpoints.get(idx).is_some_and(|e| e.auth.is_some())
}

/// Per-endpoint auth status marker for the list row / detail pane:
/// `auth=global` when the endpoint inherits the profile-level
/// `[profiles.auth]`, or `auth=local(<method>)` when it overrides with
/// its own auth block (method shown, defaulting to `?` when blank).
fn auth_marker(e: &Endpoint) -> String {
    match e.auth.as_ref() {
        None => "auth=global".to_owned(),
        Some(a) => {
            let m = if a.method.is_empty() {
                "?"
            } else {
                a.method.as_str()
            };
            format!("auth=local({m})")
        }
    }
}

impl Default for EndpointsPage {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the editor field list for endpoint `idx`.
///
/// The base layout (name/host/port/priority/weight) is unconditional and
/// byte-identical to the pre-feature page. After it come the per-endpoint
/// `user` override and the `auth.override` toggle. The shared
/// [`auth_fields`] credential rows are appended **only when the override
/// is currently ON** (`endpoints[idx].auth.is_some()`), mirroring the
/// way the Events page surfaces only the active sink kind's fields. The
/// editor rebuilds this list when the toggle flips (see
/// [`EndpointsPage::on_key`]).
fn endpoint_fields(idx: usize, profile: &Profile) -> Vec<FieldDef> {
    let i = idx;
    let mut fields = vec![
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
        // user — per-endpoint login user. Overrides the profile-level
        // (global) `user`; falls back to it when unset.
        opt_text(
            "user",
            "Per-endpoint login user (overrides the global `user`; blank = inherit)",
            move |p| p.endpoints.get(i).and_then(|e| e.user.clone()),
            move |p, v| {
                if let Some(e) = p.endpoints.get_mut(i) {
                    e.user = v;
                }
            },
        ),
        // auth.override — toggle: ON installs a per-endpoint Auth block
        // (Some(Auth::default())) that fully replaces the global
        // `[profiles.auth]` for this endpoint; OFF clears it back to None
        // so the endpoint inherits the global default again.
        opt_bool_with_help(
            "auth.override",
            "Override the global auth for this endpoint",
            "Inherit the global `[profiles.auth]` (auth=global).",
            "Use a per-endpoint auth block (auth=local) — fully replaces the global one.",
            move |p| Some(p.endpoints.get(i).is_some_and(|e| e.auth.is_some())),
            move |p, v| {
                if let Some(e) = p.endpoints.get_mut(i) {
                    match v {
                        Some(true) => {
                            // Only install a fresh block if not already set,
                            // so flipping ON never clobbers existing creds.
                            if e.auth.is_none() {
                                e.auth = Some(spt_config::schema::Auth::default());
                            }
                        }
                        _ => e.auth = None,
                    }
                }
            },
        ),
    ];

    // Gate the shared credential rows behind the override being ON, so a
    // no-override endpoint's editor stays exactly name/host/port/priority/
    // weight/user/auth.override and never materialises an empty `[auth]`.
    if endpoint_override_on(profile, idx) {
        fields.extend(auth_fields(
            "auth",
            move |p: &Profile| p.endpoints.get(i).and_then(|e| e.auth.as_ref()),
            move |p: &mut Profile| {
                // The editor only reaches these setters while the override
                // is ON, so the endpoint exists and its `auth` is `Some`;
                // fall back to a leaked throwaway only in the impossible
                // out-of-range case to satisfy the `&mut Option<Auth>` shape.
                &mut p.endpoints[i].auth
            },
        ));
    }

    fields
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
                let auth = auth_marker(e);
                ListItem::new(format!(
                    "{:>12} {}:{}  p={} w={}  {}",
                    e.name, e.host, e.port, priority, weight, auth
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
                Line::from(format!("user:     {}", e.user.clone().unwrap_or_default())),
                Line::from(format!("auth:     {}", auth_marker(e))),
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
        // Two-pane navigation contract:
        //
        // * List mode (no editor open):
        //   - ↑/k, ↓/j   move list cursor
        //   - Enter, →   open editor on the focused entry (pane nav right)
        //   - a / d      add / delete entries
        // * Editor mode (editor open), NOT actively editing a field:
        //   - Esc, ←     close editor and return to list (pane nav left)
        //   - ↑/k, ↓/j   move field focus within the editor
        // * Editor mode, actively editing a field (FieldList::editing):
        //   - every key flows through to FieldList::on_edit_key so
        //     spinner-style ←/→ keep rotating Choice options
        if let Some(ed) = self.editor.as_mut() {
            if ed.fields.editing {
                // Actively typing or rotating a field — every key flows
                // through. ←/→ are still consumed here for Choice rotate.
                //
                // Detect whether the focused field is the `auth.override`
                // toggle *before* committing, so that if the commit flips
                // it we can rebuild the editor rows to add/remove the
                // gated auth credential fields (mirrors the Events page's
                // rebuild-on-kind-change behaviour).
                let override_focused = ed
                    .fields
                    .fields
                    .get(ed.fields.focus)
                    .is_some_and(|f| f.def.label == "auth.override");
                let was_on = endpoint_override_on(model.profile(), ed.endpoint_index);
                let changed = ed.fields.on_edit_key(key, model.profile_mut_silent());
                if changed {
                    model.mark_dirty();
                    if override_focused {
                        let now_on = endpoint_override_on(model.profile(), ed.endpoint_index);
                        if now_on != was_on {
                            let idx = ed.endpoint_index;
                            let p = model.profile().clone();
                            let fields = endpoint_fields(idx, &p);
                            let mut list = FieldList::new(fields);
                            // Keep focus on the toggle row across the rebuild.
                            list.focus = ed.fields.focus.min(list.fields.len().saturating_sub(1));
                            ed.fields = list;
                        }
                    }
                }
                return changed;
            }
            // Field-nav mode within the editor: ← closes the editor as
            // the pane-nav counterpart to Right-opens-from-the-list.
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
                let n = model.profile().endpoints.len();
                if self.selected + 1 < n {
                    self.selected += 1;
                }
                false
            }
            KeyCode::Right => {
                // Pane nav: → from the list opens the editor on the
                // focused entry. Same semantic as Enter.
                if self.selected < model.profile().endpoints.len() {
                    let p = model.profile().clone();
                    self.open_editor(&p, self.selected);
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
                    user: None,
                    auth: None,
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
    fn left_arrow_closes_editor_when_not_field_editing() {
        // Pane-nav contract: ← closes the editor (returns to list).
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open editor
                                                 // The editor auto-opens but is NOT field-editing yet — fields.editing == false.
        assert!(p.editor.is_some());
        assert!(!p.editor.as_ref().unwrap().fields.editing);
        p.on_key(k(KeyCode::Left), &mut m);
        assert!(
            p.editor.is_none(),
            "Left while in editor (not field-editing) must close the editor"
        );
    }

    #[test]
    fn left_arrow_inside_field_edit_does_not_close_editor() {
        // While actively editing a field, Left rotates the Choice spinner
        // / moves text cursor — it MUST NOT close the editor.
        let mut p = EndpointsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add endpoint, editor open
        p.on_key(k(KeyCode::Enter), &mut m); // begin editing field 0 (name = Text)
        assert!(p.editor.as_ref().unwrap().fields.editing);
        p.on_key(k(KeyCode::Left), &mut m);
        assert!(
            p.editor.is_some(),
            "Left while field-editing must NOT close the editor (it moves text cursor)"
        );
        assert!(p.editor.as_ref().unwrap().fields.editing);
    }

    #[test]
    fn right_arrow_opens_editor_from_list() {
        // Pane-nav: → from the list opens the editor on the focused entry.
        let mut p = EndpointsPage::new();
        let mut m = model();
        // Add an endpoint, then Esc out so we're in list mode with one entry.
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
        p.on_key(k(KeyCode::Right), &mut m);
        assert!(
            p.editor.is_some(),
            "Right from the list must open the editor on the focused entry"
        );
    }

    #[test]
    fn right_arrow_on_empty_list_does_not_panic() {
        // Edge case: no endpoints, Right pressed → should be a no-op.
        let mut p = EndpointsPage::new();
        let mut m = model();
        assert_eq!(m.profile().endpoints.len(), 0);
        p.on_key(k(KeyCode::Right), &mut m);
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
        let p = Model::from_str(
            r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[profiles.endpoints]]
name = "e1"
host = "h"
port = 22
"#,
        );
        // No override → base layout only: name, host, port, priority,
        // weight, user, auth.override (7 fields). The gated auth.* rows
        // are absent until the override is toggled ON.
        let fields = endpoint_fields(0, p.profile());
        assert_eq!(fields.len(), 7);
        let labels: Vec<&str> = fields.iter().map(|f| f.label).collect();
        assert_eq!(
            labels,
            [
                "name",
                "host",
                "port",
                "priority",
                "weight",
                "user",
                "auth.override"
            ]
        );
    }

    #[test]
    fn editor_field_count_with_override() {
        let p = Model::from_str(
            r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[profiles.endpoints]]
name = "e1"
host = "h"
port = 22

[profiles.endpoints.auth]
method = "password"
"#,
        );
        // Override ON → base 7 + 11 shared auth rows (method,
        // identity_file, certificate_file, passphrase, password, token,
        // agent, identity_hint, keyboard_interactive, oidc_issuer,
        // oidc_client_id) = 18.
        let fields = endpoint_fields(0, p.profile());
        assert_eq!(fields.len(), 18);
        let labels: Vec<&str> = fields.iter().map(|f| f.label).collect();
        assert!(labels.contains(&"auth.method"));
        assert!(labels.contains(&"auth.password"));
        assert!(labels.contains(&"auth.token"));
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
