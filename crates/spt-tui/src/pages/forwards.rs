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
    opt_bool_with_help, opt_choice_with_help, opt_list, opt_multi_with_help, opt_text, opt_u32,
    FieldDef, FieldList, FieldValue,
};
use crate::pages::Page;

const KIND: &[&str] = &["local", "remote", "dynamic"];
const KIND_HELP: &[&str] = &[
    "local: listen here, forward to remote (SSH `-L`).",
    "remote: listen on the SSH peer, forward back to here (SSH `-R`).",
    "dynamic: local SOCKS / HTTP CONNECT proxy (SSH `-D`).",
];
const TRANSPORT: &[&str] = &["tcp", "udp"];
const TRANSPORT_HELP: &[&str] = &[
    "TCP forwarding. Available on every profile (SSH2 + SSH3).",
    "UDP forwarding via QUIC datagrams. SSH3 profiles only.",
];
const BIND_MODE: &[&str] = &[
    "loopback",
    "specific_ip",
    "specific_interface",
    "all_interfaces",
    "auto_interface",
];
const BIND_MODE_HELP: &[&str] = &[
    "Bind 127.0.0.1 / ::1 only. Safe default — local users only.",
    "Bind a specific IP address. Set `bind` to e.g. `192.0.2.5:5432`.",
    "Bind a specific named interface. Set `bind_interface`.",
    "Wildcard bind (0.0.0.0 / ::). Requires `expose = true`.",
    "Pick the first matching interface from `bind_interface_preference`.",
];
const LINK_KIND: &[&str] = &["tcp", "local_uds", "remote_uds"];
const LINK_KIND_HELP: &[&str] = &[
    "tcp: standard RFC 4254 direct-tcpip / tcpip-forward (default).",
    "local_uds: direct-streamlocal to a server-side UNIX socket (needs remote_socket_path).",
    "remote_uds: streamlocal-forward; server listens on a UNIX socket (Unix client only).",
];
const PROXY_PROTOCOLS: &[&str] = &["socks4", "socks4a", "socks5", "http_connect"];
const PROXY_PROTOCOLS_HELP: &[&str] = &[
    "socks4: legacy SOCKS — IPv4 destination, no auth, no remote DNS.",
    "socks4a: SOCKS4 + remote DNS resolution at the proxy.",
    "socks5: RFC 1928 — IPv4/IPv6/hostname destinations, optional auth.",
    "http_connect: HTTP CONNECT proxy. Standard for tunnelling HTTPS via web proxies.",
];

/// Forwards list page.
pub struct ForwardsPage {
    /// Index of selected forward in the list view.
    selected: usize,
    /// `Some` when editor is open.
    editor: Option<ForwardEditor>,
    /// Cached list state for rendering.
    list_state: ListState,
    /// Cached `profile.forwards.len()` updated every render. Used by
    /// `focused_position` (which takes `&self` and has no profile
    /// reference) to surface the `[N/total]` counter in the footer.
    forwards_count: usize,
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
            forwards_count: 0,
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
            bool_option_help: None,
        },
        FieldDef {
            label: "type",
            help: "`local` (listen here), `remote` (listen on peer), or `dynamic` (SOCKS).",
            get: Box::new(move |p: &Profile| FieldValue::Choice {
                value: p
                    .forwards
                    .get(i)
                    .map(|f| f.kind.clone())
                    .unwrap_or_default(),
                options: KIND,
                display: None,
                option_help: Some(KIND_HELP),
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    if let Some(f) = p.forwards.get_mut(i) {
                        f.kind = value;
                    }
                }
            }),
            validate: None,
            bool_option_help: None,
        },
        FieldDef {
            label: "transport",
            help: "`tcp` always; `udp` only with SSH3.",
            get: Box::new(move |p: &Profile| FieldValue::Choice {
                value: p
                    .forwards
                    .get(i)
                    .map(|f| f.transport.clone())
                    .unwrap_or_default(),
                options: TRANSPORT,
                display: None,
                option_help: Some(TRANSPORT_HELP),
            }),
            set: Box::new(move |p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    if let Some(f) = p.forwards.get_mut(i) {
                        f.transport = value;
                    }
                }
            }),
            validate: None,
            bool_option_help: None,
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
        opt_choice_with_help(
            "bind_mode",
            "Bind mode (loopback, specific_ip, ...)",
            BIND_MODE,
            BIND_MODE_HELP,
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
        opt_bool_with_help(
            "expose",
            "Required acknowledgement for non-loopback binds (§9.14).",
            "Loopback-only bind. Safe — no external acknowledgement required.",
            "Acknowledge: this forward is intentionally reachable beyond loopback.",
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
        opt_multi_with_help(
            "proxy_protocols",
            "Dynamic proxy protocols (empty = all)",
            PROXY_PROTOCOLS,
            PROXY_PROTOCOLS_HELP,
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
        // required — whether this forward is mandatory for the profile to be
        // considered healthy vs. degraded-allowed. §9.14.
        opt_bool_with_help(
            "required",
            "Whether this forward must succeed for the profile to be healthy.",
            "Optional: the profile stays healthy even if this forward fails (degraded).",
            "Required: a failure of this forward degrades/fails the whole profile.",
            move |p| p.forwards.get(i).and_then(|f| f.required),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.required = v;
                }
            },
        ),
        // dns_names — DNS names to register for this forward. §9.14.
        opt_list(
            "dns_names",
            "DNS names to register for this forward (comma-separated)",
            move |p| {
                p.forwards
                    .get(i)
                    .and_then(|f| f.dns_names.clone())
                    .unwrap_or_default()
            },
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.dns_names = if v.is_empty() { None } else { Some(v) };
                }
            },
        ),
        // allow_targets — SOCKS/dynamic destination allow-list (SSRF/abuse
        // mitigation). Host globs or CIDR/IP rules. §9.14.
        opt_list(
            "allow_targets",
            "Dynamic-forward destination allow-list (host glob or CIDR; empty = allow all)",
            move |p| {
                p.forwards
                    .get(i)
                    .and_then(|f| f.allow_targets.clone())
                    .unwrap_or_default()
            },
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.allow_targets = if v.is_empty() { None } else { Some(v) };
                }
            },
        ),
        // deny_targets — SOCKS/dynamic destination deny-list (deny wins over
        // allow). §9.14.
        opt_list(
            "deny_targets",
            "Dynamic-forward destination deny-list (deny wins over allow; empty = none)",
            move |p| {
                p.forwards
                    .get(i)
                    .and_then(|f| f.deny_targets.clone())
                    .unwrap_or_default()
            },
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.deny_targets = if v.is_empty() { None } else { Some(v) };
                }
            },
        ),
        // max_bytes_per_second_in — inbound byte-rate cap (e.g. `1MiB`). §9.14.
        opt_text(
            "max_bytes_per_second_in",
            "Inbound byte-rate cap (e.g. `1MiB`, `500KiB`)",
            move |p| {
                p.forwards
                    .get(i)
                    .and_then(|f| f.max_bytes_per_second_in.clone())
            },
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.max_bytes_per_second_in = v;
                }
            },
        ),
        // max_bytes_per_second_out — outbound byte-rate cap. §9.14.
        opt_text(
            "max_bytes_per_second_out",
            "Outbound byte-rate cap (e.g. `1MiB`, `500KiB`)",
            move |p| {
                p.forwards
                    .get(i)
                    .and_then(|f| f.max_bytes_per_second_out.clone())
            },
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.max_bytes_per_second_out = v;
                }
            },
        ),
        // max_new_connections_per_second — accept-rate cap. §9.14.
        opt_u32(
            "max_new_connections_per_second",
            "Accept-rate cap (new connections per second)",
            move |p| {
                p.forwards
                    .get(i)
                    .and_then(|f| f.max_new_connections_per_second)
            },
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.max_new_connections_per_second = v;
                }
            },
        ),
        // link_kind — wire flavour: tcp (default), local_uds, remote_uds. t6-e2.
        opt_choice_with_help(
            "link_kind",
            "Forward link kind (tcp, local_uds, remote_uds)",
            LINK_KIND,
            LINK_KIND_HELP,
            move |p| p.forwards.get(i).and_then(|f| f.link_kind.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.link_kind = v;
                }
            },
        ),
        // remote_socket_path — server-side UDS path for local_uds/remote_uds.
        opt_text(
            "remote_socket_path",
            "Server-side UNIX socket path (local_uds / remote_uds)",
            move |p| p.forwards.get(i).and_then(|f| f.remote_socket_path.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.remote_socket_path = v;
                }
            },
        ),
        // local_socket_path — client-side UDS path (Unix-only). t6-e2.
        opt_text(
            "local_socket_path",
            "Client-side UNIX socket path (Unix-only; local_uds / remote_uds)",
            move |p| p.forwards.get(i).and_then(|f| f.local_socket_path.clone()),
            move |p, v| {
                if let Some(f) = p.forwards.get_mut(i) {
                    f.local_socket_path = v;
                }
            },
        ),
    ]
}

impl Page for ForwardsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        // Cache the count for `focused_position` (no `model` available
        // in the trait signature).
        self.forwards_count = model.profile().forwards.len();
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

    fn focused_help(&self) -> Option<&str> {
        // When the editor is open, surface the focused field's static
        // help; in list mode show the keymap so operators don't see a
        // blank footer.
        if let Some(ed) = self.editor.as_ref() {
            ed.fields.focused_help()
        } else {
            Some("Forwards list: a=add, d=del, Enter=edit")
        }
    }

    fn focused_help_dynamic(&self, model: &Model) -> Option<&str> {
        if let Some(ed) = self.editor.as_ref() {
            ed.fields.focused_help_dynamic(model.profile())
        } else {
            Some("Forwards list: a=add, d=del, Enter=edit")
        }
    }

    fn focused_position(&self) -> Option<(usize, usize)> {
        // Editor mode → the editor field-list's position; list mode →
        // forward index within the cached `forwards_count` (refreshed
        // on every render).
        if let Some(ed) = self.editor.as_ref() {
            ed.fields.focus_position()
        } else if self.forwards_count == 0 {
            None
        } else {
            Some((
                self.selected.min(self.forwards_count - 1) + 1,
                self.forwards_count,
            ))
        }
    }

    fn is_editing(&self) -> bool {
        self.editor.as_ref().is_some_and(|ed| ed.fields.editing)
    }

    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        // Two-pane navigation contract (mirrors EndpointsPage):
        //
        // * List mode (no editor open):
        //   - ↑/k, ↓/j   move list cursor
        //   - Enter, →   open editor on the focused entry (pane nav right)
        //   - a / d      add / delete entries
        // * Editor mode, NOT actively editing a field:
        //   - Esc, ←     close editor and return to list (pane nav left)
        //   - ↑/k, ↓/j   move field focus within the editor
        // * Editor mode, actively editing a field (FieldList::editing):
        //   - every key flows through so spinner ←/→ keep rotating
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
                let n = model.profile().forwards.len();
                if self.selected + 1 < n {
                    self.selected += 1;
                }
                false
            }
            KeyCode::Right => {
                // Pane nav: → from the list opens the editor on the
                // focused entry. Same semantic as Enter.
                if self.selected < model.profile().forwards.len() {
                    let p = model.profile().clone();
                    self.open_editor(&p, self.selected);
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
    fn left_arrow_closes_editor_when_not_field_editing() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
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
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin editing field 0
        assert!(p.editor.as_ref().unwrap().fields.editing);
        p.on_key(k(KeyCode::Left), &mut m);
        assert!(
            p.editor.is_some(),
            "Left while field-editing must NOT close the editor"
        );
        assert!(p.editor.as_ref().unwrap().fields.editing);
    }

    #[test]
    fn right_arrow_opens_editor_from_list() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(p.editor.is_none());
        p.on_key(k(KeyCode::Right), &mut m);
        assert!(
            p.editor.is_some(),
            "Right from the list must open the editor"
        );
    }

    #[test]
    fn right_arrow_on_empty_list_does_not_panic() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        assert_eq!(m.profile().forwards.len(), 0);
        p.on_key(k(KeyCode::Right), &mut m);
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
        // 22 fields: name, type, transport, bind, target, bind_mode,
        //   bind_interface, expose, idle_timeout, max_connections,
        //   proxy_protocols, max_packets_per_second, required, dns_names,
        //   allow_targets, deny_targets, max_bytes_per_second_in,
        //   max_bytes_per_second_out, max_new_connections_per_second,
        //   link_kind, remote_socket_path, local_socket_path.
        assert_eq!(fields.len(), 22);
        let labels: Vec<&str> = fields.iter().map(|f| f.label).collect();
        assert!(labels.contains(&"allow_targets"));
        assert!(labels.contains(&"deny_targets"));
        assert!(labels.contains(&"required"));
        assert!(labels.contains(&"link_kind"));
    }

    #[test]
    fn allow_targets_round_trip() {
        let mut p = ForwardsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open editor
                                                 // allow_targets is index 14.
        for _ in 0..14 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        assert_eq!(
            p.editor.as_ref().unwrap().fields.fields[14].def.label,
            "allow_targets"
        );
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (List)
        for c in "10.0.0.0/8, *.internal".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.profile().forwards[0].allow_targets,
            Some(vec!["10.0.0.0/8".to_string(), "*.internal".to_string()])
        );
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
