//! "Basics" page — id, description, protocol.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{
    opt_choice_with_display_and_help, opt_choice_with_help, opt_text, FieldDef, FieldList,
    FieldValue,
};
use crate::pages::Page;

const PROTOCOLS: &[&str] = &["ssh2", "ssh3"];
/// Display labels parallel to [`PROTOCOLS`]. The on-disk value remains
/// `"ssh3"` (canonical) but the UI clarifies that our implementation
/// targets the [francoismichel/ssh3](https://github.com/francoismichel/ssh3)
/// reference — a research/proposal implementation over QUIC + HTTP/3,
/// not the future IETF SSH3 standard.
const PROTOCOL_DISPLAY: &[&str] = &["ssh2", "ssh3 (francoismichel)"];
const PROTOCOL_HELP: &[&str] = &[
    "Classic SSH over TCP via libssh2/russh. Stable; full forward + agent support.",
    "francoismichel/ssh3 research impl over QUIC/HTTP-3. Not the future IETF SSH3 standard.",
];
const STARTUP: &[&str] = &["eager", "lazy"];
const STARTUP_HELP: &[&str] = &[
    "Connect on boot / service start. Use for always-on tunnels.",
    "Connect on first forward usage. Saves resources for rarely-used profiles.",
];
const FAILURE: &[&str] = &["retry", "fail_profile", "fail_process"];
const FAILURE_HELP: &[&str] = &[
    "Keep reconnecting forever within the backoff. Default for daemons.",
    "Stop this profile but keep the daemon alive — other profiles keep running.",
    "Exit the whole daemon process. Loudest signal — for one-shot or supervised scripts.",
];

/// Top-level identity + protocol.
pub struct BasicsPage {
    list: FieldList,
}

impl BasicsPage {
    /// Construct the page with field definitions wired to [`spt_config::schema::Profile`].
    pub fn new() -> Self {
        let fields = vec![
            // The name field is special: it's not Option<String>.
            crate::pages::field::FieldDef {
                label: "id",
                help: "Profile identifier (must be unique)",
                get: Box::new(|p| crate::pages::FieldValue::Text(p.name.clone())),
                set: Box::new(|p, v| {
                    if let crate::pages::FieldValue::Text(s) = v {
                        if !s.is_empty() {
                            p.name = s;
                        }
                    }
                }),
                validate: Some(Box::new(|v| {
                    if let crate::pages::FieldValue::Text(s) = v {
                        if s.is_empty() {
                            return Some("profile id cannot be empty".into());
                        }
                        if !s
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                        {
                            return Some("profile id may only contain [a-zA-Z0-9_-]".into());
                        }
                    }
                    None
                })),
                bool_option_help: None,
            },
            opt_text(
                "description",
                "Free-form profile description",
                |p| p.description.clone(),
                |p, v| p.description = v,
            ),
            // Protocol is required, not Option<String>; serialize as a
            // canonical String. The `ssh3` option targets the
            // francoismichel/ssh3 research implementation (QUIC +
            // HTTP/3), not the future IETF SSH3 standard. The on-disk
            // value stays `"ssh3"` for config-file compatibility; the
            // spinner shows the friendlier `"ssh3 (francoismichel)"`
            // label. `opt_choice_with_display` does the display-vs-
            // canonical mapping; we wrap `String` in `Some(...)` to
            // satisfy its `Option<String>` get/set signature.
            opt_choice_with_display_and_help(
                "protocol",
                "Transport — ssh2 (libssh2) or ssh3 (francoismichel/ssh3 over QUIC)",
                PROTOCOLS,
                PROTOCOL_DISPLAY,
                PROTOCOL_HELP,
                |p| Some(p.protocol.clone()),
                |p, v| {
                    if let Some(s) = v {
                        if !s.is_empty() {
                            p.protocol = s;
                        }
                    }
                },
            ),
            // Top-level connection target. `host`/`port` are the single-host
            // SSH2 fields; `endpoint` is the SSH3 URL. These are the most
            // fundamental fields of a profile and were previously uneditable
            // anywhere in the wizard (the Endpoints page edits the
            // `endpoints[]` failover array, not these top-level scalars).
            opt_text(
                "host",
                "SSH2 target host or IP (single-host profiles). For failover use the Endpoints page.",
                |p| p.host.clone(),
                |p, v| p.host = v,
            ),
            // port — Option<u16>. Empty clears to None (runtime default 22).
            FieldDef {
                label: "port",
                help: "SSH2 target port (1-65535; blank = default 22)",
                get: Box::new(|p| {
                    FieldValue::Numeric(p.port.map(|n| n.to_string()).unwrap_or_default())
                }),
                set: Box::new(|p, v| {
                    if let FieldValue::Numeric(s) = v {
                        if s.is_empty() {
                            p.port = None;
                        } else if let Ok(n) = s.parse::<u16>() {
                            if n >= 1 {
                                p.port = Some(n);
                            }
                        }
                    }
                }),
                validate: Some(Box::new(|v| {
                    if let FieldValue::Numeric(s) = v {
                        if s.is_empty() {
                            return None;
                        }
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
            opt_text(
                "endpoint",
                "SSH3 endpoint URL (e.g. `https://host:443/path`). Used when protocol = ssh3.",
                |p| p.endpoint.clone(),
                |p, v| p.endpoint = v,
            ),
            opt_choice_with_help(
                "startup",
                "When to start: eager (boot) or lazy (on demand)",
                STARTUP,
                STARTUP_HELP,
                |p| p.startup.clone(),
                |p, v| p.startup = v,
            ),
            opt_choice_with_help(
                "failure_policy",
                "Action when profile fails repeatedly",
                FAILURE,
                FAILURE_HELP,
                |p| p.failure_policy.clone(),
                |p, v| p.failure_policy = v,
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for BasicsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        self.list.render(area, buf, model.profile());
    }

    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if self.list.editing {
            let changed = self.list.on_edit_key(key, model.profile_mut_silent());
            if changed {
                model.mark_dirty();
            }
            changed
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }

    fn focused_help(&self) -> Option<&str> {
        self.list.focused_help()
    }
    fn focused_help_dynamic(&self, model: &Model) -> Option<&str> {
        self.list.focused_help_dynamic(model.profile())
    }
    fn focused_position(&self) -> Option<(usize, usize)> {
        self.list.focus_position()
    }
    fn is_editing(&self) -> bool {
        self.list.editing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
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
    fn builds_with_expected_field_count() {
        let page = BasicsPage::new();
        // id, description, protocol, host, port, endpoint, startup, failure_policy.
        assert_eq!(page.list.fields.len(), 8);
        assert_eq!(page.list.fields[0].def.label, "id");
        assert_eq!(page.list.fields[2].def.label, "protocol");
        assert_eq!(page.list.fields[3].def.label, "host");
        assert_eq!(page.list.fields[4].def.label, "port");
        assert_eq!(page.list.fields[5].def.label, "endpoint");
    }

    #[test]
    fn host_round_trip_via_keys() {
        let mut page = BasicsPage::new();
        let mut m = model();
        // Move to host (index 3).
        for _ in 0..3 {
            page.on_key(k(KeyCode::Down), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // edit
        for c in "h.example.com".chars() {
            page.on_key(k(KeyCode::Char(c)), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().host.as_deref(), Some("h.example.com"));
        assert!(m.is_dirty());
    }

    #[test]
    fn port_round_trip_via_keys() {
        let mut page = BasicsPage::new();
        let mut m = model();
        // Move to port (index 4).
        for _ in 0..4 {
            page.on_key(k(KeyCode::Down), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // edit
        for c in "2222".chars() {
            page.on_key(k(KeyCode::Char(c)), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().port, Some(2222));
    }

    #[test]
    fn port_validation_rejects_overflow() {
        let mut page = BasicsPage::new();
        let mut m = model();
        for _ in 0..4 {
            page.on_key(k(KeyCode::Down), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // edit
        for c in "99999".chars() {
            page.on_key(k(KeyCode::Char(c)), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // commit attempt
        assert!(page.list.fields[4].last_error().is_some());
        assert!(m.profile().port.is_none());
    }

    #[test]
    fn endpoint_round_trip_via_keys() {
        let mut page = BasicsPage::new();
        let mut m = model();
        // Move to endpoint (index 5).
        for _ in 0..5 {
            page.on_key(k(KeyCode::Down), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // edit
        for c in "https://q.example.com".chars() {
            page.on_key(k(KeyCode::Char(c)), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.profile().endpoint.as_deref(),
            Some("https://q.example.com")
        );
    }

    #[test]
    fn renders_without_panic() {
        let mut page = BasicsPage::new();
        let m = model();
        let area = Rect::new(0, 0, 80, 24);
        let mut buf = Buffer::empty(area);
        page.render(area, &mut buf, &m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(s.contains("id") || s.contains("protocol"));
    }

    #[test]
    fn nav_keys_move_focus() {
        let mut page = BasicsPage::new();
        let mut m = model();
        assert_eq!(page.list.focus, 0);
        page.on_key(k(KeyCode::Down), &mut m);
        assert_eq!(page.list.focus, 1);
        page.on_key(k(KeyCode::Char('j')), &mut m);
        assert_eq!(page.list.focus, 2);
        page.on_key(k(KeyCode::Up), &mut m);
        assert_eq!(page.list.focus, 1);
        page.on_key(k(KeyCode::Char('k')), &mut m);
        assert_eq!(page.list.focus, 0);
    }

    #[test]
    fn enter_toggles_edit_mode() {
        let mut page = BasicsPage::new();
        let mut m = model();
        assert!(!page.list.editing);
        page.on_key(k(KeyCode::Enter), &mut m);
        assert!(page.list.editing);
        page.on_key(k(KeyCode::Esc), &mut m);
        assert!(!page.list.editing);
    }

    #[test]
    fn empty_id_validation_blocks_commit() {
        let mut page = BasicsPage::new();
        let mut m = model();
        // Focus is on id; enter edit, delete the value, try to commit.
        page.on_key(k(KeyCode::Enter), &mut m);
        assert!(page.list.editing);
        // Clear: cursor at end of "p", backspace once.
        page.on_key(k(KeyCode::Backspace), &mut m);
        // Try to commit.
        page.on_key(k(KeyCode::Enter), &mut m);
        // Validator should have rejected — last_error set, still editing.
        assert!(page.list.fields[0].last_error().is_some());
    }

    #[test]
    fn invalid_id_chars_are_rejected_by_validator() {
        let mut page = BasicsPage::new();
        let mut m = model();
        page.on_key(k(KeyCode::Enter), &mut m); // enter edit
                                                // Type a forbidden character.
        page.on_key(k(KeyCode::Char('!')), &mut m);
        page.on_key(k(KeyCode::Enter), &mut m); // commit attempt
        assert!(page.list.fields[0].last_error().is_some());
    }

    #[test]
    fn description_round_trip_via_keys() {
        let mut page = BasicsPage::new();
        let mut m = model();
        // Move to description (index 1).
        page.on_key(k(KeyCode::Down), &mut m);
        page.on_key(k(KeyCode::Enter), &mut m); // edit
        for c in "hello".chars() {
            page.on_key(k(KeyCode::Char(c)), &mut m);
        }
        page.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().description.as_deref(), Some("hello"));
    }
}
