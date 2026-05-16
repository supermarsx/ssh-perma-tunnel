//! "Connection" page — endpoint, bind, hops, timings.
//!
//! Multi-row resources (endpoints, hops) are exposed as comma-separated
//! summaries here; finer per-row editing can be added on a sub-page later.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use spt_config::schema::Profile;

use crate::model::Model;
use crate::pages::field::{opt_text, opt_u32, FieldList};
use crate::pages::Page;

/// Connection / endpoint timings.
pub struct ConnectionPage {
    list: FieldList,
}

impl ConnectionPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_text(
                "host",
                "SSH2 hostname (used when no [[profiles.endpoints]] given)",
                |p: &Profile| p.host.clone(),
                |p, v| p.host = v,
            ),
            // Port: u16 stored as text.
            crate::pages::field::FieldDef {
                label: "port",
                help: "SSH2 TCP port (1-65535, default 22)",
                get: Box::new(|p: &Profile| {
                    crate::pages::FieldValue::Numeric(
                        p.port.map(|n| n.to_string()).unwrap_or_default(),
                    )
                }),
                set: Box::new(|p, v| {
                    if let crate::pages::FieldValue::Numeric(s) = v {
                        if s.is_empty() {
                            p.port = None;
                        } else if let Ok(n) = s.parse::<u16>() {
                            p.port = Some(n);
                        }
                    }
                }),
                validate: Some(Box::new(|v| {
                    if let crate::pages::FieldValue::Numeric(s) = v {
                        if !s.is_empty() && s.parse::<u16>().is_err() {
                            return Some(format!("`{s}` is not a valid TCP port"));
                        }
                    }
                    None
                })),
            },
            opt_text(
                "endpoint",
                "SSH3 endpoint URL (https://host[:port]/path)",
                |p| p.endpoint.clone(),
                |p, v| p.endpoint = v,
            ),
            opt_text(
                "user",
                "Remote login user",
                |p| p.user.clone(),
                |p, v| p.user = v,
            ),
            opt_text(
                "connect_timeout",
                "Top-level legacy alias (e.g. `15s`)",
                |p| p.connect_timeout.clone(),
                |p, v| p.connect_timeout = v,
            ),
            opt_text(
                "connection.connect_timeout",
                "TCP connect timeout (e.g. `15s`)",
                |p| {
                    p.connection
                        .as_ref()
                        .and_then(|c| c.connect_timeout.clone())
                },
                |p, v| {
                    p.connection
                        .get_or_insert_with(Default::default)
                        .connect_timeout = v;
                },
            ),
            opt_text(
                "connection.handshake_timeout",
                "Protocol handshake timeout (e.g. `30s`)",
                |p| {
                    p.connection
                        .as_ref()
                        .and_then(|c| c.handshake_timeout.clone())
                },
                |p, v| {
                    p.connection
                        .get_or_insert_with(Default::default)
                        .handshake_timeout = v;
                },
            ),
            opt_text(
                "connection.auth_timeout",
                "Auth round-trip timeout",
                |p| p.connection.as_ref().and_then(|c| c.auth_timeout.clone()),
                |p, v| {
                    p.connection
                        .get_or_insert_with(Default::default)
                        .auth_timeout = v;
                },
            ),
            opt_u32(
                "connection.keepalive_retries",
                "Socket-level keepalive retries before drop",
                |p| p.connection.as_ref().and_then(|c| c.keepalive_retries),
                |p, v| {
                    p.connection
                        .get_or_insert_with(Default::default)
                        .keepalive_retries = v;
                },
            ),
            // Endpoints summary (read-only here).
            crate::pages::field::FieldDef {
                label: "endpoints (count)",
                help:
                    "Number of [[profiles.endpoints]] entries — edit via the Forwards page sub-list",
                get: Box::new(|p: &Profile| {
                    crate::pages::FieldValue::Text(p.endpoints.len().to_string())
                }),
                set: Box::new(|_p, _v| {}),
                validate: None,
            },
            // Hops summary.
            crate::pages::field::FieldDef {
                label: "hops (count)",
                help: "Number of [[profiles.hops]] entries (multi-hop chain)",
                get: Box::new(|p: &Profile| {
                    crate::pages::FieldValue::Text(p.hops.len().to_string())
                }),
                set: Box::new(|_p, _v| {}),
                validate: None,
            },
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for ConnectionPage {
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
    fn builds_with_all_fields() {
        let p = ConnectionPage::new();
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        assert!(labels.contains(&"host"));
        assert!(labels.contains(&"port"));
        assert!(labels.contains(&"endpoint"));
        assert!(labels.contains(&"user"));
    }

    #[test]
    fn renders_into_buffer() {
        let mut p = ConnectionPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(s.contains("host"));
        assert!(s.contains("port"));
    }

    #[test]
    fn port_numeric_validation_rejects_overflow() {
        let mut p = ConnectionPage::new();
        let mut m = model();
        // Move focus to port (index 1).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // edit
        for c in "999999".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert!(p.list.fields[1].last_error().is_some());
    }

    #[test]
    fn host_text_round_trip() {
        let mut p = ConnectionPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Enter), &mut m); // host edit
        for c in "h.example.com".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.profile().host.as_deref(), Some("h.example.com"));
    }

    #[test]
    fn esc_cancels_edit() {
        let mut p = ConnectionPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Enter), &mut m);
        assert!(p.list.editing);
        p.on_key(k(KeyCode::Char('x')), &mut m);
        p.on_key(k(KeyCode::Esc), &mut m);
        assert!(!p.list.editing);
        assert!(m.profile().host.is_none());
    }

    #[test]
    fn endpoints_and_hops_count_fields_present() {
        let p = ConnectionPage::new();
        let labels: Vec<&str> = p.list.fields.iter().map(|f| f.def.label).collect();
        assert!(labels.contains(&"endpoints (count)"));
        assert!(labels.contains(&"hops (count)"));
    }
}
