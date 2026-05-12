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
