//! "Basics" page — id, description, protocol.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_choice, opt_text, FieldList};
use crate::pages::Page;

const PROTOCOLS: &[&str] = &["ssh2", "ssh3"];
const STARTUP: &[&str] = &["eager", "lazy"];
const FAILURE: &[&str] = &["retry", "fail_profile", "fail_process"];

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
                        if !s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
                            return Some("profile id may only contain [a-zA-Z0-9_-]".into());
                        }
                    }
                    None
                })),
            },
            opt_text(
                "description",
                "Free-form profile description",
                |p| p.description.clone(),
                |p, v| p.description = v,
            ),
            // Protocol is required, not Option<String>; serialize-as-text.
            crate::pages::field::FieldDef {
                label: "protocol",
                help: "Transport protocol — ssh2 (libssh2) or ssh3 (HTTP/3)",
                get: Box::new(|p| crate::pages::FieldValue::Choice {
                    value: p.protocol.clone(),
                    options: PROTOCOLS,
                }),
                set: Box::new(|p, v| {
                    if let crate::pages::FieldValue::Choice { value, .. } = v {
                        if !value.is_empty() {
                            p.protocol = value;
                        }
                    }
                }),
                validate: None,
            },
            opt_choice(
                "startup",
                "When to start: eager (boot) or lazy (on demand)",
                STARTUP,
                |p| p.startup.clone(),
                |p, v| p.startup = v,
            ),
            opt_choice(
                "failure_policy",
                "Action when profile fails repeatedly",
                FAILURE,
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
            self.list.on_edit_key(key, model.profile_mut())
        } else {
            self.list.on_nav_key(key, model.profile());
            false
        }
    }
}
