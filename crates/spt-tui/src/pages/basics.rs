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
                        if !s
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                        {
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
        assert_eq!(page.list.fields.len(), 5);
        assert_eq!(page.list.fields[0].def.label, "id");
        assert_eq!(page.list.fields[2].def.label, "protocol");
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
