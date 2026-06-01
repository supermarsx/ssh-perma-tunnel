//! "Limits" page — connection caps, byte/packet throttles.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;
use crate::pages::field::{opt_choice, opt_text, opt_u32, FieldList};
use crate::pages::Page;

const ALGORITHMS: &[&str] = &["token_bucket", "leaky_bucket"];

/// Per-profile limits.
pub struct LimitsPage {
    list: FieldList,
}

impl LimitsPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![
            opt_u32(
                "limits.max_active_connections",
                "Maximum active forwarded connections",
                |p| p.limits.as_ref().and_then(|l| l.max_active_connections),
                |p, v| {
                    p.limits
                        .get_or_insert_with(Default::default)
                        .max_active_connections = v;
                },
            ),
            opt_u32(
                "limits.max_new_connections_per_second",
                "Accept rate (per second)",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_new_connections_per_second)
                },
                |p, v| {
                    p.limits
                        .get_or_insert_with(Default::default)
                        .max_new_connections_per_second = v;
                },
            ),
            opt_text(
                "limits.max_bytes_per_second_in",
                "Inbound byte rate (e.g. `20MiB`)",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_bytes_per_second_in.clone())
                },
                |p, v| {
                    p.limits
                        .get_or_insert_with(Default::default)
                        .max_bytes_per_second_in = v;
                },
            ),
            opt_text(
                "limits.max_bytes_per_second_out",
                "Outbound byte rate",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_bytes_per_second_out.clone())
                },
                |p, v| {
                    p.limits
                        .get_or_insert_with(Default::default)
                        .max_bytes_per_second_out = v;
                },
            ),
            opt_choice(
                "limits.throttle_algorithm",
                "Throttle algorithm",
                ALGORITHMS,
                |p| p.limits.as_ref().and_then(|l| l.throttle_algorithm.clone()),
                |p, v| {
                    p.limits
                        .get_or_insert_with(Default::default)
                        .throttle_algorithm = v;
                },
            ),
            opt_text(
                "limits.max_connection_lifetime",
                "Maximum lifetime of a single forwarded connection",
                |p| {
                    p.limits
                        .as_ref()
                        .and_then(|l| l.max_connection_lifetime.clone())
                },
                |p, v| {
                    p.limits
                        .get_or_insert_with(Default::default)
                        .max_connection_lifetime = v;
                },
            ),
        ];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for LimitsPage {
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

    fn focused_help(&self) -> Option<&str> {
        self.list.focused_help()
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
    fn builds_with_six_fields() {
        let p = LimitsPage::new();
        assert_eq!(p.list.fields.len(), 6);
    }

    #[test]
    fn renders_without_panic() {
        let mut p = LimitsPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn max_active_round_trip() {
        let mut p = LimitsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "100".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile()
                .limits
                .as_ref()
                .and_then(|l| l.max_active_connections),
            Some(100)
        );
    }

    #[test]
    fn bytes_per_second_text_field() {
        let mut p = LimitsPage::new();
        let mut m = model();
        for _ in 0..2 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "20MiB".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile()
                .limits
                .as_ref()
                .and_then(|l| l.max_bytes_per_second_in.clone())
                .as_deref(),
            Some("20MiB")
        );
    }

    #[test]
    fn throttle_algorithm_choice() {
        let mut p = LimitsPage::new();
        let mut m = model();
        for _ in 0..4 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        // First option = "token_bucket"; Down moves to "leaky_bucket".
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.profile()
                .limits
                .as_ref()
                .and_then(|l| l.throttle_algorithm.clone())
                .as_deref(),
            Some("leaky_bucket")
        );
    }
}
