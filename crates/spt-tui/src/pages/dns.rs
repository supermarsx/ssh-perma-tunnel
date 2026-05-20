//! "DNS" page — `dns_names` per forward, plus a summary view of the
//! global `[[dns.records]]` bound to this profile (for orientation only —
//! editing global records is out of scope for the per-profile wizard).

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

use crate::model::Model;
use crate::pages::field::{opt_list, FieldList};
use crate::pages::Page;

/// DNS names registered by this profile's forwards.
pub struct DnsPage {
    list: FieldList,
}

impl DnsPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![opt_list(
            "forward[0].dns_names",
            "DNS names registered by the first forward (CSV)",
            |p| {
                p.forwards
                    .first()
                    .and_then(|f| f.dns_names.clone())
                    .unwrap_or_default()
            },
            |p, v| {
                if let Some(f) = p.forwards.first_mut() {
                    f.dns_names = if v.is_empty() { None } else { Some(v) };
                }
            },
        )];
        Self {
            list: FieldList::new(fields),
        }
    }
}

impl Page for DnsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(5), Constraint::Min(0)])
            .split(area);
        self.list.render(chunks[0], buf, model.profile());

        // Show global [[dns.records]] for orientation.
        let lines: Vec<Line<'_>> = model
            .config()
            .dns
            .as_ref()
            .map(|d| {
                d.records
                    .iter()
                    .map(|r| Line::from(format!("{:<32} {:<5} {}", r.name, r.kind, r.value)))
                    .collect()
            })
            .unwrap_or_default();
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Global [[dns.records]] (read-only here — edit via `spt config render`)");
        Paragraph::new(lines).block(block).render(chunks[1], buf);
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
    use spt_config::schema::Forward;

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn model_with_forward() -> Model {
        let mut m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        );
        m.profile_mut().forwards.push(Forward {
            name: "f1".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            ..Default::default()
        });
        m
    }

    #[test]
    fn renders_without_forwards() {
        let mut p = DnsPage::new();
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        );
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn renders_with_global_dns_records() {
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[[dns.records]]
name = "service.local"
type = "A"
value = "127.0.0.1"
"#,
        );
        let mut p = DnsPage::new();
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(s.contains("service.local"));
    }

    #[test]
    fn list_edit_round_trip() {
        let mut p = DnsPage::new();
        let mut m = model_with_forward();
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        for c in "a.example, b.example".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        let names = m.profile().forwards[0]
            .dns_names
            .clone()
            .unwrap_or_default();
        assert_eq!(names, vec!["a.example", "b.example"]);
    }
}
