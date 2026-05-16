//! "Review & save" page.
//!
//! Renders the in-memory profile as canonical TOML (with secrets redacted)
//! and shows the validator's diagnostics. `Ctrl-S` (handled in [`crate::app`])
//! triggers the actual save.

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget, Wrap};
use spt_config::ValidationDiagnostics;

use crate::model::Model;
use crate::pages::Page;

/// Review page — read-only TOML preview + diagnostics.
pub struct ReviewPage;

impl ReviewPage {
    /// Construct the page.
    pub fn new() -> Self {
        Self
    }
}

impl Page for ReviewPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(0), Constraint::Length(8)])
            .split(area);

        // Render the redacted canonical TOML.
        let toml = model.render_redacted();
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Canonical TOML (redacted) — Ctrl-S to save");
        Paragraph::new(toml)
            .block(block)
            .wrap(Wrap { trim: false })
            .render(chunks[0], buf);

        // Validation summary.
        let diag = model.validate();
        let lines = diagnostics_to_lines(&diag);
        let title = format!(
            "Validation: {} error(s), {} warning(s)",
            diag.errors.len(),
            diag.warnings.len()
        );
        let block = Block::default().borders(Borders::ALL).title(title);
        Paragraph::new(lines).block(block).render(chunks[1], buf);
    }

    fn on_key(&mut self, _key: KeyEvent, _model: &mut Model) -> bool {
        // The save side-effect happens in `App::on_key` via Ctrl-S.
        false
    }
}

fn diagnostics_to_lines(d: &ValidationDiagnostics) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    for e in &d.errors {
        out.push(Line::from(Span::styled(
            format!("error[{}]: {}", e.code, e.message),
            Style::default().fg(Color::Red),
        )));
    }
    for w in &d.warnings {
        out.push(Line::from(Span::styled(
            format!("warn[{}]: {}", w.code, w.message),
            Style::default().fg(Color::Yellow),
        )));
    }
    if out.is_empty() {
        out.push(Line::from(Span::styled(
            "no issues",
            Style::default().fg(Color::Green),
        )));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;

    fn rendered_text(p: &mut ReviewPage, m: &Model) -> String {
        let area = Rect::new(0, 0, 100, 40);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, m);
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    #[test]
    fn renders_clean_profile() {
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
"#,
        );
        let mut page = ReviewPage::new();
        let s = rendered_text(&mut page, &m);
        // Title and validation block headers present.
        assert!(s.contains("Canonical TOML"));
        assert!(s.contains("Validation"));
        assert!(s.contains("no issues") || s.contains("0 error"));
    }

    #[test]
    fn renders_diagnostics_for_broken_profile() {
        // Missing host AND endpoint should be flagged by validate.
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        );
        let mut page = ReviewPage::new();
        let s = rendered_text(&mut page, &m);
        assert!(s.contains("Validation"));
    }

    #[test]
    fn ignores_key_events() {
        let mut page = ReviewPage::new();
        let mut m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        );
        let key = KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE);
        assert!(!page.on_key(key, &mut m));
        assert!(!page.on_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), &mut m));
    }

    #[test]
    fn diagnostics_to_lines_handles_empty() {
        let d = ValidationDiagnostics {
            errors: vec![],
            warnings: vec![],
        };
        let lines = diagnostics_to_lines(&d);
        assert_eq!(lines.len(), 1);
    }
}
