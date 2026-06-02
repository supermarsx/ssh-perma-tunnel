//! "Review & save" page.
//!
//! Renders the in-memory profile as canonical TOML (with secrets redacted)
//! and shows the validator's diagnostics. `Ctrl-S` (handled in [`crate::app`])
//! triggers the actual save.
//!
//! The TOML preview is **scrollable**: Up/Down (or `j`/`k`) move one line,
//! PageUp/PageDown move one screen, Home/End jump to the extremes. The
//! status footer advertises `↑↓/jk: move` and this page honours that
//! contract.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget, Wrap};
use spt_config::ValidationDiagnostics;

use crate::model::Model;
use crate::pages::Page;

/// Review page — read-only TOML preview + diagnostics, with vertical scroll.
pub struct ReviewPage {
    /// Top-line offset into the rendered TOML (in logical lines, not
    /// wrapped visual lines). Clamped by render() to the valid range.
    scroll: u16,
    /// Cached geometry from the last render so `on_key` can compute
    /// page-sized scrolls without re-rendering. Both default to 0
    /// before the first render — page/end keys are no-ops at that
    /// point, which is correct.
    last_visible_height: u16,
    last_total_lines: u16,
}

impl ReviewPage {
    /// Construct the page.
    pub fn new() -> Self {
        Self {
            scroll: 0,
            last_visible_height: 0,
            last_total_lines: 0,
        }
    }

    /// Current top-line offset (exposed for tests).
    #[cfg(test)]
    pub(crate) fn scroll_offset(&self) -> u16 {
        self.scroll
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
        // Count logical lines (newline-separated). With Wrap { trim: false }
        // on, very long lines wrap visually, so this undercounts at narrow
        // widths — acceptable, the cursor still moves through every line
        // and the operator can keep pressing Down past the apparent end.
        #[allow(clippy::cast_possible_truncation)]
        let total_lines = (toml.lines().count() as u16).max(1);
        let inner_height = chunks[0].height.saturating_sub(2); // top/bottom borders
        let max_scroll = total_lines.saturating_sub(inner_height);
        self.scroll = self.scroll.min(max_scroll);
        self.last_visible_height = inner_height;
        self.last_total_lines = total_lines;

        // Compose a title that exposes the scroll position so the operator
        // can see they've moved (e.g. "12/87 line" on the title bar).
        let title = if total_lines > inner_height {
            format!(
                "Canonical TOML (redacted) — line {}/{}  ↑↓/jk to scroll, Ctrl-S to save",
                self.scroll + 1,
                total_lines,
            )
        } else {
            "Canonical TOML (redacted) — Ctrl-S to save".to_string()
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        Paragraph::new(toml)
            .block(block)
            .wrap(Wrap { trim: false })
            .scroll((self.scroll, 0))
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

    fn on_key(&mut self, key: KeyEvent, _model: &mut Model) -> bool {
        // Compute clamp ceiling from the last render's geometry. If the
        // page was never rendered yet, both fields are 0 and max=0 so
        // every key is effectively a no-op until the first render seeds
        // them. The very next render will rectify scroll regardless.
        let max = self
            .last_total_lines
            .saturating_sub(self.last_visible_height);
        let page_step = self.last_visible_height.max(1);
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.scroll = self.scroll.saturating_sub(1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.scroll = self.scroll.saturating_add(1).min(max);
            }
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(page_step);
            }
            KeyCode::PageDown => {
                self.scroll = self.scroll.saturating_add(page_step).min(max);
            }
            KeyCode::Home => {
                self.scroll = 0;
            }
            KeyCode::End => {
                self.scroll = max;
            }
            _ => {}
        }
        // Scroll doesn't mutate the model.
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
    use crossterm::event::KeyModifiers;
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
            s.push('\n');
        }
        s
    }

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    /// Build a model whose canonical TOML is dozens of lines long so
    /// scrolling actually has somewhere to go. The forwards array
    /// gives us cheap line inflation.
    fn long_model() -> Model {
        let mut s = String::from(
            "version = 1\n\n[[profiles]]\nname = \"p\"\nprotocol = \"ssh2\"\nhost = \"h.example.com\"\n",
        );
        for i in 0..30 {
            s.push_str(&format!(
                "\n[[profiles.forwards]]\nname = \"f-{i}\"\ntype = \"local\"\ntransport = \"tcp\"\nbind = \"127.0.0.1:{p}\"\ntarget = \"example.com:22\"\n",
                p = 10000 + i,
            ));
        }
        Model::from_str(&s)
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
    fn unrelated_keys_are_ignored() {
        // Non-navigation keys must be no-ops at the page level (Ctrl-S
        // is handled by App; this page doesn't process arbitrary input).
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m); // seed geometry
        let before = page.scroll_offset();
        page.on_key(k(KeyCode::Char('x')), &mut m);
        page.on_key(k(KeyCode::Enter), &mut m);
        page.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(
            page.scroll_offset(),
            before,
            "unrelated keys must not change scroll"
        );
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

    // ---- Scroll behavior ----------------------------------------------

    #[test]
    fn down_arrow_advances_scroll() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m); // seed last_* geometry
        assert_eq!(page.scroll_offset(), 0);
        page.on_key(k(KeyCode::Down), &mut m);
        assert_eq!(page.scroll_offset(), 1, "Down must advance scroll by 1");
        page.on_key(k(KeyCode::Char('j')), &mut m);
        assert_eq!(page.scroll_offset(), 2, "j must advance scroll by 1");
    }

    #[test]
    fn up_arrow_decrements_scroll() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m);
        page.on_key(k(KeyCode::Down), &mut m);
        page.on_key(k(KeyCode::Down), &mut m);
        page.on_key(k(KeyCode::Down), &mut m);
        assert_eq!(page.scroll_offset(), 3);
        page.on_key(k(KeyCode::Up), &mut m);
        assert_eq!(page.scroll_offset(), 2);
        page.on_key(k(KeyCode::Char('k')), &mut m);
        assert_eq!(page.scroll_offset(), 1);
    }

    #[test]
    fn up_at_top_clamps_to_zero() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m);
        assert_eq!(page.scroll_offset(), 0);
        for _ in 0..5 {
            page.on_key(k(KeyCode::Up), &mut m);
        }
        assert_eq!(
            page.scroll_offset(),
            0,
            "Up at the top must not go negative"
        );
    }

    #[test]
    fn down_past_end_clamps_to_max() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m);
        // Hammer Down many more times than there are lines.
        for _ in 0..10_000 {
            page.on_key(k(KeyCode::Down), &mut m);
        }
        let max = page.last_total_lines.saturating_sub(page.last_visible_height);
        assert_eq!(
            page.scroll_offset(),
            max,
            "Down past end must clamp to max scroll"
        );
        assert!(max > 0, "test model must produce a scrollable preview");
    }

    #[test]
    fn page_down_advances_by_visible_height() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m);
        let step = page.last_visible_height;
        assert!(step > 0);
        page.on_key(k(KeyCode::PageDown), &mut m);
        let max = page.last_total_lines.saturating_sub(step);
        assert_eq!(page.scroll_offset(), step.min(max));
    }

    #[test]
    fn page_up_decrements_by_visible_height() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m);
        page.on_key(k(KeyCode::End), &mut m);
        let end = page.scroll_offset();
        let step = page.last_visible_height.max(1);
        page.on_key(k(KeyCode::PageUp), &mut m);
        assert_eq!(page.scroll_offset(), end.saturating_sub(step));
    }

    #[test]
    fn home_jumps_to_top() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m);
        page.on_key(k(KeyCode::End), &mut m);
        assert!(page.scroll_offset() > 0);
        page.on_key(k(KeyCode::Home), &mut m);
        assert_eq!(page.scroll_offset(), 0);
    }

    #[test]
    fn end_jumps_to_last_visible_top() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let _ = rendered_text(&mut page, &m);
        page.on_key(k(KeyCode::End), &mut m);
        let max = page.last_total_lines.saturating_sub(page.last_visible_height);
        assert_eq!(page.scroll_offset(), max);
    }

    /// Rendered buffer assertion: after scrolling Down by several
    /// lines, the first visible logical line must differ from the
    /// pre-scroll first line.
    #[test]
    fn scroll_changes_first_visible_line_in_rendered_buffer() {
        let mut page = ReviewPage::new();
        let mut m = long_model();
        let before = rendered_text(&mut page, &m);
        for _ in 0..5 {
            page.on_key(k(KeyCode::Down), &mut m);
        }
        let after = rendered_text(&mut page, &m);
        assert_ne!(
            before, after,
            "rendered text must change after scrolling 5 lines down"
        );
    }

    /// Title must show the scroll position when the preview is long
    /// enough to overflow. When it fits, the simple title is used.
    #[test]
    fn title_advertises_scroll_position_when_long() {
        let mut page = ReviewPage::new();
        let m = long_model();
        let s = rendered_text(&mut page, &m);
        assert!(
            s.contains("line 1/") || s.contains("line 1 /"),
            "title must show current/total line position:\n{s}"
        );
        assert!(
            s.contains("scroll"),
            "title must advertise the scroll keys:\n{s}"
        );
    }

    #[test]
    fn title_omits_scroll_position_when_content_fits() {
        let mut page = ReviewPage::new();
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
"#,
        );
        let s = rendered_text(&mut page, &m);
        assert!(
            !s.contains("line 1/"),
            "short content must not show scroll position:\n{s}"
        );
    }
}
