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
use crate::save::{present_non_wizard_keys, unknown_keys};

/// One-line description of each non-wizard table, shown in the read-only
/// "Other settings" section so operators understand what is present but
/// unreachable from the 13-page wizard (E4-F15).
fn non_wizard_label(key: &str) -> &'static str {
    match key {
        "hops" => "hops — proxy-jump / multi-hop chain",
        "sftp_mounts" => "sftp_mounts — SFTP-backed filesystem mounts",
        "script" => "script — Rhai scripting hooks",
        "transport" => "transport — obfuscation transport",
        "enabled" => "enabled — profile start flag",
        // Unreachable: callers only pass keys from NON_WIZARD_TABLE_KEYS.
        _ => "(other)",
    }
}

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
        // Read-only "Other settings" section (E4-F15): list non-wizard tables
        // present on the profile plus any schema-unknown keys that a save
        // would silently drop. Built first so the layout can reserve space for
        // it ONLY when there's something to show — when the profile uses only
        // wizard-reachable settings the layout is identical to before, keeping
        // the existing nav-mode snapshot byte-for-byte.
        let other_lines = other_settings_lines(model);

        let chunks = if other_lines.is_empty() {
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(0), Constraint::Length(8)])
                .split(area)
        } else {
            // Reserve up to one row per line (+2 borders), capped so the TOML
            // preview keeps the majority of the screen.
            #[allow(clippy::cast_possible_truncation)]
            let other_height = (other_lines.len() as u16 + 2).min(10);
            Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Min(0),
                    Constraint::Length(8),
                    Constraint::Length(other_height),
                ])
                .split(area)
        };

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
        // Highlight each logical line into styled Spans. The line count
        // we use for `total_lines` / scroll arithmetic still matches the
        // number of logical lines (one Line per input line) so scroll
        // math is unaffected.
        let highlighted: Vec<Line<'static>> = toml.lines().map(highlight_toml_line).collect();
        Paragraph::new(highlighted)
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

        // Read-only "Other settings" section, only when there's content.
        if let Some(area) = chunks.get(2) {
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Other settings (read-only — edit in the config file)");
            Paragraph::new(other_lines)
                .block(block)
                .wrap(Wrap { trim: false })
                .render(*area, buf);
        }
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

/// Style a single TOML line into coloured spans.
///
/// The highlighter is deliberately simple — we don't fully parse TOML,
/// we just classify the visible structure that operators care about:
///
///   * `# comment`       → dark grey
///   * `[section]`       → cyan + bold
///   * `[[array.of.tables]]` → magenta + bold
///   * `key = value`     → key in yellow, `=` plain, value styled by kind:
///       - `"…"` strings → green
///       - `true`/`false` → blue
///       - numeric / hex / size / duration / ip-port → red
///   * leading whitespace and unrecognised text pass through unstyled.
///
/// Inline arrays / inline tables / multi-line strings are rendered with
/// only the key+`=` styled and the rest plain — full TOML tokenisation
/// is out of scope; the canonical writer we feed in doesn't emit them.
fn highlight_toml_line(raw: &str) -> Line<'static> {
    let trimmed_start = raw.trim_start();
    let indent_len = raw.len() - trimmed_start.len();
    let indent = &raw[..indent_len];

    // Empty line.
    if trimmed_start.is_empty() {
        return Line::from(Span::raw(raw.to_string()));
    }

    let mut spans: Vec<Span<'static>> = Vec::new();
    if !indent.is_empty() {
        spans.push(Span::raw(indent.to_string()));
    }

    // Comment line.
    if trimmed_start.starts_with('#') {
        spans.push(Span::styled(
            trimmed_start.to_string(),
            Style::default().fg(Color::DarkGray),
        ));
        return Line::from(spans);
    }

    // [[array of tables]]
    if let Some(rest) = trimmed_start.strip_prefix("[[") {
        if let Some(inner) = rest.strip_suffix("]]") {
            spans.push(Span::styled(
                "[[".to_string(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
            spans.push(Span::styled(
                inner.to_string(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
            spans.push(Span::styled(
                "]]".to_string(),
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
            return Line::from(spans);
        }
    }
    // [section]
    if let Some(rest) = trimmed_start.strip_prefix('[') {
        if let Some(inner) = rest.strip_suffix(']') {
            spans.push(Span::styled(
                "[".to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
            spans.push(Span::styled(
                inner.to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
            spans.push(Span::styled(
                "]".to_string(),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(ratatui::style::Modifier::BOLD),
            ));
            return Line::from(spans);
        }
    }

    // key = value
    if let Some((key, value)) = split_key_value(trimmed_start) {
        spans.push(Span::styled(
            key.to_string(),
            Style::default().fg(Color::Yellow),
        ));
        spans.push(Span::raw(" = ".to_string()));
        spans.push(style_value(value));
        return Line::from(spans);
    }

    // Fallback: unstyled.
    spans.push(Span::raw(trimmed_start.to_string()));
    Line::from(spans)
}

/// Split a `key = value` line, returning `(key, value)` trimmed.
/// Returns `None` if there's no top-level `=` (the `=` must occur
/// outside any quoted string at the leading position).
fn split_key_value(s: &str) -> Option<(&str, &str)> {
    let mut in_str = false;
    let mut prev = '\0';
    for (i, c) in s.char_indices() {
        match c {
            '"' if prev != '\\' => in_str = !in_str,
            '=' if !in_str => {
                let key = s[..i].trim_end();
                let value = s[i + 1..].trim_start();
                if !key.is_empty() {
                    return Some((key, value));
                }
            }
            _ => {}
        }
        prev = c;
    }
    None
}

fn style_value(v: &str) -> Span<'static> {
    let v_trim = v.trim();
    if v_trim.starts_with('"') && v_trim.ends_with('"') && v_trim.len() >= 2 {
        return Span::styled(v.to_string(), Style::default().fg(Color::Green));
    }
    if v_trim == "true" || v_trim == "false" {
        return Span::styled(v.to_string(), Style::default().fg(Color::Blue));
    }
    if v_trim.chars().next().is_some_and(|c| c.is_ascii_digit())
        || v_trim.starts_with('-') && v_trim[1..].starts_with(|c: char| c.is_ascii_digit())
    {
        return Span::styled(v.to_string(), Style::default().fg(Color::Red));
    }
    Span::raw(v.to_string())
}

/// Build the lines for the read-only "Other settings" section (E4-F15).
///
/// Returns an empty vec when the profile has no non-wizard tables and no
/// schema-unknown keys, which keeps the section (and its layout slot) hidden
/// so wizard-only profiles render byte-identically to before.
fn other_settings_lines(model: &Model) -> Vec<Line<'static>> {
    let present = present_non_wizard_keys(model);
    let dropped = unknown_keys(model);
    if present.is_empty() && dropped.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<Line<'static>> = Vec::new();
    for key in present {
        out.push(Line::from(vec![
            Span::styled("• ", Style::default().fg(Color::Cyan)),
            Span::styled(
                non_wizard_label(key).to_string(),
                Style::default().fg(Color::Cyan),
            ),
        ]));
    }
    for key in dropped {
        out.push(Line::from(Span::styled(
            format!("⚠ unknown key `{key}` — NOT understood by the schema; a TUI save will drop it"),
            Style::default().fg(Color::Yellow),
        )));
    }
    out
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
        use std::fmt::Write as _; // 1.88 lint: format_push_string
        let mut s = String::from(
            "version = 1\n\n[[profiles]]\nname = \"p\"\nprotocol = \"ssh2\"\nhost = \"h.example.com\"\n",
        );
        for i in 0..30 {
            let _ = writeln!(
                s,
                "\n[[profiles.forwards]]\nname = \"f-{i}\"\ntype = \"local\"\ntransport = \"tcp\"\nbind = \"127.0.0.1:{p}\"\ntarget = \"example.com:22\"",
                p = 10000 + i,
            );
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

    // ---- Other-settings read-only section (E4-F15) -------------------

    #[test]
    fn other_settings_empty_for_wizard_only_profile() {
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
"#,
        );
        assert!(
            other_settings_lines(&m).is_empty(),
            "wizard-only profile must not grow the Other-settings section"
        );
    }

    #[test]
    fn other_settings_lists_non_wizard_tables_and_unknown_keys() {
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
enabled = true
typo_key = "x"

[profiles.transport]
"#,
        );
        let lines = other_settings_lines(&m);
        assert!(!lines.is_empty());
        let text: String = lines
            .iter()
            .flat_map(|l| l.spans.iter())
            .map(|s| s.content.as_ref())
            .collect();
        assert!(text.contains("transport"), "must list transport table");
        assert!(text.contains("enabled"), "must list enabled flag");
        assert!(text.contains("typo_key"), "must warn about unknown key");
        assert!(text.contains("drop it"), "must say the key will be dropped");
    }

    #[test]
    fn rendered_review_shows_other_settings_section_when_present() {
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"

[profiles.transport]
"#,
        );
        let mut page = ReviewPage::new();
        let s = rendered_text(&mut page, &m);
        assert!(
            s.contains("Other settings"),
            "section header must render when non-wizard tables are present:\n{s}"
        );
    }

    #[test]
    fn rendered_review_hides_other_settings_for_plain_profile() {
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
        assert!(
            !s.contains("Other settings"),
            "section must be hidden for wizard-only profiles (snapshot parity):\n{s}"
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
        let max = page
            .last_total_lines
            .saturating_sub(page.last_visible_height);
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
        let max = page
            .last_total_lines
            .saturating_sub(page.last_visible_height);
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

    // ---- Syntax highlighting -----------------------------------------

    fn span_at(line: &Line<'_>, content: &str) -> Option<Style> {
        line.spans
            .iter()
            .find(|s| s.content.contains(content))
            .map(|s| s.style)
    }

    #[test]
    fn highlight_section_header_styled_cyan_bold() {
        let line = highlight_toml_line("[profile]");
        let style = span_at(&line, "profile").expect("section name must be a span");
        assert_eq!(style.fg, Some(Color::Cyan));
        assert!(style.add_modifier.contains(ratatui::style::Modifier::BOLD));
    }

    #[test]
    fn highlight_array_of_tables_styled_magenta_bold() {
        let line = highlight_toml_line("[[profiles.forwards]]");
        let style = span_at(&line, "profiles.forwards").expect("array name must be a span");
        assert_eq!(style.fg, Some(Color::Magenta));
        assert!(style.add_modifier.contains(ratatui::style::Modifier::BOLD));
    }

    #[test]
    fn highlight_comment_styled_dark_gray() {
        let line = highlight_toml_line("# this is a comment");
        let style = span_at(&line, "comment").expect("comment must be a span");
        assert_eq!(style.fg, Some(Color::DarkGray));
    }

    #[test]
    fn highlight_string_value_styled_green() {
        let line = highlight_toml_line(r#"host = "h.example.com""#);
        let key_style = span_at(&line, "host").expect("key must be a span");
        assert_eq!(key_style.fg, Some(Color::Yellow));
        let value_style = span_at(&line, "h.example.com").expect("value must be a span");
        assert_eq!(value_style.fg, Some(Color::Green));
    }

    #[test]
    fn highlight_bool_value_styled_blue() {
        let line = highlight_toml_line("agent = true");
        let style = span_at(&line, "true").expect("bool value must be a span");
        assert_eq!(style.fg, Some(Color::Blue));
    }

    #[test]
    fn highlight_numeric_value_styled_red() {
        let line = highlight_toml_line("port = 22");
        let style = span_at(&line, "22").expect("numeric value must be a span");
        assert_eq!(style.fg, Some(Color::Red));
    }

    #[test]
    fn highlight_indented_line_preserves_indent() {
        // Canonical TOML rarely indents, but if it ever does, the
        // indent prefix must be preserved as plain spans (no panic, no
        // re-trim) and the key starts where the non-whitespace begins.
        let line = highlight_toml_line("    nested = 1");
        // Reconstruct the rendered text from the spans.
        let s: String = line.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert_eq!(s, "    nested = 1");
    }

    #[test]
    fn highlight_empty_line_returns_empty_span() {
        let line = highlight_toml_line("");
        let s: String = line.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert_eq!(s, "");
    }

    #[test]
    fn highlight_falls_back_on_unparseable_line() {
        // A line that's neither a comment, section, nor key=value
        // should pass through without panicking.
        let line = highlight_toml_line("just some text");
        let s: String = line.spans.iter().map(|sp| sp.content.as_ref()).collect();
        assert_eq!(s, "just some text");
    }

    #[test]
    fn rendered_preview_contains_styled_section_header() {
        // End-to-end: render a real profile and assert at least one
        // cell inside the section-header text has Cyan + Bold styling.
        use ratatui::buffer::Buffer;
        use ratatui::layout::Rect;
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
"#,
        );
        let mut page = ReviewPage::new();
        let area = Rect::new(0, 0, 100, 20);
        let mut buf = Buffer::empty(area);
        page.render(area, &mut buf, &m);
        // Scan every cell for one that's part of a section header and
        // has the expected style.
        let mut found = false;
        for y in 0..area.height {
            for x in 0..area.width {
                let cell = &buf[(x, y)];
                if cell.symbol() == "[" || cell.symbol() == "]" {
                    let style = cell.style();
                    if style.fg == Some(Color::Cyan)
                        && style.add_modifier.contains(ratatui::style::Modifier::BOLD)
                    {
                        found = true;
                    }
                    if style.fg == Some(Color::Magenta)
                        && style.add_modifier.contains(ratatui::style::Modifier::BOLD)
                    {
                        found = true;
                    }
                }
            }
        }
        assert!(
            found,
            "rendered preview must contain at least one bracket cell styled Cyan-or-Magenta + BOLD"
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
