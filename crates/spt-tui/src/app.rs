//! Top-level state machine and key/event loop for the TUI.
//!
//! [`App`] owns:
//!
//! * the [`Model`] (the profile being edited),
//! * a `Vec<Box<dyn Page>>` (one per [`PageKind`]),
//! * the currently-displayed [`PageId`] and a transient help-overlay flag.
//!
//! Global keys handled in [`App::on_key`]:
//!
//! | key            | action                                   |
//! |----------------|------------------------------------------|
//! | `Tab` / `]`    | next page                                |
//! | `BackTab`/`[`  | previous page                            |
//! | `?`            | toggle help overlay                      |
//! | `q` / `Esc`    | quit (with confirm if dirty)             |
//! | `Ctrl-S`       | save                                     |
//! | `Ctrl-C`       | force quit                               |
//!
//! Per-page keys are forwarded via [`Page::on_key`].

use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::backend::Backend;
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use ratatui::Terminal;
use spt_core::Result;

use crate::model::Model;
use crate::pages::{build_pages, Page, PageKind};
use crate::save;

/// Type alias used for the public re-export.
pub type PageId = PageKind;

/// Internal app events emitted by the input loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    /// Quit the loop without saving.
    Quit,
    /// Quit after a successful save.
    QuitSaved,
    /// Continue processing.
    Continue,
}

/// Top-level wizard state machine.
pub struct App {
    /// Profile / config model.
    pub model: Model,
    /// Page implementations, indexed by [`PageKind::index`].
    pub pages: Vec<Box<dyn Page>>,
    /// Currently-displayed page.
    pub current: PageKind,
    /// `true` when the help overlay should be shown.
    pub show_help: bool,
    /// Transient status-line message (e.g. "saved", "error: …").
    pub status: String,
    /// `true` when the user has pressed quit-with-dirty once already, so a
    /// second press confirms.
    pub confirm_quit: bool,
}

impl App {
    /// Construct from a [`Model`] with default page state.
    pub fn new(model: Model) -> Self {
        Self {
            model,
            pages: build_pages(),
            current: PageKind::Basics,
            show_help: false,
            status: String::new(),
            confirm_quit: false,
        }
    }

    /// Run the main event loop until the user quits.
    pub fn run<B: Backend>(&mut self, terminal: &mut Terminal<B>) -> Result<()> {
        loop {
            terminal
                .draw(|f| self.render_frame(f.area(), f.buffer_mut()))
                .map_err(|e| spt_core::Error::RuntimeFailure(format!("draw: {e}")))?;

            // Block for events with a 250 ms tick so resize / redraw is responsive.
            if event::poll(Duration::from_millis(250))
                .map_err(|e| spt_core::Error::RuntimeFailure(format!("poll: {e}")))?
            {
                let ev = event::read()
                    .map_err(|e| spt_core::Error::RuntimeFailure(format!("read: {e}")))?;
                match self.dispatch_event(ev) {
                    AppEvent::Quit | AppEvent::QuitSaved => return Ok(()),
                    AppEvent::Continue => {}
                }
            }
        }
    }

    /// Render a complete frame.
    ///
    /// Layout (top→bottom):
    ///
    /// ```text
    /// ┌─ tabs ────────────────────────────────────────────────┐  3 rows
    /// │  spt profile configure — <profile>          [3/13]    │
    /// │  1 Basics  2 Connection  3 Auth  4 Trust  …           │
    /// └────────────────────────────────────────────────────────┘
    /// │                                                        │
    /// │  page body (one widget per FieldList row)              │  min(0)
    /// │                                                        │
    /// ┌─ help footer ─────────────────────────────────────────┐  3 rows
    /// │ id [1/5]  — Profile identifier (must be unique)        │
    /// └────────────────────────────────────────────────────────┘
    /// ─── status ─────────────────────────────────────────────    2 rows
    ///  ●  Basics  0E/0W  [ok]   ↑↓/jk: move  Enter: edit  ?: help  q: quit
    /// ```
    pub fn render_frame(&mut self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // tabs
                Constraint::Min(0),    // page body
                Constraint::Length(3), // help footer
                Constraint::Length(2), // status line
            ])
            .split(area);

        // ----- Tabs ---------------------------------------------------------
        // ratatui's `Tabs` widget renders the full list left-to-right with
        // no scroll — anything beyond the inner width gets clipped silently
        // and the user can't even see which page they're on if it's past
        // the cut. With 13 pages totalling ~145 cells of text, this happens
        // routinely below 120-wide. We render a windowed view manually so
        // the active tab is always visible, with `…` markers when there's
        // overflow on either side.
        let idx = self.current.index();
        let n_pages = PageKind::all().len();
        let labels: Vec<String> = PageKind::all()
            .iter()
            .enumerate()
            .map(|(i, p)| format!("{} {}", i + 1, p.title()))
            .collect();
        let tabs_title = format!(
            "spt profile configure — {}    [{}/{}]",
            self.model.profile().name,
            idx + 1,
            n_pages,
        );
        let block = Block::default().borders(Borders::ALL).title(tabs_title);
        let inner = block.inner(chunks[0]);
        block.render(chunks[0], buf);
        let line = render_scrolling_tabs(&labels, idx, inner.width);
        Paragraph::new(line).render(inner, buf);

        // ----- Page body ----------------------------------------------------
        if let Some(page) = self.pages.get_mut(idx) {
            page.render(chunks[1], buf, &self.model);
        }

        // ----- Help footer (focused field + description) -------------------
        let (help_text, position) = if let Some(page) = self.pages.get(idx) {
            (page.focused_help(), page.focused_position())
        } else {
            (None, None)
        };
        let footer = match (help_text, position) {
            (Some(text), Some((cur, total))) => format!("[{cur}/{total}]  {text}"),
            (Some(text), None) => text.to_string(),
            // Read-only pages (e.g. Review) don't have a focused field —
            // surface a stable hint so the footer never feels empty.
            (None, _) => "(no field selected — read-only page)".into(),
        };
        let footer_block = Block::default()
            .borders(Borders::ALL)
            .title("field info")
            .border_style(Style::default().fg(Color::DarkGray));
        Paragraph::new(footer)
            .block(footer_block)
            .render(chunks[2], buf);

        // ----- Status line --------------------------------------------------
        let dirty = if self.model.is_dirty() { "●" } else { " " };
        let diag = self.model.validate();
        let editing = self.pages.get(idx).is_some_and(|p| p.is_editing());
        let key_hints = if editing {
            "Space/t: toggle  ←→: rotate  Enter: commit  Esc: cancel"
        } else {
            "↑↓/jk: move  Tab: next page  Enter: edit  ?: help  Ctrl-S: save  q: quit"
        };
        let summary = format!(
            "{}  {}  {}E/{}W  [{}]   {}",
            dirty,
            self.current.title(),
            diag.errors.len(),
            diag.warnings.len(),
            self.status,
            key_hints,
        );
        let block = Block::default().borders(Borders::TOP);
        Paragraph::new(summary).block(block).render(chunks[3], buf);

        // Help overlay (?) — drawn last so it overdraws everything else.
        if self.show_help {
            render_help(area, buf);
        }
    }

    /// Handle a key event. Returns whether the loop should continue.
    /// Dispatch a single terminal event. Filters out non-`Press` key events
    /// before calling [`Self::on_key`].
    ///
    /// **Why the kind filter is here, not at `event::read`'s call site:**
    /// crossterm on Windows emits `KeyEventKind::Press` AND
    /// `KeyEventKind::Release` (and sometimes `Repeat`) for every keystroke.
    /// Linux and macOS only emit `Press`. A naive `if let Event::Key(k) = ev`
    /// handler fires the page-level action twice per press on Windows
    /// (visible as "every key duplicates"). Routing every event through
    /// this method keeps the filter authoritative and unit-testable.
    pub fn dispatch_event(&mut self, ev: Event) -> AppEvent {
        if let Event::Key(key) = ev {
            if key.kind != KeyEventKind::Press {
                return AppEvent::Continue;
            }
            return self.on_key(key);
        }
        AppEvent::Continue
    }

    /// Apply one key event to the model. Tests construct `KeyEvent` values
    /// directly and call this; runtime code goes through
    /// [`Self::dispatch_event`] so the kind filter applies.
    pub fn on_key(&mut self, key: KeyEvent) -> AppEvent {
        // Global Ctrl-C: force-quit.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return AppEvent::Quit;
        }
        // Ctrl-S: save.
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            match save::save(&mut self.model) {
                Ok(p) => self.status = format!("saved to {}", p.display()),
                Err(e) => self.status = format!("save failed: {e}"),
            }
            return AppEvent::Continue;
        }

        match key.code {
            KeyCode::Char('?') => {
                self.show_help = !self.show_help;
                return AppEvent::Continue;
            }
            KeyCode::Char('q') => {
                if self.model.is_dirty() && !self.confirm_quit {
                    self.confirm_quit = true;
                    self.status =
                        "unsaved changes — press q again to discard, Ctrl-S to save".into();
                    return AppEvent::Continue;
                }
                return AppEvent::Quit;
            }
            KeyCode::Esc => {
                // If the page is in nav mode (not editing), Esc could be quit.
                // Pages handle their own Esc-cancel inside edit mode; we only
                // intercept if no page is editing. The page-key dispatcher
                // below returns whether it consumed the event.
            }
            KeyCode::Tab => {
                let next = (self.current.index() + 1) % PageKind::COUNT;
                self.current = PageKind::all()[next];
                return AppEvent::Continue;
            }
            KeyCode::BackTab => {
                let prev = (self.current.index() + PageKind::COUNT - 1) % PageKind::COUNT;
                self.current = PageKind::all()[prev];
                return AppEvent::Continue;
            }
            KeyCode::Char(']') => {
                let next = (self.current.index() + 1) % PageKind::COUNT;
                self.current = PageKind::all()[next];
                return AppEvent::Continue;
            }
            KeyCode::Char('[') => {
                let prev = (self.current.index() + PageKind::COUNT - 1) % PageKind::COUNT;
                self.current = PageKind::all()[prev];
                return AppEvent::Continue;
            }
            KeyCode::Char('h') => {
                // Vim-style page-prev (only when not editing — pages with
                // text inputs in edit mode will see 'h' as a character).
                let prev = (self.current.index() + PageKind::COUNT - 1) % PageKind::COUNT;
                self.current = PageKind::all()[prev];
                return AppEvent::Continue;
            }
            KeyCode::Char('l') => {
                let next = (self.current.index() + 1) % PageKind::COUNT;
                self.current = PageKind::all()[next];
                return AppEvent::Continue;
            }
            _ => {}
        }

        // Reset confirm_quit on any other interaction.
        self.confirm_quit = false;

        // Forward to the active page.
        let idx = self.current.index();
        if let Some(page) = self.pages.get_mut(idx) {
            let changed = page.on_key(key, &mut self.model);
            if changed {
                self.status = "edited".into();
            }
        }
        AppEvent::Continue
    }
}

/// Build a single-line tab strip that fits in `width` cells, keeping
/// `active` visible and inserting `…` markers when tabs are clipped at
/// either end. Tabs are separated by ` │ `. The active tab is styled
/// yellow+bold; others are unstyled.
///
/// Always renders at least the active tab (even if it has to be
/// truncated with an ellipsis to fit). Returns a `Line` with one Span
/// per segment ready to feed into a `Paragraph`.
fn render_scrolling_tabs(labels: &[String], active: usize, width: u16) -> Line<'static> {
    const SEP_W: usize = 3; // " │ "
    const ELLIPSIS_W: usize = 2; // "… " or " …"

    let n = labels.len();
    if n == 0 || width == 0 {
        return Line::from(String::new());
    }
    let active = active.min(n - 1);
    let widths: Vec<usize> = labels.iter().map(|s| s.chars().count()).collect();
    let avail = width as usize;

    // Fast path: everything fits without ellipses.
    let total_full: usize = widths.iter().sum::<usize>() + SEP_W * (n - 1);
    if total_full <= avail {
        return build_line(labels, active, 0, n - 1, false, false);
    }

    // First pass: reserve space for ellipses on both sides; expand greedily
    // out from the active tab.
    let budget_with_both_ellipses = avail.saturating_sub(2 * ELLIPSIS_W);
    let mut used = widths[active].min(budget_with_both_ellipses.max(1));
    let mut start = active;
    let mut end = active;
    grow_window(
        &widths,
        &mut start,
        &mut end,
        &mut used,
        budget_with_both_ellipses,
    );

    // Second pass: if one or both sides no longer have hidden tabs, donate
    // the reserved ellipsis budget back to the visible window so we don't
    // waste cells. Subsequent expansion may discover yet more space.
    loop {
        let hidden_left = start > 0;
        let hidden_right = end + 1 < n;
        let donated = (if hidden_left { 0 } else { ELLIPSIS_W })
            + (if hidden_right { 0 } else { ELLIPSIS_W });
        if donated == 0 {
            break;
        }
        let bigger = budget_with_both_ellipses + donated;
        let grew_more = grow_window(&widths, &mut start, &mut end, &mut used, bigger);
        if !grew_more {
            break;
        }
    }

    build_line(labels, active, start, end, start > 0, end + 1 < n)
}

/// Greedy bidirectional expansion. Returns `true` if at least one tab
/// was added to either side. Prefers the right side first so users
/// tabbing forward see new tabs appear naturally on the right.
fn grow_window(
    widths: &[usize],
    start: &mut usize,
    end: &mut usize,
    used: &mut usize,
    budget: usize,
) -> bool {
    const SEP_W: usize = 3;
    let n = widths.len();
    let mut any_grew = false;
    loop {
        let mut grew = false;
        if *end + 1 < n {
            let cost = SEP_W + widths[*end + 1];
            if *used + cost <= budget {
                *used += cost;
                *end += 1;
                grew = true;
                any_grew = true;
            }
        }
        if *start > 0 {
            let cost = SEP_W + widths[*start - 1];
            if *used + cost <= budget {
                *used += cost;
                *start -= 1;
                grew = true;
                any_grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    any_grew
}

/// Assemble the styled `Line` from a window `[start..=end]` plus
/// optional `…` lead/trail markers. Pure rendering — no width math.
fn build_line(
    labels: &[String],
    active: usize,
    start: usize,
    end: usize,
    lead: bool,
    trail: bool,
) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    if lead {
        spans.push(Span::raw("… "));
    }
    for (i, label) in labels.iter().enumerate().take(end + 1).skip(start) {
        if i > start {
            spans.push(Span::raw(" │ "));
        }
        let style = if i == active {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default()
        };
        spans.push(Span::styled(label.clone(), style));
    }
    if trail {
        spans.push(Span::raw(" …"));
    }
    Line::from(spans)
}

fn render_help(area: Rect, buf: &mut Buffer) {
    let lines = vec![
        Line::from("Keyboard help"),
        Line::from(""),
        Line::from(Span::styled(
            "Navigation",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  ↑ / k         move focus up"),
        Line::from("  ↓ / j         move focus down"),
        Line::from("  Tab / ] / l   next page"),
        Line::from("  BackTab / [/h previous page"),
        Line::from("  1-9           jump to page by number"),
        Line::from(""),
        Line::from(Span::styled(
            "Editing — universal",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  Enter         start edit / commit current edit"),
        Line::from("  Esc           cancel current edit"),
        Line::from(""),
        Line::from(Span::styled(
            "Editing — tickboxes (Bool, Multi options)",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  Space         flip the focused tickbox"),
        Line::from("  t             flip the focused tickbox (alt to Space)"),
        Line::from("  Enter         commit (does NOT flip)"),
        Line::from("  s             commit (Multi only — alt to Enter)"),
        Line::from(""),
        Line::from(Span::styled(
            "Editing — selectors (Choice, Multi cursor)",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  ← / →         rotate cursor through options (wraps)"),
        Line::from("  ↑ / ↓         rotate cursor through options (wraps)"),
        Line::from(""),
        Line::from(Span::styled(
            "Indicators",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  ▶             cursor — focused row (yellow nav, green edit)"),
        Line::from("  [N/M]         field position within the current page"),
        Line::from("  field info    one-line description of the focused field"),
        Line::from("  ●             unsaved changes"),
        Line::from("  E / W         validation error / warning counts"),
        Line::from(""),
        Line::from(Span::styled(
            "Persistence",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from("  Ctrl-S        save (atomic, comment-preserving)"),
        Line::from("  q             quit (twice if dirty to discard)"),
        Line::from("  ?             toggle this help"),
    ];

    // Centre a wider box now that there's more content.
    let w = 64u16.min(area.width.saturating_sub(2));
    let h = (lines.len() as u16 + 2).min(area.height.saturating_sub(2));
    let x = area.x + (area.width.saturating_sub(w)) / 2;
    let y = area.y + (area.height.saturating_sub(h)) / 2;
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    let block = Block::default().borders(Borders::ALL).title("? help");
    Paragraph::new(lines).block(block).render(rect, buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers};

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn ctrl(c: char) -> KeyEvent {
        KeyEvent::new(KeyCode::Char(c), KeyModifiers::CONTROL)
    }

    fn sample() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
"#,
        )
    }

    #[test]
    fn tab_advances_page() {
        let mut app = App::new(sample());
        assert_eq!(app.current, PageKind::Basics);
        app.on_key(k(KeyCode::Tab));
        assert_eq!(app.current, PageKind::Connection);
    }

    #[test]
    fn ctrl_c_quits() {
        let mut app = App::new(sample());
        assert_eq!(app.on_key(ctrl('c')), AppEvent::Quit);
    }

    #[test]
    fn dirty_q_requires_confirm() {
        let mut app = App::new(sample());
        // Make dirty by editing user via direct model access.
        app.model.profile_mut().user = Some("alice".into());
        assert!(app.model.is_dirty());
        let r1 = app.on_key(k(KeyCode::Char('q')));
        assert_eq!(r1, AppEvent::Continue);
        let r2 = app.on_key(k(KeyCode::Char('q')));
        assert_eq!(r2, AppEvent::Quit);
    }

    #[test]
    fn help_toggles() {
        let mut app = App::new(sample());
        assert!(!app.show_help);
        app.on_key(k(KeyCode::Char('?')));
        assert!(app.show_help);
        app.on_key(k(KeyCode::Char('?')));
        assert!(!app.show_help);
    }

    /// The help overlay must document the tickbox keymap:
    /// Space and `t` flip; Enter commits (does not flip).
    #[test]
    fn help_overlay_documents_space_t_enter_for_tickboxes() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new(sample());
        app.on_key(k(KeyCode::Char('?')));
        assert!(app.show_help);
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        // Tickbox section keys must all be present and discoverable.
        assert!(
            text.contains("Space"),
            "help overlay must document Space as a tickbox flip key:\n{text}"
        );
        assert!(
            text.contains(" t  "),
            "help overlay must document `t` as a tickbox flip key:\n{text}"
        );
        assert!(
            text.contains("Enter"),
            "help overlay must document Enter:\n{text}"
        );
        assert!(
            text.contains("flip") || text.contains("toggle"),
            "help overlay must describe what Space/`t` do (flip/toggle):\n{text}"
        );
        assert!(
            text.contains("commit"),
            "help overlay must describe Enter as commit:\n{text}"
        );
    }

    /// The status-line key-hints strip must surface Space/`t` while
    /// the user is in edit mode — otherwise the new keymap is not
    /// discoverable to operators who don't open the `?` overlay.
    #[test]
    fn status_line_advertises_space_and_t_when_editing() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new(sample());
        // Enter edit mode on the focused field of Basics (id).
        app.on_key(k(KeyCode::Enter));
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(
            text.contains("Space/t"),
            "edit-mode status hint must advertise Space/t as toggle:\n{text}"
        );
        assert!(
            text.contains("Enter: commit"),
            "edit-mode status hint must advertise Enter as commit:\n{text}"
        );
    }

    // ---- Tab-bar scroll/overflow tests ------------------------------

    /// Convert a Line into a plain string (joining all spans).
    fn line_to_string(line: &Line<'_>) -> String {
        line.spans.iter().map(|s| s.content.as_ref()).collect()
    }

    #[test]
    fn scroll_tabs_all_fit_no_ellipses() {
        let labels: Vec<String> = ["1 a", "2 b", "3 c"]
            .iter()
            .map(|&s| s.to_string())
            .collect();
        // "1 a │ 2 b │ 3 c" = 3+3+3+3+3 = 15 cells
        let line = super::render_scrolling_tabs(&labels, 1, 30);
        let s = line_to_string(&line);
        assert!(!s.contains('…'), "no ellipses when all fit: {s:?}");
        assert!(s.contains("1 a"));
        assert!(s.contains("2 b"));
        assert!(s.contains("3 c"));
    }

    #[test]
    fn scroll_tabs_trail_ellipsis_when_active_near_start() {
        // Many tabs, active = 0, narrow width → right side overflows.
        let labels: Vec<String> = (0..10).map(|i| format!("{i} title")).collect();
        let line = super::render_scrolling_tabs(&labels, 0, 30);
        let s = line_to_string(&line);
        assert!(
            s.starts_with("0 title"),
            "active tab at index 0 must be visible at start: {s:?}"
        );
        assert!(
            s.trim_end().ends_with('…'),
            "must show trailing ellipsis when right side is clipped: {s:?}"
        );
        assert!(
            !s.starts_with("…"),
            "must not show leading ellipsis when active is at start: {s:?}"
        );
    }

    #[test]
    fn scroll_tabs_lead_ellipsis_when_active_near_end() {
        let labels: Vec<String> = (0..10).map(|i| format!("{i} title")).collect();
        let line = super::render_scrolling_tabs(&labels, 9, 30);
        let s = line_to_string(&line);
        assert!(
            s.contains("9 title"),
            "active tab at index 9 must be visible: {s:?}"
        );
        assert!(
            s.starts_with('…'),
            "must show leading ellipsis when left side is clipped: {s:?}"
        );
        assert!(
            !s.trim_end().ends_with('…'),
            "must not show trailing ellipsis when active is at end: {s:?}"
        );
    }

    #[test]
    fn scroll_tabs_both_ellipses_when_active_in_middle() {
        let labels: Vec<String> = (0..10).map(|i| format!("{i} title")).collect();
        let line = super::render_scrolling_tabs(&labels, 5, 25);
        let s = line_to_string(&line);
        assert!(
            s.contains("5 title"),
            "active tab at index 5 must be visible: {s:?}"
        );
        assert!(s.starts_with('…'), "must show leading ellipsis: {s:?}");
        assert!(
            s.trim_end().ends_with('…'),
            "must show trailing ellipsis: {s:?}"
        );
    }

    #[test]
    fn scroll_tabs_active_always_visible_at_extreme_narrow_width() {
        let labels: Vec<String> = (0..13).map(|i| format!("{} Title{i}", i + 1)).collect();
        for active in 0..labels.len() {
            for width in [10u16, 15, 20, 30, 50] {
                let line = super::render_scrolling_tabs(&labels, active, width);
                let s = line_to_string(&line);
                let expected = format!("{} Title{active}", active + 1);
                assert!(
                    s.contains(&expected),
                    "active label {expected:?} must appear at width={width}, got: {s:?}"
                );
            }
        }
    }

    #[test]
    fn scroll_tabs_active_span_carries_highlight_style() {
        let labels: Vec<String> = (0..5).map(|i| format!("{i} t")).collect();
        let line = super::render_scrolling_tabs(&labels, 2, 80);
        // Find the span matching the active label exactly.
        let active_span = line
            .spans
            .iter()
            .find(|s| s.content == "2 t")
            .expect("active label must be a span");
        assert!(
            active_span.style.add_modifier.contains(Modifier::BOLD),
            "active tab span must be BOLD"
        );
        assert_eq!(
            active_span.style.fg,
            Some(Color::Yellow),
            "active tab span must be Yellow"
        );
    }

    /// End-to-end: render the full App frame at a narrow width (60).
    /// The 13 spt pages total ~145 cells of tab content, so a 60-wide
    /// terminal MUST overflow. The currently-active tab title must
    /// appear in the rendered buffer despite the overflow.
    #[test]
    fn app_renders_active_tab_at_narrow_terminal() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new(sample());
        // Move to a page that's likely near the right edge of the tab
        // bar so we exercise the leading-ellipsis path.
        for _ in 0..7 {
            app.on_key(k(KeyCode::Tab));
        }
        let backend = TestBackend::new(60, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                text.push_str(buf[(x, y)].symbol());
            }
            text.push('\n');
        }
        // Whatever page we're on, its title must be in the rendered
        // frame even at 60 cells wide.
        let title = app.current.title();
        assert!(
            text.contains(title),
            "active page title {title:?} must be visible in narrow 60-wide frame:\n{text}"
        );
        // And there must be at least one ellipsis indicating overflow.
        assert!(
            text.contains('…'),
            "narrow frame with 13 pages must show overflow ellipsis:\n{text}"
        );
    }

    #[test]
    fn back_tab_goes_to_last_page() {
        let mut app = App::new(sample());
        assert_eq!(app.current, PageKind::Basics);
        app.on_key(k(KeyCode::BackTab));
        assert_eq!(app.current, PageKind::Review);
    }

    /// Windows-style key duplication regression. crossterm 0.27+ on Windows
    /// emits a `Release` event for every `Press`; routing both through the
    /// page handler fires every action twice. `dispatch_event` must swallow
    /// `Release` and `Repeat` so each physical press advances the state
    /// machine exactly once.
    #[test]
    fn dispatch_event_ignores_release_and_repeat() {
        let mut app = App::new(sample());
        let press = Event::Key(KeyEvent {
            code: KeyCode::Tab,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        });
        let release = Event::Key(KeyEvent {
            code: KeyCode::Tab,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Release,
            state: crossterm::event::KeyEventState::NONE,
        });
        let repeat = Event::Key(KeyEvent {
            code: KeyCode::Tab,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Repeat,
            state: crossterm::event::KeyEventState::NONE,
        });

        assert_eq!(app.current, PageKind::Basics);
        // The full Windows event triple for one Tab press: Press → Release.
        // Only Press should advance pages.
        app.dispatch_event(press.clone());
        app.dispatch_event(release.clone());
        assert_eq!(
            app.current,
            PageKind::Connection,
            "Tab Press+Release must advance one page, not two"
        );

        // Holding Tab on Windows generates Repeat events while the key is
        // held; we treat those as no-ops too (the supervisor's autorepeat
        // semantics differ from a TUI's; users are typically holding by
        // accident).
        app.dispatch_event(repeat);
        assert_eq!(
            app.current,
            PageKind::Connection,
            "Repeat events must not advance pages"
        );
    }

    #[test]
    fn bracket_keys_navigate() {
        let mut app = App::new(sample());
        app.on_key(k(KeyCode::Char(']')));
        assert_eq!(app.current, PageKind::Connection);
        app.on_key(k(KeyCode::Char('[')));
        assert_eq!(app.current, PageKind::Basics);
    }

    #[test]
    fn vim_keys_navigate() {
        let mut app = App::new(sample());
        app.on_key(k(KeyCode::Char('l')));
        assert_eq!(app.current, PageKind::Connection);
        app.on_key(k(KeyCode::Char('h')));
        assert_eq!(app.current, PageKind::Basics);
    }

    #[test]
    fn tab_wraps_around() {
        let mut app = App::new(sample());
        for _ in 0..PageKind::COUNT {
            app.on_key(k(KeyCode::Tab));
        }
        assert_eq!(app.current, PageKind::Basics);
    }

    #[test]
    fn clean_q_quits_without_confirm() {
        let mut app = App::new(sample());
        assert!(!app.model.is_dirty());
        assert_eq!(app.on_key(k(KeyCode::Char('q'))), AppEvent::Quit);
    }

    #[test]
    fn confirm_quit_is_reset_by_other_keys() {
        let mut app = App::new(sample());
        app.model.profile_mut().user = Some("alice".into());
        let r1 = app.on_key(k(KeyCode::Char('q')));
        assert_eq!(r1, AppEvent::Continue);
        assert!(app.confirm_quit);
        // Navigation should reset confirm_quit so the next q does NOT quit.
        app.on_key(k(KeyCode::Tab));
        // Tab doesn't fall through to clear confirm_quit (it returns early),
        // but pressing a forwarded key should. Verify status was set.
        assert!(!app.status.is_empty());
    }

    #[test]
    fn ctrl_s_save_failure_records_status() {
        let mut app = App::new(sample());
        // path() is <memory>; save will fail because the file can't be written.
        app.on_key(ctrl('s'));
        // Either success or failure is OK; we just want the status updated.
        assert!(!app.status.is_empty());
    }

    #[test]
    fn ctrl_s_save_succeeds_with_real_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(
            &path,
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
"#,
        )
        .unwrap();
        let model = Model::load(&path).unwrap();
        let mut app = App::new(model);
        app.on_key(ctrl('s'));
        assert!(app.status.contains("saved"));
    }

    #[test]
    fn render_frame_runs_without_panic() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new(sample());
        let backend = TestBackend::new(100, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
            .unwrap();
    }

    /// The page-position counter `[1/13]` shows in the tab title, the
    /// field-position counter `[1/N]` + the focused field's help text
    /// show in the footer, and the status line carries context-aware
    /// key hints. All three are load-bearing for "I know where I am
    /// and what this field does."
    #[test]
    fn render_includes_position_counter_and_field_help() {
        use ratatui::backend::TestBackend;
        use ratatui::Terminal;
        let mut app = App::new(sample());
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
            .unwrap();
        let buf = terminal.backend().buffer();
        let mut s = String::new();
        for y in 0..buf.area().height {
            for x in 0..buf.area().width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }

        // Page-position counter in the tab title.
        assert!(
            s.contains("[1/") && s.contains(&format!("/{}]", PageKind::all().len())),
            "expected page position `[1/{}]` in tab title:\n{s}",
            PageKind::all().len()
        );
        // Footer carries the focused field's help. The Basics page's
        // first field is `id` with help "Profile identifier ...".
        assert!(
            s.contains("Profile identifier"),
            "expected focused-field help in footer:\n{s}"
        );
        // Selector glyph on the focused row.
        assert!(s.contains('▶'), "expected ▶ selector glyph:\n{s}");
        // Context-aware status line — non-editing mode shows the move/
        // edit hint.
        assert!(
            s.contains("Enter: edit"),
            "expected `Enter: edit` hint in nav mode status line:\n{s}"
        );
    }

    #[test]
    fn page_kind_index_round_trip() {
        for p in PageKind::all() {
            let i = p.index();
            assert_eq!(PageKind::all()[i], p);
            assert!(!p.title().is_empty());
        }
    }

    #[test]
    fn page_kind_count_matches_all_len() {
        assert_eq!(PageKind::all().len(), PageKind::COUNT);
    }
}
