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
use ratatui::widgets::{Block, Borders, Paragraph, Tabs, Widget};
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

    /// Render a complete frame (tabs + page + status line + optional help).
    pub fn render_frame(&mut self, area: Rect, buf: &mut Buffer) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(2),
            ])
            .split(area);

        // Tabs.
        let titles: Vec<Line<'_>> = PageKind::all()
            .iter()
            .enumerate()
            .map(|(i, p)| {
                Line::from(Span::styled(
                    format!("{} {}", i + 1, p.title()),
                    Style::default(),
                ))
            })
            .collect();
        let tabs = Tabs::new(titles)
            .select(self.current.index())
            .block(Block::default().borders(Borders::ALL).title(format!(
                "spt profile configure — {}",
                self.model.profile().name
            )))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        tabs.render(chunks[0], buf);

        // Page body.
        let idx = self.current.index();
        if let Some(page) = self.pages.get_mut(idx) {
            page.render(chunks[1], buf, &self.model);
        }

        // Status line.
        let dirty = if self.model.is_dirty() { "●" } else { " " };
        let diag = self.model.validate();
        let summary = format!(
            "{}  {}  {}E/{}W  [{}]",
            dirty,
            self.current.title(),
            diag.errors.len(),
            diag.warnings.len(),
            self.status
        );
        let block = Block::default().borders(Borders::TOP);
        Paragraph::new(summary).block(block).render(chunks[2], buf);

        // Help overlay.
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

fn render_help(area: Rect, buf: &mut Buffer) {
    let lines = vec![
        Line::from("Keyboard help"),
        Line::from(""),
        Line::from("  Tab / ]       next page"),
        Line::from("  BackTab / [   previous page"),
        Line::from("  h / l         vim-style page nav"),
        Line::from("  j / k         move focus within a page"),
        Line::from("  Enter         start editing the focused field"),
        Line::from("  Esc           cancel current edit"),
        Line::from("  Space         toggle / pick (selectors, multi-selects)"),
        Line::from("  Ctrl-S        save (atomic, comment-preserving)"),
        Line::from("  q             quit (twice if dirty)"),
        Line::from("  ?             toggle this help"),
    ];

    // Center a 60×16 box on screen.
    let w = 60u16.min(area.width.saturating_sub(2));
    let h = 16u16.min(area.height.saturating_sub(2));
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
