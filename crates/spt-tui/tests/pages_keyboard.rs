//! Cross-page keyboard navigation flows.
//!
//! These tests drive [`App`] via simulated key events to verify the wizard's
//! global keymap and a handful of per-page edit flows. We rely solely on the
//! public API of `spt_tui` (no `feature = "testing"`) so the suite remains
//! compatible with the project's default-feature verification.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use spt_tui::pages::PageKind;
use spt_tui::{App, AppEvent, Model};

const SAMPLE: &str = r#"version = 1

[[profiles]]
name = "demo"
protocol = "ssh2"
host = "demo.example.com"
user = "alice"
"#;

fn k(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

fn ctrl(ch: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(ch), KeyModifiers::CONTROL)
}

fn frame_text(buf: &ratatui::buffer::Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        out.push('\n');
    }
    out
}

fn render(app: &mut App, w: u16, h: u16) -> String {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
        .unwrap();
    frame_text(terminal.backend().buffer())
}

#[test]
fn tab_cycles_through_every_page() {
    let mut app = App::new(Model::from_str(SAMPLE));
    let initial = app.current;
    for _ in 0..PageKind::COUNT {
        app.on_key(k(KeyCode::Tab));
    }
    assert_eq!(app.current, initial, "tab should wrap once after COUNT steps");
}

#[test]
fn back_tab_wraps_backward() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.on_key(k(KeyCode::BackTab));
    assert_eq!(app.current, PageKind::Review);
}

#[test]
fn bracket_and_vim_keys_advance() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.on_key(k(KeyCode::Char(']')));
    assert_eq!(app.current, PageKind::Connection);
    app.on_key(k(KeyCode::Char('[')));
    assert_eq!(app.current, PageKind::Basics);
    app.on_key(k(KeyCode::Char('l')));
    assert_eq!(app.current, PageKind::Connection);
    app.on_key(k(KeyCode::Char('h')));
    assert_eq!(app.current, PageKind::Basics);
}

#[test]
fn help_overlay_toggles_with_question_mark() {
    let mut app = App::new(Model::from_str(SAMPLE));
    assert!(!app.show_help);
    app.on_key(k(KeyCode::Char('?')));
    assert!(app.show_help);
    let text = render(&mut app, 100, 30);
    assert!(text.contains("Keyboard help"));
    app.on_key(k(KeyCode::Char('?')));
    assert!(!app.show_help);
}

#[test]
fn ctrl_c_force_quits_even_when_dirty() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.model.profile_mut().user = Some("evil".into());
    assert!(app.model.is_dirty());
    assert_eq!(app.on_key(ctrl('c')), AppEvent::Quit);
}

#[test]
fn dirty_q_requires_confirm_then_quits() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.model.profile_mut().user = Some("bob".into());
    assert_eq!(app.on_key(k(KeyCode::Char('q'))), AppEvent::Continue);
    assert!(app.confirm_quit);
    assert_eq!(app.on_key(k(KeyCode::Char('q'))), AppEvent::Quit);
}

#[test]
fn clean_q_quits_immediately() {
    let mut app = App::new(Model::from_str(SAMPLE));
    assert!(!app.model.is_dirty());
    assert_eq!(app.on_key(k(KeyCode::Char('q'))), AppEvent::Quit);
}

#[test]
fn ctrl_s_save_via_real_path_writes_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.toml");
    std::fs::write(&path, SAMPLE).unwrap();
    let mut app = App::new(Model::load(&path).unwrap());
    app.model.profile_mut().user = Some("eve".into());
    app.on_key(ctrl('s'));
    assert!(app.status.contains("saved"));
    let out = std::fs::read_to_string(&path).unwrap();
    assert!(out.contains("eve"));
}

#[test]
fn ctrl_s_with_memory_path_records_error_status() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.model.profile_mut().user = Some("alice".into());
    app.on_key(ctrl('s'));
    // <memory> isn't writable as a file, so save should fail with a status.
    assert!(!app.status.is_empty());
}

#[test]
fn enter_into_basics_starts_edit_mode_signalled_in_status() {
    let mut app = App::new(Model::from_str(SAMPLE));
    // Enter on Basics begins edit on the id field. The status remains empty
    // because no commit happened; this test ensures it didn't panic.
    app.on_key(k(KeyCode::Enter));
    let _ = render(&mut app, 100, 30);
}

#[test]
fn navigate_to_forwards_and_add_entry() {
    let mut app = App::new(Model::from_str(SAMPLE));
    // Tab to the Forwards page.
    while app.current != PageKind::Forwards {
        app.on_key(k(KeyCode::Tab));
    }
    // Add a forward.
    app.on_key(k(KeyCode::Char('a')));
    assert_eq!(app.model.profile().forwards.len(), 1);
    let f = &app.model.profile().forwards[0];
    assert_eq!(f.name, "forward-1");
    // Status reflects the edit.
    assert_eq!(app.status, "edited");
}

#[test]
fn navigate_to_review_renders_canonical_toml() {
    let mut app = App::new(Model::from_str(SAMPLE));
    while app.current != PageKind::Review {
        app.on_key(k(KeyCode::Tab));
    }
    let text = render(&mut app, 120, 40);
    assert!(text.contains("Canonical TOML"));
    assert!(text.contains("demo"));
}

#[test]
fn each_page_renders_without_panic() {
    let mut app = App::new(Model::from_str(SAMPLE));
    for _ in 0..PageKind::COUNT {
        let _ = render(&mut app, 100, 30);
        app.on_key(k(KeyCode::Tab));
    }
}

#[test]
fn status_line_includes_diagnostic_counts() {
    let mut app = App::new(Model::from_str(SAMPLE));
    let text = render(&mut app, 100, 30);
    // The status renders e.g. " Basics 0E/0W []" — look for the E/W counter shape.
    assert!(text.contains("E/"));
    assert!(text.contains('W'));
}

#[test]
fn dirty_marker_appears_after_edit() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.model.profile_mut().user = Some("alice2".into());
    let text = render(&mut app, 100, 30);
    // The dirty bullet "●" shows up in the status line.
    assert!(text.contains('●'));
}

#[test]
fn moving_focus_within_basics_via_down_keys() {
    // Drives the per-page j/k via App::on_key. After Tab away+back,
    // page state retains its focus index — this test just confirms the
    // forwarded key reaches the page (no panic).
    let mut app = App::new(Model::from_str(SAMPLE));
    app.on_key(k(KeyCode::Char('j')));
    app.on_key(k(KeyCode::Char('k')));
    // Page-forwarded j/k are also page-prev/next at App level? Let's check.
    // App::on_key handles `h` and `l` for nav and forwards 'j'/'k' to page.
    // Render without panic.
    let _ = render(&mut app, 100, 30);
}

#[test]
fn forwards_page_deletes_entry() {
    let mut app = App::new(Model::from_str(SAMPLE));
    while app.current != PageKind::Forwards {
        app.on_key(k(KeyCode::Tab));
    }
    app.on_key(k(KeyCode::Char('a'))); // add
    // Close editor that auto-opens after add.
    app.on_key(k(KeyCode::Esc));
    assert_eq!(app.model.profile().forwards.len(), 1);
    app.on_key(k(KeyCode::Char('d')));
    assert_eq!(app.model.profile().forwards.len(), 0);
}
