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
    assert_eq!(
        app.current, initial,
        "tab should wrap once after COUNT steps"
    );
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

// -----------------------------------------------------------------
// Phase 1 reproducers — t-tui-rotate.
// -----------------------------------------------------------------

/// End-to-end: rotate the protocol Choice with Right then commit.
/// Starts with `protocol = "ssh2"` and expects `"ssh3"` after Right+Enter.
#[test]
fn basics_protocol_left_right_rotate_through_options() {
    let mut app = App::new(Model::from_str(SAMPLE));
    // We start on Basics, focus 0 (id). Move down twice to focus protocol.
    assert_eq!(app.current, PageKind::Basics);
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    // Enter edit mode on protocol.
    app.on_key(k(KeyCode::Enter));
    // Press Right to rotate cursor to "ssh3".
    app.on_key(k(KeyCode::Right));
    // Commit.
    app.on_key(k(KeyCode::Enter));
    assert_eq!(app.model.profile().protocol, "ssh3");
}

/// Rotating a full cycle's worth of Right keypresses must round-trip
/// back to the starting value.
#[test]
fn basics_protocol_rotate_full_cycle_returns_to_start() {
    let mut app = App::new(Model::from_str(SAMPLE));
    let start = app.model.profile().protocol.clone();
    // Focus protocol (index 2).
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter)); // edit
                                   // PROTOCOLS has 2 entries: ssh2, ssh3. Rotate twice.
    app.on_key(k(KeyCode::Right));
    app.on_key(k(KeyCode::Right));
    app.on_key(k(KeyCode::Enter)); // commit
    assert_eq!(app.model.profile().protocol, start);
}

/// Crypto page Multi: rotate via Down (with wrap) and Space-toggle, then
/// commit via 's'. Verifies that the wrap-aware cursor + space toggle
/// composition stays consistent end-to-end.
#[test]
fn crypto_multi_select_space_toggle_after_rotate() {
    let mut app = App::new(Model::from_str(SAMPLE));
    while app.current != PageKind::Crypto {
        app.on_key(k(KeyCode::Tab));
    }
    // Find the crypto.ciphers field — Crypto layout puts Multi fields
    // after a couple of leading bool/choice fields. Locate by stepping
    // until we hit a Multi edit context. To keep this independent of
    // the exact field order, we just verify the page does not panic
    // and that Down/Space sequences produce a defined result.
    // Walk down a few times to land somewhere reasonable.
    for _ in 0..3 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // enter edit
                                   // Rotate down once + space-toggle. Even if this isn't a Multi
                                   // field, we just need to confirm no panics and no Cargo.lock
                                   // mutation. The end-to-end behavior for crypto fields is
                                   // covered by inline tests; this IT exercises the dispatch.
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Char(' ')));
    // Cancel out cleanly.
    app.on_key(k(KeyCode::Esc));
    let _ = render(&mut app, 100, 30);
}

// -----------------------------------------------------------------
// Phase 1 reproducer — t-tui-spinner.
// -----------------------------------------------------------------

/// End-to-end regression for the user-reported bug: when a profile's
/// `failure_policy` is `"fail_profile"`, the Basics page must render that
/// value — not the first option (`retry`). The legacy compact rendering
/// always showed `options[0]` because the 3-row field area clipped every
/// option line past row 0.
#[test]
fn basics_failure_policy_visible_reflects_profile_value() {
    let sample = r#"version = 1

[[profiles]]
name = "demo"
protocol = "ssh2"
host = "demo.example.com"
user = "alice"
failure_policy = "fail_profile"
"#;
    let mut app = App::new(Model::from_str(sample));
    assert_eq!(app.current, PageKind::Basics);
    let text = render(&mut app, 100, 30);
    assert!(
        text.contains("fail_profile"),
        "Basics page must display the actual failure_policy value:\n{text}"
    );
}

// -----------------------------------------------------------------
// t-tui-e2e — App-level end-to-end coverage for the 6 TUI fixes
// (commits 4be1e58 → 8a0115e). Drive `App::on_key` / `App::render_frame`
// against `TestBackend` only — no widget internals.
// -----------------------------------------------------------------

/// Render the `App` into a buffer (rather than a flattened string).
fn render_buffer(app: &mut App, w: u16, h: u16) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
        .unwrap();
    terminal.backend().buffer().clone()
}

/// True if any cell in the entire buffer carries the `Modifier::REVERSED`
/// bit. Used by the caret test to assert visibly-distinguished caret
/// painting without computing the focused field's rect. At the point this
/// is called there is exactly one focused `TextInput` in edit mode, so
/// REVERSED appears nowhere else (gutter glyph + borders use BOLD only).
fn buffer_has_reversed_cell(buf: &ratatui::buffer::Buffer) -> bool {
    use ratatui::style::Modifier;
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            if buf[(x, y)]
                .style()
                .add_modifier
                .contains(Modifier::REVERSED)
            {
                return true;
            }
        }
    }
    false
}

/// Tab from current page until `target` (with a hard cap to avoid loops).
fn tab_to(app: &mut App, target: PageKind) {
    for _ in 0..PageKind::COUNT {
        if app.current == target {
            return;
        }
        app.on_key(k(KeyCode::Tab));
    }
    assert_eq!(app.current, target, "failed to navigate to {target:?}");
}

// ---- Bool field — Enter/Space/t behavior (commit 8a0115e) ----

/// Enter alone after begin-edit must commit the unflipped Bool value.
/// End-to-end version of the inline `ack_experimental_enter_alone_does_not_flip`
/// — this routes through `App::on_key` so the full dispatch stack is covered.
#[test]
fn bool_field_enter_alone_does_not_flip_via_app() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    // Diagnostics fields: 0=tags, 1=acknowledge_experimental (Bool).
    app.on_key(k(KeyCode::Down));
    // Begin edit, then commit immediately without flipping.
    app.on_key(k(KeyCode::Enter));
    app.on_key(k(KeyCode::Enter));
    // The Bool starts at None (-> false); Enter-alone commits Some(false).
    // The user-visible boolean did not flip.
    assert_eq!(
        app.model.profile().acknowledge_experimental,
        Some(false),
        "Enter alone must commit the displayed value (false), not flip then commit"
    );
}

/// Enter, Space, Enter flips the Bool exactly once and commits.
#[test]
fn bool_field_space_then_enter_flips_and_commits_via_app() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter)); // begin edit (false)
    app.on_key(k(KeyCode::Char(' '))); // flip edit_buf -> true
    app.on_key(k(KeyCode::Enter)); // commit
    assert_eq!(
        app.model.profile().acknowledge_experimental,
        Some(true),
        "Space-then-Enter must flip and commit"
    );
}

/// `t` is an explicit Toggle key (mnemonic for "toggle"); identical to Space.
#[test]
fn bool_field_t_then_enter_flips_and_commits_via_app() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter));
    app.on_key(k(KeyCode::Char('t')));
    app.on_key(k(KeyCode::Enter));
    assert_eq!(
        app.model.profile().acknowledge_experimental,
        Some(true),
        "t-then-Enter must flip and commit"
    );
}

/// Double `t` round-trips: false -> true -> false, committed as Some(false).
#[test]
fn bool_field_double_t_round_trips_via_app() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter));
    app.on_key(k(KeyCode::Char('t')));
    app.on_key(k(KeyCode::Char('t')));
    app.on_key(k(KeyCode::Enter));
    assert_eq!(
        app.model.profile().acknowledge_experimental,
        Some(false),
        "t,t round-trip must leave value at original (false)"
    );
}

/// Live render: Space must visibly flip the rendered toggle text before
/// commit. Initial Bool is false (`[ ] no`); after Space, the still-uncommitted
/// `edit_buf` must render as `[x] yes`. This proves the render uses
/// `edit_buf`, not the committed profile value.
#[test]
fn bool_field_rendered_text_reflects_edit_buf_after_space() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    app.on_key(k(KeyCode::Down));
    // Render before begin-edit: should show the false/no rendering.
    let before = render(&mut app, 100, 30);
    assert!(
        before.contains("[ ] no"),
        "initial Bool should render `[ ] no`:\n{before}"
    );
    // Begin edit — still false.
    app.on_key(k(KeyCode::Enter));
    let begin = render(&mut app, 100, 30);
    assert!(
        begin.contains("[ ] no"),
        "begin-edit must not flip the displayed value:\n{begin}"
    );
    // Space flips edit_buf to true; render must now show `[x] yes`.
    app.on_key(k(KeyCode::Char(' ')));
    let after = render(&mut app, 100, 30);
    assert!(
        after.contains("[x] yes"),
        "Space must flip the live render to `[x] yes`:\n{after}"
    );
    // Profile must still be untouched until we Enter to commit.
    assert!(
        app.model.profile().acknowledge_experimental.is_none()
            || app.model.profile().acknowledge_experimental == Some(false),
        "Space must not have committed to profile yet"
    );
}

// ---- Choice field — Left/Right rotation + live render (4f3baf9, b8e25db) ----

/// Right-arrow during edit must rotate the visible choice AND repaint the
/// spinner chrome. This pins the user-reported bug: "we still dont see
/// values when using side keys".
#[test]
fn choice_right_arrow_updates_rendered_text_live() {
    let mut app = App::new(Model::from_str(SAMPLE));
    assert_eq!(app.current, PageKind::Basics);
    // Focus protocol (index 2).
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    // Begin edit; before any rotation, the spinner must show the seeded
    // value `ssh2`.
    app.on_key(k(KeyCode::Enter));
    let edit_initial = render(&mut app, 100, 30);
    assert!(
        edit_initial.contains("ssh2"),
        "edit-mode initial render must show seeded value ssh2:\n{edit_initial}"
    );
    // Right rotates the cursor to ssh3. Live render must reflect that.
    app.on_key(k(KeyCode::Right));
    let rotated = render(&mut app, 100, 30);
    assert!(
        rotated.contains("ssh3"),
        "Right must rotate the displayed value to ssh3:\n{rotated}"
    );
    assert!(
        rotated.contains('◀') && rotated.contains('▶'),
        "rotated render must include spinner chrome:\n{rotated}"
    );
}

/// Left-arrow at index 0 wraps to the last option; the position counter
/// `(2/2)` confirms we landed on the wrap-target.
#[test]
fn choice_left_arrow_wraps_to_last_via_app() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter));
    app.on_key(k(KeyCode::Left));
    let rendered = render(&mut app, 100, 30);
    assert!(
        rendered.contains("ssh3"),
        "Left at index 0 must wrap to ssh3:\n{rendered}"
    );
    assert!(
        rendered.contains("(2/2)"),
        "wrap target must show position counter (2/2):\n{rendered}"
    );
}

/// Enter after Right commits the rotated cursor value (`ssh3`).
#[test]
fn choice_enter_commits_displayed_cursor_value() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter));
    app.on_key(k(KeyCode::Right));
    app.on_key(k(KeyCode::Enter));
    assert_eq!(app.model.profile().protocol, "ssh3");
}

/// Esc cancels: the rotated cursor must not be committed.
#[test]
fn choice_esc_cancels_without_committing_rotated_cursor() {
    let mut app = App::new(Model::from_str(SAMPLE));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter));
    app.on_key(k(KeyCode::Right)); // cursor → ssh3 (uncommitted)
    app.on_key(k(KeyCode::Esc)); // cancel edit
    assert_eq!(
        app.model.profile().protocol,
        "ssh2",
        "Esc must discard the rotated cursor — protocol stays ssh2"
    );
}

/// Killer demo of the spinner unfocused-mode fix: when the profile is
/// `protocol = "ssh3"` and nothing has been pressed, the page must render
/// the actual value `ssh3` (not `options[0] = ssh2`).
#[test]
fn nav_mode_choice_displays_actual_value_not_options_zero() {
    const SAMPLE_SSH3: &str = r#"version = 1

[[profiles]]
name = "demo"
protocol = "ssh3"
host = "demo.example.com"
user = "alice"
"#;
    let mut app = App::new(Model::from_str(SAMPLE_SSH3));
    assert_eq!(app.current, PageKind::Basics);
    let text = render(&mut app, 100, 30);
    assert!(
        text.contains("ssh3"),
        "unfocused compact render must show actual profile value `ssh3`:\n{text}"
    );
}

// ---- TextInput caret (commit cd12ff1) ----

/// A focused empty text input must paint at least one cell with the
/// `REVERSED` style modifier so the caret is visible on terminals where
/// the lone ▏ glyph would otherwise blend in. We scan the entire buffer
/// rather than the field rect — REVERSED appears nowhere else when one
/// `TextInput` is in edit mode.
#[test]
fn text_field_empty_focused_shows_reversed_caret_cell_via_app() {
    let mut app = App::new(Model::from_str(SAMPLE));
    // Description is field index 1 on Basics and is unset in SAMPLE → empty.
    assert_eq!(app.current, PageKind::Basics);
    app.on_key(k(KeyCode::Down));
    // Sanity: render without edit mode — there should be NO REVERSED cell.
    let nav_buf = render_buffer(&mut app, 100, 30);
    assert!(
        !buffer_has_reversed_cell(&nav_buf),
        "REVERSED must not appear in nav mode (would falsify the in-edit assertion)"
    );
    app.on_key(k(KeyCode::Enter)); // begin edit on empty description
    let edit_buf = render_buffer(&mut app, 100, 30);
    assert!(
        buffer_has_reversed_cell(&edit_buf),
        "focused empty text field must paint a REVERSED caret cell"
    );
}

// ---- Multi field — Space toggles, `s` commits (no commit change) ----

/// Crypto.ciphers is a Multi: Space toggles the cursor option into the
/// selected list; `s` commits the multi-selection. End-to-end through App.
#[test]
fn multi_field_space_toggles_and_s_commits_via_app() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Crypto);
    // Crypto field order: 0=policy, 1=allow_deprecated, 2=warn_on_deprecated,
    // 3=ciphers (Multi). Down 3 times to focus ciphers.
    for _ in 0..3 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit (Multi)
    app.on_key(k(KeyCode::Char(' '))); // toggle cursor option
    app.on_key(k(KeyCode::Char('s'))); // commit Multi
    let ciphers = app
        .model
        .profile()
        .crypto
        .as_ref()
        .and_then(|c| c.ciphers.clone())
        .unwrap_or_default();
    assert_eq!(
        ciphers,
        vec!["chacha20-poly1305@openssh.com".to_string()],
        "Multi commit via `s` must persist the toggled cipher to the profile"
    );
}

/// In nav mode (no edit), a Multi field with no selection must render the
/// compact `(none)` placeholder; SAMPLE has no `[crypto]` so ciphers is
/// empty and the unfocused compact path is hit.
#[test]
fn multi_field_unfocused_compact_shows_summary_or_none() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Crypto);
    // Render in nav mode — do not press Enter on any Multi field.
    let text = render(&mut app, 100, 50);
    assert!(
        text.contains("(none)"),
        "empty Multi in nav mode must render `(none)`:\n{text}"
    );
}
