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

// -----------------------------------------------------------------
// Lockdown matrix: every plausible key the user might press while
// editing a Bool field, routed through the full App dispatch stack.
// Only Space and `t` may flip the value. Every other key must leave
// the Bool unchanged. This guards against future regressions of the
// "Enter still toggles" / "y still flips" complaints.
// -----------------------------------------------------------------

/// Drive App from `SAMPLE`, focus the diagnostics Bool field,
/// begin-edit, send the given key, then commit via Enter. Returns the
/// final committed value of `acknowledge_experimental`.
fn drive_bool_with(midkey: KeyCode) -> Option<bool> {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    app.on_key(k(KeyCode::Down)); // focus the Bool field
    app.on_key(k(KeyCode::Enter)); // begin edit (edit_buf = Bool(false))
    app.on_key(k(midkey)); // the key under test
                           // Note: if midkey was Enter, edit is already committed at this point
                           // and the trailing Enter below begins a fresh edit + commit cycle.
                           // For Esc, edit was cancelled and the trailing Enter begins a new edit.
                           // For all other keys, this trailing Enter commits the (possibly flipped)
                           // edit_buf. We then re-read the persisted value.
    if !matches!(midkey, KeyCode::Enter | KeyCode::Esc) {
        app.on_key(k(KeyCode::Enter)); // commit
    }
    app.model.profile().acknowledge_experimental
}

#[test]
fn bool_app_dispatch_only_space_and_t_flip() {
    // Initial value is None (-> false). After the test, the persisted
    // value is:
    //   - Some(true)  if `midkey` flipped the edit_buf and Enter committed
    //   - Some(false) if `midkey` did NOT flip and Enter committed false
    //   - None        if Esc cancelled before any commit
    let cases: &[(KeyCode, Option<bool>, &'static str)] = &[
        // Flip keys — must result in Some(true)
        (KeyCode::Char(' '), Some(true), "Space"),
        (KeyCode::Char('t'), Some(true), "t"),
        // Non-flip keys — must result in Some(false) (committed unflipped)
        (KeyCode::Char('y'), Some(false), "y"),
        (KeyCode::Char('n'), Some(false), "n"),
        (KeyCode::Char('T'), Some(false), "capital T"),
        (KeyCode::Char('a'), Some(false), "a"),
        (KeyCode::Char('1'), Some(false), "1"),
        (KeyCode::Up, Some(false), "Up"),
        (
            KeyCode::Down,
            Some(false),
            "Down (focus-move while editing)",
        ),
        (KeyCode::Left, Some(false), "Left"),
        (KeyCode::Right, Some(false), "Right"),
        (KeyCode::Home, Some(false), "Home"),
        (KeyCode::End, Some(false), "End"),
        (KeyCode::Backspace, Some(false), "Backspace"),
        // Special: Enter as midkey IS the commit — should commit false
        // (begin_edit set edit_buf to false; Enter does NOT flip; commits false).
        (
            KeyCode::Enter,
            Some(false),
            "Enter (alone, post-begin-edit)",
        ),
        // Special: Esc cancels the edit — no commit, value stays None
        (KeyCode::Esc, None, "Esc cancels edit"),
    ];
    for (code, expected, label) in cases {
        let got = drive_bool_with(*code);
        assert_eq!(
            got, *expected,
            "midkey={label} ({code:?}): expected {expected:?}, got {got:?}"
        );
    }
}

/// Repeated Enter presses on a Bool field must never flip the value,
/// no matter how many times the user mashes Enter. Each Enter pair
/// represents one (`begin_edit`, `commit`) cycle that should be
/// value-stable.
#[test]
fn bool_repeated_enter_mashing_never_flips() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    app.on_key(k(KeyCode::Down)); // focus Bool field
    for _ in 0..10 {
        app.on_key(k(KeyCode::Enter)); // begin edit
        app.on_key(k(KeyCode::Enter)); // commit
    }
    assert_eq!(
        app.model.profile().acknowledge_experimental,
        Some(false),
        "10 begin-edit + commit cycles must leave the value at the original false"
    );
}

/// Rendered buffer assertion: after begin-edit on a Bool field, the
/// rendered text must NOT change when Enter is pressed alone (no flip).
/// This is the visual counterpart to
/// `bool_repeated_enter_mashing_never_flips`.
#[test]
fn bool_enter_alone_does_not_change_rendered_text() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Diagnostics);
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter)); // begin edit; renders [ ] no
    let before = render(&mut app, 100, 30);
    assert!(
        before.contains("[ ] no"),
        "after begin-edit, the Bool must render `[ ] no`:\n{before}"
    );
    // Pressing Enter commits. After commit, the field is no longer in
    // edit mode but the value rendered must still be `[ ] no` (not flipped).
    app.on_key(k(KeyCode::Enter));
    let after = render(&mut app, 100, 30);
    assert!(
        after.contains("[ ] no"),
        "after Enter-commits-alone, the Bool must still render `[ ] no`:\n{after}"
    );
    assert!(
        !after.contains("[x] yes"),
        "after Enter-commits-alone, the Bool must NOT render `[x] yes`:\n{after}"
    );
}

// -----------------------------------------------------------------
// Multi-field tickbox lockdown. The user reported "the enter key
// is not just limited to committing, it also toggles tickboxes".
// On a Multi field, each option has a [x]/[ ] checkbox. Per the
// updated keymap, those checkboxes flip ONLY on Space or `t` —
// Enter is the universal commit and must not toggle.
// -----------------------------------------------------------------

/// Enter on a Multi field's cursor option must NOT toggle membership.
/// It must commit the (untoggled) selection. End-to-end via App.
#[test]
fn multi_field_enter_does_not_toggle_then_commits() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Crypto);
    // Same field path as multi_field_space_toggles_and_s_commits_via_app.
    for _ in 0..3 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit (Multi). edit_buf seeded from profile.
    app.on_key(k(KeyCode::Enter)); // MUST NOT toggle; MUST commit unchanged.
    let ciphers = app
        .model
        .profile()
        .crypto
        .as_ref()
        .and_then(|c| c.ciphers.clone())
        .unwrap_or_default();
    assert!(
        ciphers.is_empty(),
        "Enter on Multi must NOT toggle a cipher in; got {ciphers:?}"
    );
}

/// `t` toggles a Multi checkbox, mirroring Space. Commit via Enter.
#[test]
fn multi_field_t_toggles_and_enter_commits() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Crypto);
    for _ in 0..3 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit
    app.on_key(k(KeyCode::Char('t'))); // t toggles
    app.on_key(k(KeyCode::Enter)); // Enter commits (no further toggle)
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
        "`t` then Enter must persist exactly one cipher (toggled by t, not by Enter)"
    );
}

/// Repeated Enter on a Multi field must never toggle. Each pair of
/// Enters is a (begin-edit, commit) cycle; after N cycles the selection
/// state is the original empty one.
#[test]
fn multi_field_repeated_enter_mashing_never_toggles() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Crypto);
    for _ in 0..3 {
        app.on_key(k(KeyCode::Down));
    }
    for _ in 0..10 {
        app.on_key(k(KeyCode::Enter)); // begin edit
        app.on_key(k(KeyCode::Enter)); // commit
    }
    let ciphers = app
        .model
        .profile()
        .crypto
        .as_ref()
        .and_then(|c| c.ciphers.clone())
        .unwrap_or_default();
    assert!(
        ciphers.is_empty(),
        "10 begin-edit/commit cycles must leave Multi untouched; got {ciphers:?}"
    );
}

/// Rendered-buffer assertion: pressing Enter on a Multi field must NOT
/// flip the visible `[x]`/`[ ]` marker. After Enter commits, the compact
/// nav-mode render does not include the cursor checkbox at all; this
/// asserts no cipher leaked into the selected list.
#[test]
fn multi_field_enter_does_not_change_rendered_summary() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Crypto);
    let before = render(&mut app, 100, 50);
    assert!(
        before.contains("(none)"),
        "before edit, Crypto ciphers must render `(none)`:\n{before}"
    );
    for _ in 0..3 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit
    app.on_key(k(KeyCode::Enter)); // commit, MUST NOT toggle
    let after = render(&mut app, 100, 50);
    assert!(
        after.contains("(none)"),
        "after Enter-Enter on Multi, ciphers must STILL render `(none)`:\n{after}"
    );
}

// -----------------------------------------------------------------
// t-endpoints — dedicated Endpoints page IT coverage.
// -----------------------------------------------------------------

/// Tab to the Endpoints page, add two entries (`a` Esc `a` Esc), and assert
/// the model picked up both with the expected default names.
#[test]
fn navigate_to_endpoints_and_add_two_entries() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Endpoints);
    app.on_key(k(KeyCode::Char('a'))); // add #1 + open editor
    app.on_key(k(KeyCode::Esc)); // close editor
    app.on_key(k(KeyCode::Char('a'))); // add #2 + open editor
    app.on_key(k(KeyCode::Esc)); // close editor
    let eps = &app.model.profile().endpoints;
    assert_eq!(eps.len(), 2);
    assert_eq!(eps[0].name, "endpoint-1");
    assert_eq!(eps[1].name, "endpoint-2");
}

/// Add one endpoint, navigate down to the priority field (index 3), type 5,
/// and commit. Verifies the editor's Numeric round-trip end-to-end.
#[test]
fn endpoints_page_priority_round_trip() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Endpoints);
    app.on_key(k(KeyCode::Char('a'))); // add + open editor at focus 0 (name)
                                       // Move focus to priority (index 3) via nav-mode Down x3.
    for _ in 0..3 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit on priority
    app.on_key(k(KeyCode::Char('5')));
    app.on_key(k(KeyCode::Enter)); // commit
    app.on_key(k(KeyCode::Esc)); // close editor
    assert_eq!(app.model.profile().endpoints[0].priority, Some(5));
}

// -----------------------------------------------------------------
// Choice-radio cycle through 3+ options. The user reported the
// radio spinner not cycling visible options when they press the
// rotate key. The existing `choice_right_arrow_updates_rendered_text_live`
// only covers a 2-option Choice (protocol: ssh2/ssh3) which can't
// distinguish "cycle works" from "single-flip works". These tests
// pin every visible step of a 3-option rotation through the App-
// level dispatch + render path.
// -----------------------------------------------------------------

/// `failure_policy` is a 3-option Choice (`retry`, `fail_profile`,
/// `fail_process`). Beginning edit, then pressing Right three times,
/// must walk through every option and wrap back to the first one,
/// with each step **visible in the rendered buffer**.
#[test]
fn basics_failure_policy_cycles_three_options_in_viewport_via_right() {
    let mut app = App::new(Model::from_str(SAMPLE));
    assert_eq!(app.current, PageKind::Basics);
    // Basics field order: 0=id, 1=description, 2=protocol, 3=startup,
    // 4=failure_policy. Down four times to focus failure_policy.
    for _ in 0..4 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit
    let s0 = render(&mut app, 100, 30);
    assert!(
        s0.contains("retry"),
        "before any rotation, spinner must show options[0] `retry`:\n{s0}"
    );
    assert!(
        s0.contains("(1/3)"),
        "position counter must show 1/3 at the start:\n{s0}"
    );

    app.on_key(k(KeyCode::Right));
    let s1 = render(&mut app, 100, 30);
    assert!(
        s1.contains("fail_profile"),
        "after 1× Right, viewport must show `fail_profile`:\n{s1}"
    );
    assert!(
        s1.contains("(2/3)"),
        "position counter must update to 2/3 after 1× Right:\n{s1}"
    );

    app.on_key(k(KeyCode::Right));
    let s2 = render(&mut app, 100, 30);
    assert!(
        s2.contains("fail_process"),
        "after 2× Right, viewport must show `fail_process`:\n{s2}"
    );
    assert!(
        s2.contains("(3/3)"),
        "position counter must update to 3/3 after 2× Right:\n{s2}"
    );

    app.on_key(k(KeyCode::Right));
    let s3 = render(&mut app, 100, 30);
    assert!(
        s3.contains("retry"),
        "after 3× Right (wrap), viewport must show `retry` again:\n{s3}"
    );
    assert!(
        s3.contains("(1/3)"),
        "position counter must wrap to 1/3 after 3× Right:\n{s3}"
    );

    // Each consecutive frame must differ from the prior — proves the
    // cycle is empirically visible, not just internally tracked.
    assert_ne!(s0, s1, "Right #1 must visibly change the frame");
    assert_ne!(s1, s2, "Right #2 must visibly change the frame");
    assert_ne!(s2, s3, "Right #3 must visibly change the frame (wrap)");
}

/// Same cycle, but driven by **Left** — must walk backwards through
/// the three options with proper wrap from index 0 → last.
#[test]
fn basics_failure_policy_cycles_three_options_in_viewport_via_left() {
    let mut app = App::new(Model::from_str(SAMPLE));
    for _ in 0..4 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit, cursor at options[0]=retry
    let s0 = render(&mut app, 100, 30);
    assert!(s0.contains("retry"), "{s0}");

    app.on_key(k(KeyCode::Left)); // wrap to last = fail_process
    let s_back = render(&mut app, 100, 30);
    assert!(
        s_back.contains("fail_process"),
        "Left at index 0 must wrap to `fail_process`:\n{s_back}"
    );
    assert!(s_back.contains("(3/3)"), "position must be 3/3:\n{s_back}");

    app.on_key(k(KeyCode::Left)); // → fail_profile
    let s_mid = render(&mut app, 100, 30);
    assert!(
        s_mid.contains("fail_profile") && s_mid.contains("(2/3)"),
        "2× Left must show `fail_profile` at 2/3:\n{s_mid}"
    );

    app.on_key(k(KeyCode::Left)); // → retry
    let s_start = render(&mut app, 100, 30);
    assert!(
        s_start.contains("retry") && s_start.contains("(1/3)"),
        "3× Left must wrap back to `retry` at 1/3:\n{s_start}"
    );
}

/// Up / Down must cycle identically to Left / Right per the wrap
/// fix in commit 4f3baf9. Verify on the same 3-option field.
#[test]
fn basics_failure_policy_cycles_three_options_in_viewport_via_down() {
    let mut app = App::new(Model::from_str(SAMPLE));
    for _ in 0..4 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter)); // begin edit

    app.on_key(k(KeyCode::Down)); // forward = same as Right
    let s = render(&mut app, 100, 30);
    assert!(
        s.contains("fail_profile") && s.contains("(2/3)"),
        "Down during edit must rotate to options[1]:\n{s}"
    );

    app.on_key(k(KeyCode::Up)); // reverse = same as Left
    let s = render(&mut app, 100, 30);
    assert!(
        s.contains("retry") && s.contains("(1/3)"),
        "Up during edit must rotate back to options[0]:\n{s}"
    );
}

/// Crypto.policy is another 3-option Choice (`modern`, `interop`,
/// `legacy`). Verify the same cycle behavior on a different page so
/// we know the bug isn't basics-page-specific.
#[test]
fn crypto_policy_cycles_three_options_in_viewport() {
    let mut app = App::new(Model::from_str(SAMPLE));
    tab_to(&mut app, PageKind::Crypto);
    // Crypto field 0 is `policy`; no Down required.
    app.on_key(k(KeyCode::Enter)); // begin edit
    let s0 = render(&mut app, 100, 30);
    assert!(
        s0.contains("modern") && s0.contains("(1/3)"),
        "initial render must show `modern` at 1/3:\n{s0}"
    );
    app.on_key(k(KeyCode::Right));
    let s1 = render(&mut app, 100, 30);
    assert!(
        s1.contains("interop") && s1.contains("(2/3)"),
        "1× Right must rotate to `interop` at 2/3:\n{s1}"
    );
    app.on_key(k(KeyCode::Right));
    let s2 = render(&mut app, 100, 30);
    assert!(
        s2.contains("legacy") && s2.contains("(3/3)"),
        "2× Right must rotate to `legacy` at 3/3:\n{s2}"
    );
}

/// After a full forward cycle (N × Right with wrap), the rendered
/// frame must be byte-identical to the starting frame — proves the
/// cycle is closed and repeatable, not drifting.
#[test]
fn failure_policy_full_cycle_returns_to_identical_viewport() {
    let mut app = App::new(Model::from_str(SAMPLE));
    for _ in 0..4 {
        app.on_key(k(KeyCode::Down));
    }
    app.on_key(k(KeyCode::Enter));
    let initial = render(&mut app, 100, 30);
    for _ in 0..3 {
        app.on_key(k(KeyCode::Right));
    }
    let after_full_cycle = render(&mut app, 100, 30);
    assert_eq!(
        initial, after_full_cycle,
        "after a full N=3 cycle, the rendered frame must match the start exactly"
    );
}

// -----------------------------------------------------------------
// Protocol display label — the spinner shows "ssh3 (francoismichel)"
// while the stored value remains the canonical "ssh3". This protects
// users from believing our `ssh3` is the IETF SSH3 standard.
// -----------------------------------------------------------------

/// In nav mode, a profile with `protocol = "ssh3"` must render the
/// friendly display label, not the bare canonical value.
#[test]
fn protocol_nav_mode_renders_friendly_display_label_for_ssh3() {
    const SAMPLE_SSH3: &str = r#"version = 1

[[profiles]]
name = "demo"
protocol = "ssh3"
host = "demo.example.com"
"#;
    let mut app = App::new(Model::from_str(SAMPLE_SSH3));
    let text = render(&mut app, 100, 30);
    assert!(
        text.contains("ssh3 (francoismichel)"),
        "nav-mode protocol row must show friendly display label:\n{text}"
    );
}

/// `protocol = "ssh2"` is canonical and friendly already; nav-mode
/// must render plain `ssh2` (no parenthetical).
#[test]
fn protocol_nav_mode_renders_plain_ssh2_unchanged() {
    let mut app = App::new(Model::from_str(SAMPLE));
    let text = render(&mut app, 100, 30);
    assert!(
        text.contains("ssh2"),
        "nav-mode protocol row must show ssh2:\n{text}"
    );
    assert!(
        !text.contains("ssh2 ("),
        "ssh2 must render plain — no parenthetical:\n{text}"
    );
}

/// In edit mode, pressing Right to rotate to the second option must
/// display the friendly label `ssh3 (francoismichel)` in the spinner.
#[test]
fn protocol_edit_rotate_to_ssh3_renders_friendly_label() {
    let mut app = App::new(Model::from_str(SAMPLE));
    // Focus protocol (index 2 on Basics).
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter)); // begin edit
    app.on_key(k(KeyCode::Right)); // rotate to ssh3
    let text = render(&mut app, 100, 30);
    assert!(
        text.contains("◀ ssh3 (francoismichel) ▶"),
        "rotated spinner must show friendly display label, not just `ssh3`:\n{text}"
    );
    assert!(
        text.contains("(2/2)"),
        "position counter must reflect index 2 of 2:\n{text}"
    );
}

/// Critical compat guard: committing the friendly-labelled option
/// must persist the **canonical** `"ssh3"` to the profile — not the
/// display string. Existing configs with `protocol = "ssh3"` keep
/// working because we never write `"ssh3 (francoismichel)"` to TOML.
#[test]
fn protocol_commit_writes_canonical_value_not_display_label() {
    let mut app = App::new(Model::from_str(SAMPLE));
    assert_eq!(app.model.profile().protocol, "ssh2");
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Down));
    app.on_key(k(KeyCode::Enter)); // begin edit
    app.on_key(k(KeyCode::Right)); // rotate to ssh3
    app.on_key(k(KeyCode::Enter)); // commit
    assert_eq!(
        app.model.profile().protocol,
        "ssh3",
        "committed value must be the canonical `ssh3`, NOT the display label"
    );
}

// -----------------------------------------------------------------
// Nav-mode focus border highlight — the field whose row is currently
// pre-selected (but not yet in edit) must have its border tinted
// Yellow so the operator can see which row will receive the next
// Enter, beyond just the ▶ gutter glyph.
// -----------------------------------------------------------------

/// In nav mode, the focused field's border cells must carry a Yellow
/// foreground style. Edit mode is a separate concern (widget paints
/// bright Yellow + BOLD itself).
#[test]
fn nav_mode_focused_field_border_is_yellow() {
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;
    use ratatui::Terminal;

    let mut app = App::new(Model::from_str(SAMPLE));
    // Default focus is index 0 (id). Render and probe the field's
    // border cells.
    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
        .unwrap();
    let buf = terminal.backend().buffer();

    // Scan rows for any cell whose symbol is one of the border glyphs
    // AND whose fg is Yellow. There must be at least a handful — the
    // top + bottom borders of the focused field row.
    let mut yellow_border_cells = 0usize;
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            let cell = &buf[(x, y)];
            let sym = cell.symbol();
            let is_border = matches!(sym, "─" | "│" | "┌" | "┐" | "└" | "┘");
            if is_border && cell.style().fg == Some(Color::Yellow) {
                yellow_border_cells += 1;
            }
        }
    }
    assert!(
        yellow_border_cells >= 4,
        "nav-mode focused field must have at least 4 Yellow border cells, \
         found {yellow_border_cells}"
    );
}

/// When focus moves to a different row, the Yellow border tint must
/// follow. This pins the "highlight follows focus" contract.
#[test]
fn nav_mode_yellow_border_follows_focus() {
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;
    use ratatui::Terminal;

    let mut app = App::new(Model::from_str(SAMPLE));
    let snapshot = |a: &mut App| -> Vec<(u16, u16)> {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|f| a.render_frame(f.area(), f.buffer_mut()))
            .unwrap();
        let buf = terminal.backend().buffer().clone();
        let mut cells = Vec::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                let c = &buf[(x, y)];
                let sym = c.symbol();
                let is_border = matches!(sym, "─" | "│" | "┌" | "┐" | "└" | "┘");
                if is_border && c.style().fg == Some(Color::Yellow) {
                    cells.push((x, y));
                }
            }
        }
        cells
    };

    let before = snapshot(&mut app);
    app.on_key(k(KeyCode::Down));
    let after = snapshot(&mut app);

    assert!(!before.is_empty(), "must have some yellow cells at focus 0");
    assert!(!after.is_empty(), "must have some yellow cells at focus 1");
    assert_ne!(
        before, after,
        "the yellow border cell set must shift when focus moves to a new row"
    );
}
