//! Snapshot tests for page rendering using ratatui's `TestBackend`.
//!
//! These tests render each major page with a seeded [`Model`] into an
//! in-memory buffer, then assert the rendered text passes a smoke check
//! (key labels are present). We deliberately do *not* lock the entire
//! buffer to disk — ratatui's exact line breaking can shift between
//! versions and a brittle full-frame snapshot would dominate maintenance.

use ratatui::backend::TestBackend;
use ratatui::Terminal;
use spt_tui::pages::{build_pages, PageKind};
use spt_tui::Model;

const SAMPLE: &str = r#"version = 1

[[profiles]]
name = "demo"
protocol = "ssh2"
host = "demo.example.com"
user = "alice"

[profiles.auth]
method = "public_key"
identity_file = "/home/alice/.ssh/id_ed25519"

[profiles.crypto]
policy = "modern"

[[profiles.forwards]]
name = "pg"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "db.internal:5432"
"#;

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

#[test]
fn basics_page_renders_protocol_choice() {
    let model = Model::from_str(SAMPLE);
    let mut pages = build_pages();
    let page = &mut pages[PageKind::Basics.index()];

    let backend = TestBackend::new(80, 24);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    let text = frame_text(terminal.backend().buffer());
    assert!(text.contains("id"), "frame missing id: {text}");
    assert!(text.contains("protocol"), "frame missing protocol: {text}");
    assert!(text.contains("ssh2"));
}

#[test]
fn auth_page_lists_methods() {
    let model = Model::from_str(SAMPLE);
    let mut pages = build_pages();
    let page = &mut pages[PageKind::Auth.index()];

    let backend = TestBackend::new(80, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    let text = frame_text(terminal.backend().buffer());
    assert!(text.contains("auth.method"));
    assert!(text.contains("public_key"));
}

#[test]
fn forwards_page_lists_existing_entries() {
    let model = Model::from_str(SAMPLE);
    let mut pages = build_pages();
    let page = &mut pages[PageKind::Forwards.index()];

    let backend = TestBackend::new(120, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    let text = frame_text(terminal.backend().buffer());
    assert!(text.contains("local"));
    assert!(text.contains("tcp"));
    assert!(text.contains("127.0.0.1:5432"));
    assert!(text.contains("db.internal:5432"));
}

#[test]
fn review_page_shows_canonical_toml_and_validation() {
    let model = Model::from_str(SAMPLE);
    let mut pages = build_pages();
    let page = &mut pages[PageKind::Review.index()];

    let backend = TestBackend::new(120, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    let text = frame_text(terminal.backend().buffer());
    assert!(text.contains("Canonical TOML"), "missing title: {text}");
    assert!(text.contains("Validation"));
    assert!(text.contains("demo"));
}

#[test]
fn integration_save_round_trip_preserves_comments() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("c.toml");
    // NOTE: The save path replaces the entire `[[profiles]]` table for the
    // edited profile, so comments *inside* that profile are lost. Bytes
    // outside the table (header, other profiles, top-level tables) are
    // preserved exactly.
    let raw = "# top-level note\nversion = 1\n\n[logging]\nlevel = \"debug\"\n\n[[profiles]]\nname = \"demo\"\nprotocol = \"ssh2\"\nhost = \"old.example.com\"\n";
    std::fs::write(&path, raw).unwrap();

    let mut model = Model::load(&path).unwrap();
    model.profile_mut().host = Some("new.example.com".into());
    model.profile_mut().user = Some("bob".into());

    let written = spt_tui::save::save(&mut model).unwrap();
    assert_eq!(written, path);

    let out = std::fs::read_to_string(&path).unwrap();
    assert!(out.contains("# top-level note"));
    assert!(out.contains("[logging]"));
    assert!(out.contains("level = \"debug\""));
    assert!(out.contains("new.example.com"));
    assert!(out.contains("user = \"bob\""));
    assert!(!out.contains("old.example.com"));
}
