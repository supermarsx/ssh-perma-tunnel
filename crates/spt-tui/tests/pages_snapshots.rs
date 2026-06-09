//! Insta-driven golden snapshots for each wizard page.
//!
//! We deliberately render each page **in isolation** (via `build_pages` and
//! `Page::render`) rather than through `App::render_frame`, because the
//! whole-frame title bar embeds the profile name and the status line embeds
//! transient strings — both would make the snapshots flaky. Per-page render
//! is deterministic given a fixed `Model`.

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

[profiles.keepalive]
interval = "30s"
timeout = "5s"
max_missed = 3

[[profiles.forwards]]
name = "pg"
type = "local"
transport = "tcp"
bind = "127.0.0.1:5432"
target = "db.internal:5432"

[[dns.records]]
name = "service.local"
type = "A"
value = "127.0.0.1"
"#;

fn buffer_text(buf: &ratatui::buffer::Buffer) -> String {
    let mut out = String::new();
    for y in 0..buf.area.height {
        for x in 0..buf.area.width {
            out.push_str(buf[(x, y)].symbol());
        }
        // Trim trailing whitespace for stable snapshots.
        while out.ends_with(' ') {
            out.pop();
        }
        out.push('\n');
    }
    out
}

fn snapshot_page(kind: PageKind, w: u16, h: u16) -> String {
    let model = Model::from_str(SAMPLE);
    let mut pages = build_pages();
    let page = &mut pages[kind.index()];
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    buffer_text(terminal.backend().buffer())
}

#[test]
fn snapshot_basics_page() {
    let snap = snapshot_page(PageKind::Basics, 80, 20);
    insta::assert_snapshot!("basics_page_80x20", snap);
}

#[test]
fn snapshot_auth_page() {
    let snap = snapshot_page(PageKind::Auth, 80, 40);
    insta::assert_snapshot!("auth_page_80x40", snap);
}

#[test]
fn snapshot_trust_page() {
    let snap = snapshot_page(PageKind::Trust, 80, 40);
    insta::assert_snapshot!("trust_page_80x40", snap);
}

#[test]
fn snapshot_crypto_page() {
    let snap = snapshot_page(PageKind::Crypto, 80, 40);
    insta::assert_snapshot!("crypto_page_80x40", snap);
}

#[test]
fn snapshot_keepalive_page() {
    // 7 fields × 3-row chunks = 21 rows — needs ≥20 to fit without truncation.
    let snap = snapshot_page(PageKind::Keepalive, 80, 24);
    insta::assert_snapshot!("keepalive_page_80x24", snap);
}

#[test]
fn snapshot_failover_page() {
    let snap = snapshot_page(PageKind::Failover, 80, 50);
    insta::assert_snapshot!("failover_page_80x50", snap);
}

#[test]
fn snapshot_limits_page() {
    let snap = snapshot_page(PageKind::Limits, 80, 24);
    insta::assert_snapshot!("limits_page_80x24", snap);
}

#[test]
fn snapshot_forwards_page() {
    let snap = snapshot_page(PageKind::Forwards, 120, 20);
    insta::assert_snapshot!("forwards_page_120x20", snap);
}

#[test]
fn snapshot_dns_page() {
    let snap = snapshot_page(PageKind::Dns, 100, 20);
    insta::assert_snapshot!("dns_page_100x20", snap);
}

#[test]
fn snapshot_events_page() {
    let snap = snapshot_page(PageKind::Events, 100, 20);
    insta::assert_snapshot!("events_page_100x20", snap);
}

#[test]
fn snapshot_diagnostics_page() {
    let snap = snapshot_page(PageKind::Diagnostics, 80, 20);
    insta::assert_snapshot!("diagnostics_page_80x20", snap);
}

#[test]
fn snapshot_review_page() {
    let snap = snapshot_page(PageKind::Review, 100, 30);
    insta::assert_snapshot!("review_page_100x30", snap);
}

// -----------------------------------------------------------------
// Phase 1 reproducers — t-tui-rotate. New snapshots only.
// -----------------------------------------------------------------

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn key_press(c: KeyCode) -> KeyEvent {
    KeyEvent::new(c, KeyModifiers::NONE)
}

/// Drive the page at `kind` with a sequence of key events against a fresh
/// model, then render via `Page::render`. This matches the existing
/// snapshot tests (page-level render, no App chrome).
fn snapshot_page_with_keys(
    kind: PageKind,
    keys: &[KeyCode],
    sample: &str,
    w: u16,
    h: u16,
) -> String {
    let mut model = Model::from_str(sample);
    let mut pages = build_pages();
    let page = &mut pages[kind.index()];
    for k in keys {
        page.on_key(key_press(*k), &mut model);
    }
    let backend = TestBackend::new(w, h);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    buffer_text(terminal.backend().buffer())
}

/// Render the Basics page while editing the empty `description` field.
/// Pins the visible caret behavior for the empty-input case — the
/// regression that motivates RC4. We render at 80x20 (same dimensions
/// as the baseline `basics_page_80x20.snap`) so the diff is local to
/// the focus / edit changes.
#[test]
fn snapshot_basics_page_editing_empty_description_80x20() {
    // description = None ⇒ edit buffer is "".
    let sample = r#"version = 1

[[profiles]]
name = "demo"
protocol = "ssh2"
"#;
    let snap = snapshot_page_with_keys(
        PageKind::Basics,
        &[KeyCode::Down, KeyCode::Enter],
        sample,
        80,
        20,
    );
    insta::assert_snapshot!("basics_page_editing_empty_description_80x20", snap);
}

/// Render the Basics page after entering edit on `protocol` and
/// pressing Right twice (which under wrap semantics returns to the
/// start). Pins the rotate-rendering behavior.
#[test]
fn snapshot_basics_page_editing_protocol_after_rotate_80x20() {
    let snap = snapshot_page_with_keys(
        PageKind::Basics,
        &[
            KeyCode::Down,
            KeyCode::Down,
            KeyCode::Enter,
            KeyCode::Right,
            KeyCode::Right,
        ],
        SAMPLE,
        80,
        20,
    );
    insta::assert_snapshot!("basics_page_editing_protocol_after_rotate_80x20", snap);
}

// -----------------------------------------------------------------
// t-endpoints — snapshot for the dedicated Endpoints page rendering
// two entries (one with priority only, one with priority + weight).
// -----------------------------------------------------------------

#[test]
fn snapshot_endpoints_page() {
    let sample = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[profiles.endpoints]]
name = "primary"
host = "edge-1.example.com"
port = 22
priority = 0

[[profiles.endpoints]]
name = "backup"
host = "edge-2.example.com"
port = 22
priority = 1
weight = 5
"#;
    let model = Model::from_str(sample);
    let mut pages = build_pages();
    let page = &mut pages[PageKind::Endpoints.index()];
    let backend = TestBackend::new(100, 20);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    let snap = buffer_text(terminal.backend().buffer());
    insta::assert_snapshot!("endpoints_page_100x20", snap);
}
