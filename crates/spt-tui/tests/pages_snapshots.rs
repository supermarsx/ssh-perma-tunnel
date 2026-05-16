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
fn snapshot_connection_page() {
    let snap = snapshot_page(PageKind::Connection, 80, 40);
    insta::assert_snapshot!("connection_page_80x40", snap);
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
    let snap = snapshot_page(PageKind::Keepalive, 80, 12);
    insta::assert_snapshot!("keepalive_page_80x12", snap);
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
