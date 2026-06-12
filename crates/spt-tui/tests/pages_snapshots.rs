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

/// E4-F15: the Review page grows a read-only "Other settings" section when
/// the profile carries non-wizard tables (`hops`/`sftp_mounts`/`script`/
/// `transport`/`enabled`) or schema-unknown keys. This profile has several of
/// each, plus a typo'd key that a TUI save would silently drop — the section
/// makes both visible. Rendered against a dedicated sample so the wizard-only
/// `review_page_100x30` snapshot stays byte-identical.
#[test]
fn snapshot_review_page_other_settings() {
    let sample = r#"version = 1

[[profiles]]
name = "demo"
protocol = "ssh2"
host = "demo.example.com"
enabled = true
mystery_key = "would be dropped"

[profiles.transport]

[profiles.script]
path = "hooks.rhai"

[[profiles.hops]]
name = "jump"
protocol = "ssh2"
host = "jump.example.com"
port = 22
"#;
    let model = Model::from_str(sample);
    let mut pages = build_pages();
    let page = &mut pages[PageKind::Review.index()];
    let backend = TestBackend::new(100, 30);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| page.render(f.area(), f.buffer_mut(), &model))
        .unwrap();
    let snap = buffer_text(terminal.backend().buffer());
    insta::assert_snapshot!("review_page_other_settings_100x30", snap);
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

// -----------------------------------------------------------------
// ma-tui (multi-auth Phase 4) — per-endpoint auth override.
//
// These exercise the new `user` field, the `auth.override` toggle, the
// gated shared `auth_fields` rows, the `auth=global`/`auth=local(...)`
// list+detail marker, and the secret-redaction guarantee for per-endpoint
// password/passphrase/token secrets. All are additive; the default
// `endpoints_page_100x20` snapshot above is regenerated once to grow the
// detail pane's `user:`/`auth:` lines and otherwise stays stable.
// -----------------------------------------------------------------

const ENDPOINTS_LOCAL_AUTH_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"
user = "global-user"

[profiles.auth]
method = "public_key"
identity_file = "/home/global/.ssh/id_ed25519"

[[profiles.endpoints]]
name = "primary"
host = "edge-1.example.com"
port = 22
priority = 0

[[profiles.endpoints]]
name = "override"
host = "edge-2.example.com"
port = 22
user = "edge-user"

[profiles.endpoints.auth]
method = "password"
"#;

/// Detail render (no editor open) for the GLOBAL-inherit endpoint: its
/// detail pane shows `auth=global`.
#[test]
fn snapshot_endpoints_page_global_auth_marker() {
    let snap = snapshot_page_with_keys(
        PageKind::Endpoints,
        &[],
        ENDPOINTS_LOCAL_AUTH_SAMPLE,
        120,
        20,
    );
    assert!(
        snap.contains("auth=global"),
        "first endpoint's detail pane must show the global-inherit marker:\n{snap}"
    );
    insta::assert_snapshot!("endpoints_page_global_auth_marker_120x20", snap);
}

/// Detail render for the OVERRIDE endpoint (selected via Down): its detail
/// pane shows `auth=local(password)` plus its per-endpoint `user`.
#[test]
fn snapshot_endpoints_page_local_auth_marker() {
    let snap = snapshot_page_with_keys(
        PageKind::Endpoints,
        &[KeyCode::Down],
        ENDPOINTS_LOCAL_AUTH_SAMPLE,
        120,
        20,
    );
    assert!(
        snap.contains("auth=local(password)"),
        "override endpoint's detail pane must show the local-auth marker with its method:\n{snap}"
    );
    assert!(
        snap.contains("edge-user"),
        "override endpoint's detail pane must show its per-endpoint user:\n{snap}"
    );
    insta::assert_snapshot!("endpoints_page_local_auth_marker_120x20", snap);
}

/// Secret-leak guard: a per-endpoint `password = "secret://..."` must
/// render REDACTED everywhere — the cleartext reference body must NEVER
/// appear in any rendered buffer (list/detail OR the open editor with the
/// override gating ON). Direct-assert, not a golden snapshot, so the
/// secret literal is never committed to a `.snap` file.
#[test]
fn endpoints_page_never_leaks_per_endpoint_secret() {
    const SECRET_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[profiles.endpoints]]
name = "primary"
host = "edge-1.example.com"
port = 22

[profiles.endpoints.auth]
method = "password"
password = "secret://ns/perendpointtopsecret"
"#;
    // (a) List/detail view (no editor open): cleartext never surfaces.
    let detail = snapshot_page_with_keys(PageKind::Endpoints, &[], SECRET_SAMPLE, 120, 30);
    assert!(
        !detail.contains("perendpointtopsecret"),
        "per-endpoint secret plaintext leaked into the Endpoints list/detail render"
    );
    // (b) Editor open (field-nav mode) with the override ON, rendered tall
    // so the gated `auth.password` row is visible. The row must be
    // [REDACTED]; the cleartext reference body must never appear. Enter (or
    // Right) opens the editor on the focused endpoint.
    let editor = snapshot_page_with_keys(
        PageKind::Endpoints,
        &[KeyCode::Enter],
        SECRET_SAMPLE,
        120,
        80,
    );
    assert!(
        !editor.contains("perendpointtopsecret"),
        "per-endpoint secret plaintext leaked into the open endpoint editor render"
    );
    assert!(
        editor.contains("[REDACTED]"),
        "expected the redacted auth.password marker in the editor render"
    );
}

// -----------------------------------------------------------------
// t-events-tui (E2) — populated Events page: sinks/bindings editors.
// These are all gated behind a populated `[events]` state; the
// default-state `events_page_100x20` snapshot above is unaffected.
// -----------------------------------------------------------------

const EVENTS_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "webhook"
type = "http"
url = "https://example.com/hook"
method = "POST"

[[events.sinks]]
name = "notifier"
type = "mcp_notify"

[[events.bindings]]
name = "on-fail"
on = ["profile.failed", "endpoint.down"]
actions = ["webhook"]
min_level = "warn"
"#;

/// Sinks + bindings rendered as populated lists (no editor open). Pins the
/// three-region populated layout.
#[test]
fn snapshot_events_page_populated() {
    let snap = snapshot_page_with_keys(PageKind::Events, &[], EVENTS_SAMPLE, 100, 30);
    insta::assert_snapshot!("events_page_populated_100x30", snap);
}

/// Sink editor open on the first (http) sink. We Tab into the Sinks region
/// then Enter to open the editor — the editor is in field-NAV mode (no field
/// actively editing), so the secret `auth` row renders redacted.
#[test]
fn snapshot_events_page_sink_editor_http() {
    let snap = snapshot_page_with_keys(
        PageKind::Events,
        &[KeyCode::Tab, KeyCode::Enter],
        EVENTS_SAMPLE,
        100,
        30,
    );
    insta::assert_snapshot!("events_page_sink_editor_http_100x30", snap);
}

/// Bindings list focused (Tab twice → Bindings region). Pins the populated
/// bindings list rendering.
#[test]
fn snapshot_events_page_bindings_focused() {
    let snap = snapshot_page_with_keys(
        PageKind::Events,
        &[KeyCode::Tab, KeyCode::Tab],
        EVENTS_SAMPLE,
        100,
        30,
    );
    insta::assert_snapshot!("events_page_bindings_focused_100x30", snap);
}

/// Secret-leak guard: a sink whose `auth` is a `secret://` reference must
/// render REDACTED — the cleartext reference body must NEVER appear in any
/// rendered buffer (list detail OR editor). Asserted directly (not a golden
/// snapshot) so the secret literal never has to be committed to a .snap file.
#[test]
fn events_page_never_leaks_secret_plaintext() {
    const SECRET_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "webhook"
type = "http"
url = "https://example.com/hook"
auth = "secret://ns/topsecretref"
"#;
    // (a) List-detail view (no editor): secret never surfaces, and the
    // detail summary surfaces the redaction marker in its place.
    let detail = snapshot_page_with_keys(PageKind::Events, &[], SECRET_SAMPLE, 100, 30);
    assert!(
        !detail.contains("topsecretref"),
        "secret plaintext leaked into the Events list/detail render"
    );
    assert!(
        detail.contains("[REDACTED]"),
        "expected the redacted auth marker in the sink detail render"
    );
    // (b) Editor open (field-nav mode) on the secret-bearing sink. The `auth`
    // row renders redacted; the cleartext reference body must never appear,
    // even where the row is visible (render at a tall height so it is).
    let editor = snapshot_page_with_keys(
        PageKind::Events,
        &[KeyCode::Tab, KeyCode::Enter],
        SECRET_SAMPLE,
        100,
        60,
    );
    assert!(
        !editor.contains("topsecretref"),
        "secret plaintext leaked into the open sink editor render"
    );
    assert!(
        editor.contains("[REDACTED]"),
        "expected the redacted auth marker in the editor render"
    );
}

// -----------------------------------------------------------------
// t-dns-forward-tui (E2) — populated DNS page: records list editor.
// All gated behind focusing the Records region (a `Down` keypress) or
// an open editor; the default-state `dns_page_100x20` snapshot above
// (read-only paragraph) is unaffected and stays byte-identical.
// -----------------------------------------------------------------

const DNS_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[profiles.forwards]]
name = "pg"
type = "local"
transport = "tcp"

[[dns.records]]
name = "service.local"
type = "A"
value = "127.0.0.1"

[[dns.records]]
name = "_sip._tcp.example"
type = "SRV"
value = "sip.example.com"
priority = 10
weight = 5
port = 5060
"#;

/// Records list editor focused (Down crosses from Forwards into Records).
/// Pins the interactive two-pane list/detail layout.
#[test]
fn snapshot_dns_page_records_list() {
    let snap = snapshot_page_with_keys(PageKind::Dns, &[KeyCode::Down], DNS_SAMPLE, 100, 30);
    insta::assert_snapshot!("dns_page_records_list_100x30", snap);
}

/// A-record editor open on the first (A) record: Down to focus Records,
/// Enter to open the editor. Editor is in field-nav mode showing all seven
/// record rows (SRV numeric rows blank for the A record).
#[test]
fn snapshot_dns_page_record_editor_a() {
    let snap = snapshot_page_with_keys(
        PageKind::Dns,
        &[KeyCode::Down, KeyCode::Enter],
        DNS_SAMPLE,
        100,
        30,
    );
    insta::assert_snapshot!("dns_page_record_editor_a_100x30", snap);
}

/// SRV-record editor open on the second record: the priority/weight/port
/// rows must show their populated SRV values. Down (focus Records), Down
/// (select record 1), Enter (open editor).
#[test]
fn snapshot_dns_page_record_editor_srv() {
    let snap = snapshot_page_with_keys(
        PageKind::Dns,
        &[KeyCode::Down, KeyCode::Down, KeyCode::Enter],
        DNS_SAMPLE,
        100,
        30,
    );
    insta::assert_snapshot!("dns_page_record_editor_srv_100x30", snap);
}

// -----------------------------------------------------------------
// t-events-tui-complete — new sink kinds (email/webpush), the webpush
// subscription sub-editor, and the `[[events.commands]]` region. All
// gated behind populated `[events]` state; the default-state
// `events_page_100x20` snapshot remains byte-identical.
// -----------------------------------------------------------------

/// Webpush sink editor with the VAPID private key set. The
/// `vapid_private_key` row must render `[REDACTED]` (never the raw key) in
/// field-nav mode. We Tab into Sinks then Enter to open the editor.
#[test]
fn snapshot_events_page_webpush_editor() {
    const WEBPUSH_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "push"
type = "webpush"
vapid_subject = "mailto:ops@example.com"
vapid_private_key = "RAWVAPIDKEYMATERIAL"
endpoint = "https://push.example/send"
"#;
    let snap = snapshot_page_with_keys(
        PageKind::Events,
        &[KeyCode::Tab, KeyCode::Enter],
        WEBPUSH_SAMPLE,
        100,
        40,
    );
    assert!(
        !snap.contains("RAWVAPIDKEYMATERIAL"),
        "VAPID private key cleartext leaked into the webpush editor render"
    );
    insta::assert_snapshot!("events_page_webpush_editor_100x40", snap);
}

/// Email sink editor showing the email-specific field set (smtp/from/to/
/// `body_template`) and the pinned-TLS rows.
#[test]
fn snapshot_events_page_email_editor() {
    const EMAIL_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "mailer"
type = "email"
smtp = "smtp.example.com:587"
from = "alerts@example.com"
to = ["oncall@example.com"]
body_template = "{{event}}"
"#;
    let snap = snapshot_page_with_keys(
        PageKind::Events,
        &[KeyCode::Tab, KeyCode::Enter],
        EMAIL_SAMPLE,
        100,
        40,
    );
    insta::assert_snapshot!("events_page_email_editor_100x40", snap);
}

/// The `[[events.commands]]` region rendered as a populated 4th region.
/// Tab×3 focuses Commands; the region is laid out below Bindings.
#[test]
fn snapshot_events_page_commands_region() {
    const COMMANDS_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "webhook"
type = "http"
url = "https://example.com/hook"

[[events.bindings]]
name = "on-fail"
on = ["profile.failed"]
actions = ["runit"]

[[events.commands]]
name = "runit"
command = "/usr/bin/notify"
args = ["--urgent"]
allow_exec = true
"#;
    let snap = snapshot_page_with_keys(
        PageKind::Events,
        &[KeyCode::Tab, KeyCode::Tab, KeyCode::Tab],
        COMMANDS_SAMPLE,
        100,
        40,
    );
    insta::assert_snapshot!("events_page_commands_region_100x40", snap);
}

/// The webpush subscription sub-editor (modal nested list) opened from the
/// webpush sink editor's `subscriptions` row. The per-subscription `auth`
/// secret must render `[REDACTED]` and never leak.
#[test]
fn snapshot_events_page_subscription_sub_editor() {
    const SUBS_SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "push"
type = "webpush"
vapid_subject = "mailto:ops@example.com"

[[events.sinks.subscriptions]]
endpoint = "https://push.example/ep1"
p256dh = "BPUBLICKEY"
auth = "SUBSCRIPTIONAUTHSECRET"
"#;
    // Tab→Sinks, Enter→open sink editor, Down×4 to reach the `subscriptions`
    // row (name,type,vapid_subject,vapid_private_key,body_template,endpoint,
    // subscriptions — index 6), Enter→open the sub-editor.
    let keys = [
        KeyCode::Tab,
        KeyCode::Enter,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Enter,
    ];
    let snap = snapshot_page_with_keys(PageKind::Events, &keys, SUBS_SAMPLE, 100, 30);
    assert!(
        !snap.contains("SUBSCRIPTIONAUTHSECRET"),
        "subscription auth cleartext leaked into the sub-editor render"
    );
    insta::assert_snapshot!("events_page_subscription_sub_editor_100x30", snap);
}

/// Per-secret no-plaintext guard for the webpush VAPID private key. The
/// cleartext must NEVER appear in any render (sink list/detail OR the open
/// editor); `[REDACTED]` is shown in its place. Direct-assert, not golden.
#[test]
fn events_page_never_leaks_vapid_private_key() {
    const SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "push"
type = "webpush"
vapid_private_key = "TOPSECRETVAPIDSCALAR"
"#;
    // (a) Sink list/detail view (no editor open): cleartext never surfaces,
    // and the detail summary surfaces the redaction marker in its place.
    let detail = snapshot_page_with_keys(PageKind::Events, &[], SAMPLE, 100, 40);
    assert!(
        !detail.contains("TOPSECRETVAPIDSCALAR"),
        "VAPID key leaked into the sink list/detail render"
    );
    assert!(
        detail.contains("[REDACTED]"),
        "expected the redacted VAPID marker in the sink detail render"
    );
    // (b) Editor open (field-nav mode): the vapid_private_key row renders
    // redacted — the cleartext must never appear even where the row is shown.
    let editor = snapshot_page_with_keys(
        PageKind::Events,
        &[KeyCode::Tab, KeyCode::Enter],
        SAMPLE,
        100,
        60,
    );
    assert!(
        !editor.contains("TOPSECRETVAPIDSCALAR"),
        "VAPID key leaked into the open webpush editor render"
    );
}

/// Per-secret no-plaintext guard for a webpush subscription `auth` secret.
/// The cleartext must NEVER appear in the sub-editor list/detail OR the open
/// per-subscription row editor; `[REDACTED]` is shown.
#[test]
fn events_page_never_leaks_subscription_auth() {
    const SAMPLE: &str = r#"version = 1
[[profiles]]
name = "demo"
protocol = "ssh2"

[[events.sinks]]
name = "push"
type = "webpush"

[[events.sinks.subscriptions]]
endpoint = "https://push.example/ep1"
p256dh = "BPUBLIC"
auth = "TOPSECRETSUBAUTH"
"#;
    // Open the sink editor and the subscription sub-editor (sub-list/detail).
    let down_to_subs = [
        KeyCode::Tab,
        KeyCode::Enter,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Down,
        KeyCode::Enter,
    ];
    let sub_list = snapshot_page_with_keys(PageKind::Events, &down_to_subs, SAMPLE, 100, 40);
    assert!(
        !sub_list.contains("TOPSECRETSUBAUTH"),
        "subscription auth leaked into the sub-editor list/detail render"
    );
    assert!(
        sub_list.contains("[REDACTED]"),
        "expected the redacted auth marker in the sub-editor detail render"
    );
    // Now open the per-subscription row editor (Enter on subscription #0) and
    // confirm the auth row is redacted there too.
    let mut keys: Vec<KeyCode> = down_to_subs.to_vec();
    keys.push(KeyCode::Enter); // open the row editor on subscription #0
    let row_editor = snapshot_page_with_keys(PageKind::Events, &keys, SAMPLE, 100, 40);
    assert!(
        !row_editor.contains("TOPSECRETSUBAUTH"),
        "subscription auth leaked into the per-subscription row editor render"
    );
    assert!(
        row_editor.contains("[REDACTED]"),
        "expected the redacted auth marker in the row editor render"
    );
}
