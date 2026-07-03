//! "Events" page — per-profile binding tags plus global `[events]` editors.
//!
//! The page has three stacked regions:
//!
//! 1. **Tags** (top) — the per-profile [`Profile::tags`] [`FieldList`]. Event
//!    bindings can match a profile by tag. Kept exactly as it was so its
//!    snapshots/tests stay byte-identical.
//! 2. **Sinks** — `[[events.sinks]]` add/`d`elete/`Enter`-edit list, mirroring
//!    [`crate::pages::endpoints::EndpointsPage`] (list-mode ↔ edit-mode).
//! 3. **Bindings** — `[[events.bindings]]`, same list/edit pattern.
//!
//! Regions 2 & 3 are global (live on `Config.events`, not the profile) and are
//! rendered **only when non-empty**. When there are zero sinks AND zero
//! bindings the page falls back to the exact original two-region layout (tags +
//! read-only bindings overview) so the default-state `events` snapshot stays
//! byte-identical.
//!
//! Editors here are hand-rolled on top of the low-level
//! [`crate::widgets`] primitives (`TextInput`, `Select`, `StringList`) rather
//! than the `Profile`-bound [`FieldList`] runner, because `[events]` lives on
//! `Config`, not `Profile`. v1 deliberately surfaces **no** push/VAPID/email
//! secret material; the only secret-shaped field is a sink `auth` secret
//! reference, which is validated for `secret://` shape and rendered through the
//! redacted `SecretRef` precedent so cleartext never lands in a snapshot.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget,
};
use spt_config::schema::{
    EventBinding, EventCommand, EventDedupe, EventSink, EventSinkSubscription, Events,
};
use spt_core::RedactedString;

use crate::model::Model;
use crate::pages::field::{opt_list, FieldList};
use crate::pages::Page;
use crate::widgets::{Select, StringList, TextInput};

/// Sink editor type discriminator options. `webpush` (not `push`) is the
/// runtime discriminator string (cli_dispatch.rs).
const SINK_KINDS: &[&str] = &[
    "http",
    "webhook_post",
    "command",
    "mcp_notify",
    "email",
    "sms",
    "webpush",
];

/// Choice options for a boolean-shaped row (`allow_exec`, `allow_self_signed`).
const BOOL_CHOICES: &[&str] = &["false", "true"];

/// Severity names for the `default_min_level` Choice row, low→high. The empty
/// first option means "unset" (omit the key — bindings stay unfiltered by
/// default), matching the schema's `None` round-trip.
const SEVERITY_CHOICES: &[&str] = &["", "trace", "debug", "info", "warn", "error"];

/// Documented event kinds surfaced as discoverability help on the binding `on`
/// row, plus the runtime-detection kind `memory.leak_suspected`. The `on` row
/// stays free-text/CSV so arbitrary or glob kinds still work — this list is a
/// hint, not a hard picker.
const KNOWN_KINDS: &[&str] = &[
    "profile.started",
    "profile.failed",
    "profile.stopped",
    "endpoint.up",
    "endpoint.down",
    "forward.bound",
    "forward.closed",
    "reconnect.attempt",
    "reconnect.succeeded",
    "memory.leak_suspected",
];

/// Which stacked region currently owns keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Region {
    /// Per-profile tags FieldList.
    Tags,
    /// Top-level `[events]` scalars (ring_capacity/retry_interval/spool_dir/
    /// spool_max_bytes/default_min_level) editor.
    Settings,
    /// `[[events.sinks]]` list/editor.
    Sinks,
    /// `[[events.bindings]]` list/editor.
    Bindings,
    /// `[[events.commands]]` list/editor.
    Commands,
}

/// Kind of value a hand-rolled editor row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    /// Free-form single-line text.
    Text,
    /// Fixed-choice from `SINK_KINDS`.
    Choice,
    /// Comma-separated list.
    List,
    /// Secret reference (`secret://…`); rendered redacted **and** validated
    /// for `secret://` shape at commit.
    Secret,
    /// Opaque secret material (e.g. a VAPID private key or a per-subscription
    /// auth secret). Rendered redacted like [`RowKind::Secret`] but **not**
    /// forced through `SecretRef::parse` — the value may be a raw base64url
    /// scalar OR a `secret://ns/name` reference.
    SecretOpaque,
}

/// Row labels whose committed value is a `u32`. Non-numeric input to these
/// rows is rejected at commit (held open with an inline error) rather than
/// silently parsed to `None` (E4-F8).
const NUMERIC_U32_ROWS: &[&str] = &["ring_capacity", "max_cert_chain_depth"];

/// One editable row inside a hand-rolled sink/binding editor.
struct EditorRow {
    /// Display label / TOML key.
    label: &'static str,
    /// One-line help.
    help: &'static str,
    /// Value kind (drives widget + rendering).
    kind: RowKind,
    /// Working buffer (cleartext for `Secret`, used only transiently).
    value: String,
    /// Cursor-aware text input state (Text / Secret).
    text: TextInput,
    /// Comma-list state (List).
    list: StringList,
    /// Choice spinner state (Choice).
    select: Select,
    /// Static option list for `Choice`.
    options: &'static [&'static str],
    /// Last validation error, if any.
    last_error: Option<String>,
}

impl EditorRow {
    fn text(label: &'static str, help: &'static str, value: String) -> Self {
        Self::new(label, help, RowKind::Text, value, &[])
    }
    fn secret(label: &'static str, help: &'static str, value: String) -> Self {
        Self::new(label, help, RowKind::Secret, value, &[])
    }
    fn secret_opaque(label: &'static str, help: &'static str, value: String) -> Self {
        Self::new(label, help, RowKind::SecretOpaque, value, &[])
    }
    fn list(label: &'static str, help: &'static str, values: &[String]) -> Self {
        let mut row = Self::new(label, help, RowKind::List, String::new(), &[]);
        row.list = StringList::from_vec(values);
        row
    }
    fn choice(
        label: &'static str,
        help: &'static str,
        options: &'static [&'static str],
        value: String,
    ) -> Self {
        let mut row = Self::new(label, help, RowKind::Choice, value, options);
        row.select.index = options.iter().position(|o| *o == row.value).unwrap_or(0);
        row
    }

    fn new(
        label: &'static str,
        help: &'static str,
        kind: RowKind,
        value: String,
        options: &'static [&'static str],
    ) -> Self {
        let cursor = value.chars().count();
        Self {
            label,
            help,
            kind,
            value,
            text: TextInput {
                cursor,
                focused: false,
            },
            list: StringList::default(),
            select: Select::default(),
            options,
            last_error: None,
        }
    }

    /// Sync the working `value` from the row's active widget at commit time.
    /// For `Choice`, the spinner only moves its cursor index while editing;
    /// the chosen option string is materialized here. Other kinds already
    /// keep `value`/`list` live.
    fn commit_value(&mut self) {
        if self.kind == RowKind::Choice {
            if let Some(opt) = self.options.get(self.select.index) {
                self.value = (*opt).to_owned();
            }
        }
    }

    /// Validate the current buffer; `Some(err)` blocks commit.
    fn validate(&self) -> Option<String> {
        if self.kind == RowKind::Secret && !self.value.is_empty() {
            if let Err(e) = spt_auth::SecretRef::parse(&self.value) {
                return Some(format!("invalid secret reference: {e}"));
            }
        }
        // Numeric `u32` rows: a non-empty, non-numeric buffer previously
        // parsed to `None` via `.ok()` and silently discarded the operator's
        // input (E4-F8). Validate the shape up front so a bad value holds the
        // field open with an inline error instead of vanishing on commit.
        if NUMERIC_U32_ROWS.contains(&self.label) {
            let t = self.value.trim();
            if !t.is_empty() && t.parse::<u32>().is_err() {
                return Some(format!("`{t}` is not a valid non-negative integer"));
            }
        }
        None
    }

    /// Apply an edit-mode key. Returns `true` if the buffer changed.
    fn on_key(&mut self, key: KeyEvent) -> bool {
        match self.kind {
            RowKind::Text | RowKind::Secret | RowKind::SecretOpaque => {
                let mut tmp = std::mem::take(&mut self.value);
                let changed = self.text.on_key(&mut tmp, key);
                self.value = tmp;
                changed
            }
            RowKind::List => self.list.on_key(key),
            RowKind::Choice => self.select.on_key(self.options, &mut self.value, key),
        }
    }

    /// The display string for this row when **not** editing. Secret refs are
    /// redacted so cleartext never reaches the buffer/snapshot.
    fn display(&self) -> String {
        match self.kind {
            RowKind::Secret | RowKind::SecretOpaque => {
                if self.value.is_empty() {
                    String::new()
                } else {
                    "[REDACTED]".to_owned()
                }
            }
            RowKind::List => self.list.parse().join(", "),
            _ => self.value.clone(),
        }
    }

    fn render(&self, area: Rect, buf: &mut Buffer, editing: bool, focused: bool) {
        match self.kind {
            RowKind::Text => {
                let mut t = self.text.clone();
                t.focused = editing;
                if editing {
                    t.render(area, buf, self.label, &self.value);
                } else {
                    render_static(area, buf, self.label, &self.value, focused);
                }
            }
            RowKind::Secret | RowKind::SecretOpaque => {
                // NEVER hand the raw secret to a focused TextInput at render
                // time when not actively editing — redact instead. While
                // editing, the operator is entering the reference / key
                // material; showing the transient edit buffer is acceptable
                // and mirrors the auth-page SecretRef precedent. Outside of
                // edit mode the value is always `[REDACTED]`, so cleartext
                // never lands in a snapshot.
                if editing {
                    let mut t = self.text.clone();
                    t.focused = true;
                    t.render(area, buf, self.label, &self.value);
                } else {
                    render_static(area, buf, self.label, &self.display(), focused);
                }
            }
            RowKind::List => {
                if editing {
                    self.list.render(area, buf, self.label);
                } else {
                    render_static(area, buf, self.label, &self.display(), focused);
                }
            }
            RowKind::Choice => {
                let mut s = self.select.clone();
                s.focused = editing;
                s.render(area, buf, self.label, self.options, &self.value);
                if !editing && focused {
                    paint_focus_border(buf, area);
                }
            }
        }
    }
}

/// Render a labelled, bordered static value box (nav-mode appearance).
fn render_static(area: Rect, buf: &mut Buffer, label: &str, value: &str, focused: bool) {
    let style = if focused {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(label)
        .border_style(style);
    Paragraph::new(value.to_owned())
        .block(block)
        .render(area, buf);
}

/// Tint the border of `area` Yellow to mark nav focus (mirrors the
/// FieldList nav-focus tint for rows that paint their own border).
fn paint_focus_border(buf: &mut Buffer, area: Rect) {
    if area.width < 2 || area.height < 2 {
        return;
    }
    let buf_area = buf.area();
    let max_x = buf_area.x + buf_area.width;
    let max_y = buf_area.y + buf_area.height;
    let right = area.x + area.width - 1;
    let bottom = area.y + area.height - 1;
    for x in area.x..=right {
        if x < max_x {
            if area.y < max_y {
                let s = buf[(x, area.y)].style().fg(Color::Yellow);
                buf[(x, area.y)].set_style(s);
            }
            if bottom < max_y && bottom != area.y {
                let s = buf[(x, bottom)].style().fg(Color::Yellow);
                buf[(x, bottom)].set_style(s);
            }
        }
    }
    for y in (area.y + 1)..bottom {
        if y < max_y {
            if area.x < max_x {
                let s = buf[(area.x, y)].style().fg(Color::Yellow);
                buf[(area.x, y)].set_style(s);
            }
            if right < max_x && right != area.x {
                let s = buf[(right, y)].style().fg(Color::Yellow);
                buf[(right, y)].set_style(s);
            }
        }
    }
}

/// A hand-rolled multi-row editor for one sink or binding.
struct RowEditor {
    /// Index of the item being edited within its `Vec`.
    index: usize,
    /// Editable rows.
    rows: Vec<EditorRow>,
    /// Focused row.
    focus: usize,
    /// Whether the focused row is in active edit mode.
    editing: bool,
}

impl RowEditor {
    fn new(index: usize, rows: Vec<EditorRow>) -> Self {
        Self {
            index,
            rows,
            focus: 0,
            editing: false,
        }
    }

    fn move_focus(&mut self, delta: isize) {
        if self.rows.is_empty() {
            return;
        }
        let n = self.rows.len() as isize;
        let mut new = self.focus as isize + delta;
        while new < 0 {
            new += n;
        }
        self.focus = (new % n) as usize;
    }

    /// Handle a key while the editor is open. Returns `(committed, close)`:
    ///
    /// * `committed` — a field edit was just **committed** (Enter passed
    ///   validation). Only then should the caller write the editor's rows
    ///   back into the model. Mid-edit keystrokes return `false` so a
    ///   half-typed buffer never lands in the model (and a failed validation
    ///   can't leave a partial value behind).
    /// * `close` — close the editor (pane-nav left).
    fn on_key(&mut self, key: KeyEvent) -> (bool, bool) {
        if self.editing {
            match key.code {
                KeyCode::Esc => {
                    self.editing = false;
                    return (false, false);
                }
                KeyCode::Enter => {
                    // Commit. Sync the row's working `value` from its widget
                    // (Choice cursor moves don't write `value` until commit;
                    // Text/Secret/List keep `value`/`list` live), then
                    // validate. Validation failure holds the field open and
                    // does NOT write the model.
                    if let Some(row) = self.rows.get_mut(self.focus) {
                        row.commit_value();
                        if let Some(err) = row.validate() {
                            row.last_error = Some(err);
                            return (false, false);
                        }
                        row.last_error = None;
                    }
                    self.editing = false;
                    return (true, false);
                }
                _ => {
                    // Mutate the row's working buffer only — do NOT signal a
                    // model commit on each keystroke.
                    if let Some(row) = self.rows.get_mut(self.focus) {
                        row.on_key(key);
                    }
                    return (false, false);
                }
            }
        }
        match key.code {
            KeyCode::Esc | KeyCode::Left => (false, true),
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_focus(-1);
                (false, false)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_focus(1);
                (false, false)
            }
            KeyCode::Enter | KeyCode::Char('e') => {
                if let Some(row) = self.rows.get_mut(self.focus) {
                    row.text.focused = true;
                    row.text.cursor = row.value.chars().count();
                    if row.kind == RowKind::List {
                        row.list.text.focused = true;
                    }
                }
                self.editing = true;
                (false, false)
            }
            _ => (false, false),
        }
    }

    fn render(&self, area: Rect, buf: &mut Buffer) {
        let n = self.rows.len().max(1);
        let constraints: Vec<Constraint> = (0..n).map(|_| Constraint::Length(3)).collect();
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);
        for (i, row) in self.rows.iter().enumerate() {
            let Some(rect) = chunks.get(i) else { continue };
            let focused = i == self.focus;
            let editing = self.editing && focused;
            row.render(*rect, buf, editing, focused);
        }
    }
}

// --- Sink / binding row builders ------------------------------------------

/// Normalize a sink `type` discriminator to a known kind. Unknown kinds fall
/// back to `http` so the editor always presents a coherent field set.
fn norm_kind(kind: &str) -> &'static str {
    SINK_KINDS
        .iter()
        .copied()
        .find(|k| *k == kind)
        .unwrap_or("http")
}

/// The leading two rows shared by every kind: `name` then the `type` Choice.
fn lead_rows(s: &EventSink) -> Vec<EditorRow> {
    vec![
        EditorRow::text("name", "Sink identifier", s.name.clone()),
        EditorRow::choice(
            "type",
            "Sink kind (http/webhook_post/command/mcp_notify/email/sms/webpush)",
            SINK_KINDS,
            if s.kind.is_empty() {
                SINK_KINDS[0].to_owned()
            } else {
                s.kind.clone()
            },
        ),
    ]
}

/// The pinned-TLS rows shared by every TLS-doing kind.
fn pinned_tls_rows(s: &EventSink) -> Vec<EditorRow> {
    vec![
        EditorRow::list(
            "pin_spki_sha256",
            "Pinned SPKI SHA-256 set (CSV, base64)",
            &s.pin_spki_sha256,
        ),
        EditorRow::choice(
            "allow_self_signed",
            "Allow self-signed certs (requires a non-empty pin set)",
            BOOL_CHOICES,
            bool_to_choice(s.allow_self_signed),
        ),
        EditorRow::text(
            "max_cert_chain_depth",
            "Maximum certificate chain depth (integer)",
            s.max_cert_chain_depth
                .map(|d| d.to_string())
                .unwrap_or_default(),
        ),
    ]
}

/// The `auth` secret-ref row plus a `timeout` row (shared tail for several
/// kinds). `auth` is a `secret://` reference, validated for shape.
fn auth_row(s: &EventSink) -> EditorRow {
    EditorRow::secret(
        "auth",
        "Secret ref for sink auth — `secret://ns/name`",
        s.auth.clone().unwrap_or_default(),
    )
}
fn timeout_row(s: &EventSink) -> EditorRow {
    EditorRow::text(
        "timeout",
        "Per-call timeout (e.g. 5s)",
        s.timeout.clone().unwrap_or_default(),
    )
}
fn subject_template_row(s: &EventSink) -> EditorRow {
    EditorRow::text(
        "subject_template",
        "Subject template ({{var}} rendered against the event)",
        s.subject_template.clone().unwrap_or_default(),
    )
}
fn body_template_row(s: &EventSink) -> EditorRow {
    EditorRow::text(
        "body_template",
        "Body template ({{var}} rendered against the event)",
        s.body_template.clone().unwrap_or_default(),
    )
}

/// Build the editor rows for a sink, branching on its normalized `kind` so
/// only the active kind's fields are surfaced. Every kind leads with
/// `name` + `type`. Non-active-kind struct fields are intentionally NOT
/// surfaced; `apply_sink_rows` matches labels as a superset so untouched
/// fields round-trip on save.
fn sink_rows(s: &EventSink) -> Vec<EditorRow> {
    let mut rows = lead_rows(s);
    match norm_kind(&s.kind) {
        "email" => {
            rows.push(EditorRow::text(
                "smtp",
                "SMTP endpoint (host:port)",
                s.smtp.clone().unwrap_or_default(),
            ));
            rows.push(EditorRow::text(
                "from",
                "From address",
                s.from.clone().unwrap_or_default(),
            ));
            rows.push(EditorRow::list(
                "to",
                "Recipient list (CSV)",
                s.to.as_deref().unwrap_or(&[]),
            ));
            rows.push(subject_template_row(s));
            rows.push(body_template_row(s));
            rows.push(auth_row(s));
            rows.push(timeout_row(s));
            rows.extend(pinned_tls_rows(s));
        }
        "sms" => {
            rows.push(EditorRow::text(
                "provider",
                "SMS provider hint",
                s.provider.clone().unwrap_or_default(),
            ));
            rows.push(EditorRow::text(
                "url",
                "Provider endpoint URL",
                s.url.clone().unwrap_or_default(),
            ));
            rows.push(body_template_row(s));
            rows.push(auth_row(s));
            rows.push(timeout_row(s));
            rows.extend(pinned_tls_rows(s));
        }
        "webpush" => {
            rows.push(EditorRow::text(
                "vapid_subject",
                "VAPID `sub` claim — usually a mailto: URL",
                s.vapid_subject.clone().unwrap_or_default(),
            ));
            rows.push(EditorRow::secret_opaque(
                "vapid_private_key",
                "VAPID private key (raw base64url scalar OR secret://ns/name)",
                s.vapid_private_key
                    .as_ref()
                    .map(|r| r.expose().to_owned())
                    .unwrap_or_default(),
            ));
            rows.push(body_template_row(s));
            rows.push(EditorRow::text(
                "endpoint",
                "Endpoint URL alias (push)",
                s.endpoint.clone().unwrap_or_default(),
            ));
            // The subscriptions row is a marker; Enter on it (nav mode) opens
            // the nested subscription sub-editor at the page level.
            rows.push(EditorRow::text(
                "subscriptions",
                "Push subscriptions — Enter opens the sub-editor",
                subscriptions_summary(s),
            ));
            rows.push(timeout_row(s));
            rows.extend(pinned_tls_rows(s));
        }
        // http / webhook_post / command / mcp_notify — the v1 surface.
        kind => {
            rows.push(EditorRow::text(
                "url",
                "Endpoint URL (http / webhook_post)",
                s.url.clone().unwrap_or_default(),
            ));
            rows.push(EditorRow::text(
                "method",
                "HTTP method (GET/POST/…)",
                s.method.clone().unwrap_or_default(),
            ));
            rows.push(EditorRow::text(
                "content_type",
                "HTTP content type",
                s.content_type.clone().unwrap_or_default(),
            ));
            rows.push(timeout_row(s));
            rows.push(auth_row(s));
            // Pinned-TLS applies to the HTTPS-doing kinds (http/webhook_post).
            if matches!(kind, "http" | "webhook_post") {
                rows.extend(pinned_tls_rows(s));
            }
        }
    }
    rows
}

/// A short read-only summary of the configured subscriptions for the marker
/// row (never leaks the per-subscription auth secret).
fn subscriptions_summary(s: &EventSink) -> String {
    match s.subscriptions.as_ref() {
        Some(subs) if !subs.is_empty() => format!("[{} subscription(s)]", subs.len()),
        _ => "(none — Enter to add)".to_owned(),
    }
}

/// Render a bool option to its `BOOL_CHOICES` string.
fn bool_to_choice(v: Option<bool>) -> String {
    match v {
        Some(true) => "true".to_owned(),
        _ => "false".to_owned(),
    }
}

/// Write the editor rows back into a sink. Matches ALL known labels as a
/// superset so whichever kind is active, only its surfaced fields are
/// written; non-active-kind struct fields are left untouched and round-trip
/// on save. The `subscriptions` marker row is intentionally NOT applied here
/// (the sub-editor mutates the model directly).
fn apply_sink_rows(rows: &[EditorRow], s: &mut EventSink) {
    let opt = |v: &str| {
        if v.is_empty() {
            None
        } else {
            Some(v.to_owned())
        }
    };
    let opt_list_val = |row: &EditorRow| -> Option<Vec<String>> {
        let v = row.list.parse();
        if v.is_empty() {
            None
        } else {
            Some(v)
        }
    };
    for row in rows {
        match row.label {
            "name" => s.name = row.value.clone(),
            "type" => s.kind = row.value.clone(),
            "url" => s.url = opt(&row.value),
            "method" => s.method = opt(&row.value),
            "content_type" => s.content_type = opt(&row.value),
            "timeout" => s.timeout = opt(&row.value),
            "auth" => s.auth = opt(&row.value),
            "smtp" => s.smtp = opt(&row.value),
            "from" => s.from = opt(&row.value),
            "to" => s.to = opt_list_val(row),
            "provider" => s.provider = opt(&row.value),
            "endpoint" => s.endpoint = opt(&row.value),
            "subject_template" => s.subject_template = opt(&row.value),
            "body_template" => s.body_template = opt(&row.value),
            "vapid_subject" => s.vapid_subject = opt(&row.value),
            "vapid_private_key" => {
                s.vapid_private_key = if row.value.is_empty() {
                    None
                } else {
                    Some(RedactedString::from(row.value.clone()))
                };
            }
            "pin_spki_sha256" => s.pin_spki_sha256 = row.list.parse(),
            "allow_self_signed" => {
                s.allow_self_signed = match row.value.as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => s.allow_self_signed,
                };
            }
            "max_cert_chain_depth" => {
                s.max_cert_chain_depth = row.value.trim().parse::<u32>().ok();
            }
            // `subscriptions` marker — handled by the sub-editor, not here.
            _ => {}
        }
    }
}

/// Help text for the binding `on` row: free-text/CSV plus a discoverability
/// hint listing the documented [`KNOWN_KINDS`] (incl. `memory.leak_suspected`).
/// `on` stays free-text so arbitrary/glob kinds still work. Built once from
/// `KNOWN_KINDS` so the hint never drifts from the canonical list.
fn on_help() -> &'static str {
    use std::sync::OnceLock;
    static ON_HELP: OnceLock<String> = OnceLock::new();
    ON_HELP
        .get_or_init(|| {
            format!(
                "Event kinds (CSV, globs OK). Known: {}",
                KNOWN_KINDS.join(", ")
            )
        })
        .as_str()
}

fn binding_rows(b: &EventBinding) -> Vec<EditorRow> {
    let (dedupe_key, dedupe_window) = match b.dedupe.as_ref() {
        Some(d) => (
            d.key.clone().unwrap_or_default(),
            d.window.clone().unwrap_or_default(),
        ),
        None => (String::new(), String::new()),
    };
    vec![
        EditorRow::text("name", "Binding identifier", b.name.clone()),
        EditorRow::list("on", on_help(), &b.on),
        EditorRow::list("actions", "Sink/command names to fire (CSV)", &b.actions),
        EditorRow::text(
            "min_level",
            "Minimum severity (e.g. warn)",
            b.min_level.clone().unwrap_or_default(),
        ),
        EditorRow::text(
            "throttle",
            "Per-binding throttle (e.g. 1m)",
            b.throttle.clone().unwrap_or_default(),
        ),
        EditorRow::text(
            "dedupe.key",
            "Dedupe key field path (e.g. kind); empty = dispatcher default",
            dedupe_key,
        ),
        EditorRow::text(
            "dedupe.window",
            "Dedupe suppression window (duration, e.g. 60s)",
            dedupe_window,
        ),
    ]
}

fn apply_binding_rows(rows: &[EditorRow], b: &mut EventBinding) {
    let opt = |v: &str| {
        if v.is_empty() {
            None
        } else {
            Some(v.to_owned())
        }
    };
    // Collect the two dedupe sub-fields then lazily (re)build EventDedupe:
    // Some when either is non-empty, None when both are empty.
    let mut dedupe_key: Option<String> = None;
    let mut dedupe_window: Option<String> = None;
    for row in rows {
        match row.label {
            "name" => b.name = row.value.clone(),
            "on" => b.on = row.list.parse(),
            "actions" => b.actions = row.list.parse(),
            "min_level" => b.min_level = opt(&row.value),
            "throttle" => b.throttle = opt(&row.value),
            "dedupe.key" => dedupe_key = opt(&row.value),
            "dedupe.window" => dedupe_window = opt(&row.value),
            _ => {}
        }
    }
    b.dedupe = if dedupe_key.is_none() && dedupe_window.is_none() {
        None
    } else {
        Some(EventDedupe {
            key: dedupe_key,
            window: dedupe_window,
        })
    };
}

// --- Events settings (top-level `[events]` scalars) row builders -----------

/// Build the editor rows for the top-level `[events]` scalars. Mirrors the
/// schema fields E1 added: ring_capacity/retry_interval/spool_dir/
/// spool_max_bytes/default_min_level.
fn settings_rows(e: &Events) -> Vec<EditorRow> {
    vec![
        EditorRow::text(
            "ring_capacity",
            "Event-bus ring capacity (u32, >0); empty = bus default 1024",
            e.ring_capacity.map(|c| c.to_string()).unwrap_or_default(),
        ),
        EditorRow::text(
            "retry_interval",
            "Spool-retry poll interval (duration, e.g. 30s)",
            e.retry_interval.clone().unwrap_or_default(),
        ),
        EditorRow::text(
            "spool_dir",
            "Per-sink disk-spool root; empty = default `event-spool`",
            e.spool_dir.clone().unwrap_or_default(),
        ),
        EditorRow::text(
            "spool_max_bytes",
            "Disk-spool byte cap (bytesize, e.g. 32MiB)",
            e.spool_max_bytes.clone().unwrap_or_default(),
        ),
        EditorRow::choice(
            "default_min_level",
            "Default minimum severity for bindings without their own min_level",
            SEVERITY_CHOICES,
            e.default_min_level.clone().unwrap_or_default(),
        ),
    ]
}

fn apply_settings_rows(rows: &[EditorRow], e: &mut Events) {
    let opt = |v: &str| {
        let t = v.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_owned())
        }
    };
    for row in rows {
        match row.label {
            "ring_capacity" => e.ring_capacity = row.value.trim().parse::<u32>().ok(),
            "retry_interval" => e.retry_interval = opt(&row.value),
            "spool_dir" => e.spool_dir = opt(&row.value),
            "spool_max_bytes" => e.spool_max_bytes = opt(&row.value),
            "default_min_level" => e.default_min_level = opt(&row.value),
            _ => {}
        }
    }
}

/// `true` when any top-level `[events]` scalar is set — drives whether the
/// Settings region is rendered when it is not the active region.
fn has_settings(e: &Events) -> bool {
    e.ring_capacity.is_some()
        || e.retry_interval.is_some()
        || e.spool_dir.is_some()
        || e.spool_max_bytes.is_some()
        || e.default_min_level.is_some()
}

// --- Command row builders --------------------------------------------------

fn command_rows(c: &EventCommand) -> Vec<EditorRow> {
    vec![
        EditorRow::text("name", "Command identifier", c.name.clone()),
        EditorRow::text("command", "Allow-listed executable path", c.command.clone()),
        EditorRow::list(
            "args",
            "Argument template (CSV)",
            c.args.as_deref().unwrap_or(&[]),
        ),
        EditorRow::choice(
            "allow_exec",
            "Must be true to fire the command",
            BOOL_CHOICES,
            bool_to_choice(c.allow_exec),
        ),
        EditorRow::text(
            "timeout",
            "Execution timeout (e.g. 5s)",
            c.timeout.clone().unwrap_or_default(),
        ),
    ]
}

fn apply_command_rows(rows: &[EditorRow], c: &mut EventCommand) {
    let opt = |v: &str| {
        if v.is_empty() {
            None
        } else {
            Some(v.to_owned())
        }
    };
    for row in rows {
        match row.label {
            "name" => c.name = row.value.clone(),
            "command" => c.command = row.value.clone(),
            "args" => {
                let v = row.list.parse();
                c.args = if v.is_empty() { None } else { Some(v) };
            }
            "allow_exec" => {
                c.allow_exec = match row.value.as_str() {
                    "true" => Some(true),
                    "false" => Some(false),
                    _ => c.allow_exec,
                };
            }
            "timeout" => c.timeout = opt(&row.value),
            _ => {}
        }
    }
}

// --- Subscription (webpush) row builders -----------------------------------

fn subscription_rows(sub: &EventSinkSubscription) -> Vec<EditorRow> {
    vec![
        EditorRow::text(
            "endpoint",
            "Subscription endpoint URL",
            sub.endpoint.clone(),
        ),
        EditorRow::text(
            "p256dh",
            "Browser P256 ECDH key (base64url)",
            sub.p256dh.clone(),
        ),
        EditorRow::secret_opaque(
            "auth",
            "Per-subscription auth secret (base64url) — opaque",
            sub.auth.expose().to_owned(),
        ),
    ]
}

fn apply_subscription_rows(rows: &[EditorRow], sub: &mut EventSinkSubscription) {
    for row in rows {
        match row.label {
            "endpoint" => sub.endpoint = row.value.clone(),
            "p256dh" => sub.p256dh = row.value.clone(),
            "auth" => sub.auth = RedactedString::from(row.value.clone()),
            _ => {}
        }
    }
}

/// Nested subscription sub-editor for a webpush sink. Owns its own selection
/// and an optional inner [`RowEditor`] for the focused subscription. Reachable
/// from the webpush sink editor's `subscriptions` row.
struct SubEditor {
    /// Parent sink index within `events.sinks`.
    sink_index: usize,
    /// Selected subscription index (list mode).
    sel: usize,
    /// Open per-subscription row editor, if any.
    editor: Option<RowEditor>,
    /// Cached list state for rendering.
    list_state: ListState,
}

impl SubEditor {
    fn new(sink_index: usize) -> Self {
        Self {
            sink_index,
            sel: 0,
            editor: None,
            list_state: ListState::default(),
        }
    }
}

/// Event tags + sinks/bindings/commands editors.
pub struct EventsPage {
    /// Per-profile tags FieldList (region 1). Unchanged from before.
    list: FieldList,
    /// Active region for keyboard input.
    region: Region,
    /// Open settings editor (top-level `[events]` scalars), if any.
    settings_editor: Option<RowEditor>,
    /// Selected sink index (list mode).
    sink_sel: usize,
    /// Selected binding index (list mode).
    binding_sel: usize,
    /// Selected command index (list mode).
    command_sel: usize,
    /// Open sink editor, if any.
    sink_editor: Option<RowEditor>,
    /// Open binding editor, if any.
    binding_editor: Option<RowEditor>,
    /// Open command editor, if any.
    command_editor: Option<RowEditor>,
    /// Open subscription sub-editor (webpush), if any.
    sub_editor: Option<SubEditor>,
    /// Cached list states for rendering.
    sink_list_state: ListState,
    binding_list_state: ListState,
    command_list_state: ListState,
}

impl EventsPage {
    /// Build the page.
    pub fn new() -> Self {
        let fields = vec![opt_list(
            "tags",
            "Free-form tags (CSV); event bindings can match by tag",
            |p| p.tags.clone().unwrap_or_default(),
            |p, v| p.tags = if v.is_empty() { None } else { Some(v) },
        )];
        Self {
            list: FieldList::new(fields),
            region: Region::Tags,
            settings_editor: None,
            sink_sel: 0,
            binding_sel: 0,
            command_sel: 0,
            sink_editor: None,
            binding_editor: None,
            command_editor: None,
            sub_editor: None,
            sink_list_state: ListState::default(),
            binding_list_state: ListState::default(),
            command_list_state: ListState::default(),
        }
    }

    /// `true` when all event lists are empty (or `[events]` absent), meaning
    /// the page should fall back to the original two-region layout so the
    /// default-state snapshot stays byte-identical.
    fn is_empty_state(model: &Model) -> bool {
        model.events().is_none_or(|e| {
            e.sinks.is_empty() && e.bindings.is_empty() && e.commands.is_empty() && !has_settings(e)
        })
    }

    fn n_sinks(model: &Model) -> usize {
        model.events().map_or(0, |e| e.sinks.len())
    }
    fn n_bindings(model: &Model) -> usize {
        model.events().map_or(0, |e| e.bindings.len())
    }
    fn n_commands(model: &Model) -> usize {
        model.events().map_or(0, |e| e.commands.len())
    }

    fn open_settings_editor(&mut self, model: &Model) {
        let e = model.events().cloned().unwrap_or_default();
        self.settings_editor = Some(RowEditor::new(0, settings_rows(&e)));
    }
    fn commit_settings_editor(&mut self, model: &mut Model) {
        if let Some(ed) = self.settings_editor.as_ref() {
            apply_settings_rows(&ed.rows, model.events_mut());
        }
    }

    fn open_sink_editor(&mut self, model: &Model, idx: usize) {
        if let Some(s) = model.events().and_then(|e| e.sinks.get(idx)) {
            self.sink_editor = Some(RowEditor::new(idx, sink_rows(s)));
        }
    }
    fn open_binding_editor(&mut self, model: &Model, idx: usize) {
        if let Some(b) = model.events().and_then(|e| e.bindings.get(idx)) {
            self.binding_editor = Some(RowEditor::new(idx, binding_rows(b)));
        }
    }
    fn open_command_editor(&mut self, model: &Model, idx: usize) {
        if let Some(c) = model.events().and_then(|e| e.commands.get(idx)) {
            self.command_editor = Some(RowEditor::new(idx, command_rows(c)));
        }
    }
    fn open_sub_editor_row(&mut self, model: &Model, sub_idx: usize) {
        let Some(se) = self.sub_editor.as_mut() else {
            return;
        };
        if let Some(sub) = model
            .events()
            .and_then(|e| e.sinks.get(se.sink_index))
            .and_then(|s| s.subscriptions.as_ref())
            .and_then(|subs| subs.get(sub_idx))
        {
            se.editor = Some(RowEditor::new(sub_idx, subscription_rows(sub)));
        }
    }

    /// Write the open sink editor's current row buffers back into the model
    /// **without** closing the editor. Called after a single field commit.
    fn commit_sink_editor(&mut self, model: &mut Model) {
        if let Some(ed) = self.sink_editor.as_ref() {
            let idx = ed.index;
            if let Some(s) = model.events_mut().sinks.get_mut(idx) {
                apply_sink_rows(&ed.rows, s);
            }
        }
    }
    fn commit_binding_editor(&mut self, model: &mut Model) {
        if let Some(ed) = self.binding_editor.as_ref() {
            let idx = ed.index;
            if let Some(b) = model.events_mut().bindings.get_mut(idx) {
                apply_binding_rows(&ed.rows, b);
            }
        }
    }
    fn commit_command_editor(&mut self, model: &mut Model) {
        if let Some(ed) = self.command_editor.as_ref() {
            let idx = ed.index;
            if let Some(c) = model.events_mut().commands.get_mut(idx) {
                apply_command_rows(&ed.rows, c);
            }
        }
    }
    fn commit_sub_editor(&mut self, model: &mut Model) {
        let Some(se) = self.sub_editor.as_ref() else {
            return;
        };
        let Some(ed) = se.editor.as_ref() else {
            return;
        };
        let sub_idx = ed.index;
        if let Some(sub) = model
            .events_mut()
            .sinks
            .get_mut(se.sink_index)
            .and_then(|s| s.subscriptions.as_mut())
            .and_then(|subs| subs.get_mut(sub_idx))
        {
            apply_subscription_rows(&ed.rows, sub);
        }
    }
}

impl Default for EventsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl Page for EventsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        // EMPTY STATE: byte-identical fallback to the original layout.
        if Self::is_empty_state(model) {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(5), Constraint::Min(0)])
                .split(area);
            self.list.render(chunks[0], buf, model.profile());

            let lines: Vec<Line<'_>> = model
                .config()
                .events
                .as_ref()
                .map(|e| {
                    e.bindings
                        .iter()
                        .map(|b| {
                            Line::from(format!(
                                "{:<24} on=[{}] actions=[{}]",
                                b.name,
                                b.on.join(","),
                                b.actions.join(",")
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Global [[events.bindings]] (read-only here)");
            Paragraph::new(lines).block(block).render(chunks[1], buf);
            return;
        }

        // SUB-EDITOR overlay: when the webpush subscription sub-editor is open
        // it owns the whole page area (a modal nested list/editor).
        if self.sub_editor.is_some() {
            self.render_sub_editor(area, buf, model);
            return;
        }

        // POPULATED STATE: tags + sinks + bindings (+ commands when present)
        // (+ settings when present). The Commands region is rendered only when
        // non-empty OR active, and the Settings region only when any scalar is
        // set OR it is the active region — so the zero-commands / zero-settings
        // populated layout is byte-identical to the original.
        let show_commands = Self::n_commands(model) > 0 || self.region == Region::Commands;
        let show_settings =
            model.events().is_some_and(has_settings) || self.region == Region::Settings;
        // Tags is the fixed top region; sinks/bindings/commands share the
        // flexible middle; the settings editor (5 rows × 3 lines = 15 +
        // borders) gets a fixed slot at the tail so it never starves the
        // Min(0) list regions above it.
        let mut constraints: Vec<Constraint> = vec![Constraint::Length(5)];
        constraints.push(Constraint::Min(0)); // sinks
        constraints.push(Constraint::Min(0)); // bindings
        if show_commands {
            constraints.push(Constraint::Min(0)); // commands
        }
        if show_settings {
            constraints.push(Constraint::Length(17));
        }
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);
        self.list.render(chunks[0], buf, model.profile());

        let mut idx = 1;
        self.render_sinks(chunks[idx], buf, model);
        idx += 1;
        self.render_bindings(chunks[idx], buf, model);
        idx += 1;
        if show_commands {
            self.render_commands(chunks[idx], buf, model);
            idx += 1;
        }
        if show_settings {
            self.render_settings(chunks[idx], buf, model);
        }
    }

    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        // SUB-EDITOR modal: consumes all keys while open.
        if self.sub_editor.is_some() {
            return self.on_key_sub_editor(key, model);
        }

        // EMPTY STATE: behave exactly like the original tags-only page.
        if Self::is_empty_state(model) && self.region == Region::Tags {
            return self.on_key_tags(key, model);
        }

        // Tab cycles regions forward (a convenience shortcut). Note that
        // when this page is driven through `App`, App consumes Tab for
        // page-nav; the at-boundary Down/Up crossings handled inside each
        // per-region handler are the App-reachable path between regions.
        if matches!(key.code, KeyCode::Tab) && !self.is_editing() {
            self.region = self.next_region();
            return false;
        }

        match self.region {
            Region::Tags => self.on_key_tags(key, model),
            Region::Settings => self.on_key_settings(key, model),
            Region::Sinks => self.on_key_sinks(key, model),
            Region::Bindings => self.on_key_bindings(key, model),
            Region::Commands => self.on_key_commands(key, model),
        }
    }

    fn focused_help(&self) -> Option<&str> {
        if let Some(se) = self.sub_editor.as_ref() {
            return se
                .editor
                .as_ref()
                .and_then(|e| e.rows.get(e.focus))
                .map(|r| r.help)
                .or(Some("Subscriptions: a=add d=del Enter=edit Left=back"));
        }
        match self.region {
            Region::Tags => self.list.focused_help(),
            Region::Settings => self
                .settings_editor
                .as_ref()
                .and_then(|e| e.rows.get(e.focus))
                .map(|r| r.help)
                .or(Some("Events settings: Enter=edit ↑/↓=move region")),
            Region::Sinks => self
                .sink_editor
                .as_ref()
                .and_then(|e| e.rows.get(e.focus))
                .map(|r| r.help)
                .or(Some("Sinks: a=add d=del Enter=edit ↑/↓=move region")),
            Region::Bindings => self
                .binding_editor
                .as_ref()
                .and_then(|e| e.rows.get(e.focus))
                .map(|r| r.help)
                .or(Some("Bindings: a=add d=del Enter=edit ↑/↓=move region")),
            Region::Commands => self
                .command_editor
                .as_ref()
                .and_then(|e| e.rows.get(e.focus))
                .map(|r| r.help)
                .or(Some("Commands: a=add d=del Enter=edit ↑/↓=move region")),
        }
    }

    fn focused_position(&self) -> Option<(usize, usize)> {
        match self.region {
            Region::Tags => self.list.focus_position(),
            _ => None,
        }
    }

    fn is_editing(&self) -> bool {
        if let Some(se) = self.sub_editor.as_ref() {
            return se.editor.as_ref().is_some_and(|e| e.editing);
        }
        match self.region {
            Region::Tags => self.list.editing,
            Region::Settings => self.settings_editor.as_ref().is_some_and(|e| e.editing),
            Region::Sinks => self.sink_editor.as_ref().is_some_and(|e| e.editing),
            Region::Bindings => self.binding_editor.as_ref().is_some_and(|e| e.editing),
            Region::Commands => self.command_editor.as_ref().is_some_and(|e| e.editing),
        }
    }
}

impl EventsPage {
    fn next_region(&self) -> Region {
        match self.region {
            Region::Tags => Region::Sinks,
            Region::Sinks => Region::Bindings,
            Region::Bindings => Region::Commands,
            Region::Commands => Region::Settings,
            Region::Settings => Region::Tags,
        }
    }

    fn on_key_tags(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if self.list.editing {
            let changed = self.list.on_edit_key(key, model.profile_mut_silent());
            if changed {
                model.mark_dirty();
            }
            return changed;
        }
        // Down crosses into the Sinks region (App-reachable region nav).
        // The tags region is a single FieldList row, so Down would
        // otherwise wrap to itself.
        if matches!(key.code, KeyCode::Down | KeyCode::Char('j')) {
            self.region = Region::Sinks;
            return false;
        }
        self.list.on_nav_key(key, model.profile());
        false
    }

    /// Key handler for the Settings region (top-level `[events]` scalars).
    /// The region is backed by a persistent [`RowEditor`] lazily built on
    /// entry; unlike the list regions it has no add/delete — it edits the
    /// single `Events` struct in place. Settings sits at the tail of the
    /// region cycle: boundary Up (in nav mode, at the first row) crosses up
    /// into Commands, boundary Down (at the last row) wraps round to Tags;
    /// everything else delegates to the editor.
    fn on_key_settings(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if self.settings_editor.is_none() {
            self.open_settings_editor(model);
        }
        // Boundary region crossing in nav mode (not while editing a field).
        let editing = self.settings_editor.as_ref().is_some_and(|e| e.editing);
        if !editing {
            if matches!(key.code, KeyCode::Up | KeyCode::Char('k'))
                && self.settings_editor.as_ref().is_some_and(|e| e.focus == 0)
            {
                self.region = Region::Commands;
                return false;
            }
            if matches!(key.code, KeyCode::Down | KeyCode::Char('j'))
                && self
                    .settings_editor
                    .as_ref()
                    .is_some_and(|e| e.focus + 1 >= e.rows.len())
            {
                self.region = Region::Tags;
                return false;
            }
        }
        let Some(ed) = self.settings_editor.as_mut() else {
            return false;
        };
        let (changed, close) = ed.on_key(key);
        if changed {
            self.commit_settings_editor(model);
            return true;
        }
        if close {
            // Esc/Left out of the settings region: drop the editor and hand
            // focus back up to Commands (mirrors a list region's pane-nav left).
            self.settings_editor = None;
            self.region = Region::Commands;
        }
        false
    }

    fn on_key_sinks(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if let Some(ed) = self.sink_editor.as_mut() {
            // Special-case: nav-mode Enter/Right on the `subscriptions` marker
            // row opens the nested subscription sub-editor instead of starting
            // a text edit.
            if !ed.editing
                && matches!(key.code, KeyCode::Enter | KeyCode::Right)
                && ed
                    .rows
                    .get(ed.focus)
                    .is_some_and(|r| r.label == "subscriptions")
            {
                let sink_index = ed.index;
                self.sub_editor = Some(SubEditor::new(sink_index));
                return false;
            }
            let (changed, close) = ed.on_key(key);
            if changed {
                // Detect a committed `type` change and rebuild the editor rows
                // for the new kind (preserving shared fields via the model).
                let type_changed = self
                    .sink_editor
                    .as_ref()
                    .and_then(|e| e.rows.get(e.focus))
                    .is_some_and(|r| r.label == "type");
                self.commit_sink_editor(model);
                if type_changed {
                    self.rebuild_sink_rows_for_kind(model);
                }
                return true;
            }
            if close {
                self.sink_editor = None;
            }
            return false;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                // At the top of the list, Up crosses up into Tags.
                if self.sink_sel == 0 {
                    self.region = Region::Tags;
                } else {
                    self.sink_sel -= 1;
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = Self::n_sinks(model);
                if self.sink_sel + 1 < n {
                    self.sink_sel += 1;
                } else {
                    // At the bottom of the list, Down crosses into Bindings.
                    self.region = Region::Bindings;
                }
                false
            }
            KeyCode::Enter | KeyCode::Right => {
                if self.sink_sel < Self::n_sinks(model) {
                    self.open_sink_editor(model, self.sink_sel);
                }
                false
            }
            KeyCode::Char('a') => {
                let n = Self::n_sinks(model);
                let sink = EventSink {
                    name: format!("sink-{}", n + 1),
                    kind: SINK_KINDS[0].to_owned(),
                    ..Default::default()
                };
                model.events_mut().sinks.push(sink);
                self.sink_sel = n;
                self.open_sink_editor(model, n);
                true
            }
            KeyCode::Char('d') => {
                let n = Self::n_sinks(model);
                if self.sink_sel < n {
                    model.events_mut().sinks.remove(self.sink_sel);
                    let after = Self::n_sinks(model);
                    if self.sink_sel >= after && self.sink_sel > 0 {
                        self.sink_sel -= 1;
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Rebuild the open sink editor's rows for the (just-committed) kind.
    /// Shared fields (name/timeout/auth/body_template) survive because they
    /// live on the model sink and the rebuild re-reads them; non-active-kind
    /// struct fields are untouched (never overwritten by `apply_sink_rows`),
    /// so they round-trip on save. Focus is parked back on the `type` row.
    fn rebuild_sink_rows_for_kind(&mut self, model: &Model) {
        let Some(ed) = self.sink_editor.as_mut() else {
            return;
        };
        let idx = ed.index;
        if let Some(s) = model.events().and_then(|e| e.sinks.get(idx)) {
            let rows = sink_rows(s);
            // `type` is always row index 1.
            let focus = 1.min(rows.len().saturating_sub(1));
            ed.rows = rows;
            ed.focus = focus;
            ed.editing = false;
        }
    }

    fn on_key_bindings(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if let Some(ed) = self.binding_editor.as_mut() {
            let (changed, close) = ed.on_key(key);
            if changed {
                self.commit_binding_editor(model);
                return true;
            }
            if close {
                self.binding_editor = None;
            }
            return false;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                // At the top of the list, Up crosses up into Sinks.
                if self.binding_sel == 0 {
                    self.region = Region::Sinks;
                } else {
                    self.binding_sel -= 1;
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = Self::n_bindings(model);
                if self.binding_sel + 1 < n {
                    self.binding_sel += 1;
                } else {
                    // At the bottom of the list, Down crosses into Commands.
                    self.region = Region::Commands;
                }
                false
            }
            KeyCode::Enter | KeyCode::Right => {
                if self.binding_sel < Self::n_bindings(model) {
                    self.open_binding_editor(model, self.binding_sel);
                }
                false
            }
            KeyCode::Char('a') => {
                let n = Self::n_bindings(model);
                let binding = EventBinding {
                    name: format!("binding-{}", n + 1),
                    ..Default::default()
                };
                model.events_mut().bindings.push(binding);
                self.binding_sel = n;
                self.open_binding_editor(model, n);
                true
            }
            KeyCode::Char('d') => {
                let n = Self::n_bindings(model);
                if self.binding_sel < n {
                    model.events_mut().bindings.remove(self.binding_sel);
                    let after = Self::n_bindings(model);
                    if self.binding_sel >= after && self.binding_sel > 0 {
                        self.binding_sel -= 1;
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    fn on_key_commands(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if let Some(ed) = self.command_editor.as_mut() {
            let (changed, close) = ed.on_key(key);
            if changed {
                self.commit_command_editor(model);
                return true;
            }
            if close {
                self.command_editor = None;
            }
            return false;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                // At the top of the list, Up crosses up into Bindings.
                if self.command_sel == 0 {
                    self.region = Region::Bindings;
                } else {
                    self.command_sel -= 1;
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = Self::n_commands(model);
                if self.command_sel + 1 < n {
                    self.command_sel += 1;
                } else {
                    // At the bottom of the list, Down crosses into Settings.
                    self.region = Region::Settings;
                }
                false
            }
            KeyCode::Enter | KeyCode::Right => {
                if self.command_sel < Self::n_commands(model) {
                    self.open_command_editor(model, self.command_sel);
                }
                false
            }
            KeyCode::Char('a') => {
                let n = Self::n_commands(model);
                let command = EventCommand {
                    name: format!("command-{}", n + 1),
                    ..Default::default()
                };
                model.events_mut().commands.push(command);
                self.command_sel = n;
                self.open_command_editor(model, n);
                true
            }
            KeyCode::Char('d') => {
                let n = Self::n_commands(model);
                if self.command_sel < n {
                    model.events_mut().commands.remove(self.command_sel);
                    let after = Self::n_commands(model);
                    if self.command_sel >= after && self.command_sel > 0 {
                        self.command_sel -= 1;
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Modal key handler for the webpush subscription sub-editor.
    fn on_key_sub_editor(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        // Inner per-subscription row editor open?
        if self
            .sub_editor
            .as_ref()
            .is_some_and(|se| se.editor.is_some())
        {
            let (changed, close) = self
                .sub_editor
                .as_mut()
                .and_then(|se| se.editor.as_mut())
                .map_or((false, false), |ed| ed.on_key(key));
            if changed {
                self.commit_sub_editor(model);
                return true;
            }
            if close {
                if let Some(se) = self.sub_editor.as_mut() {
                    se.editor = None;
                }
            }
            return false;
        }
        // Sub-list mode.
        let sink_index = self.sub_editor.as_ref().map_or(0, |se| se.sink_index);
        let n_subs = model
            .events()
            .and_then(|e| e.sinks.get(sink_index))
            .and_then(|s| s.subscriptions.as_ref())
            .map_or(0, Vec::len);
        match key.code {
            KeyCode::Esc | KeyCode::Left => {
                // Close the sub-editor, back to the sink editor.
                self.sub_editor = None;
                false
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if let Some(se) = self.sub_editor.as_mut() {
                    se.sel = se.sel.saturating_sub(1);
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if let Some(se) = self.sub_editor.as_mut() {
                    if se.sel + 1 < n_subs {
                        se.sel += 1;
                    }
                }
                false
            }
            KeyCode::Enter | KeyCode::Right => {
                let sel = self.sub_editor.as_ref().map_or(0, |se| se.sel);
                if sel < n_subs {
                    self.open_sub_editor_row(model, sel);
                }
                false
            }
            KeyCode::Char('a') => {
                let new_idx = {
                    let subs = model
                        .events_mut()
                        .sinks
                        .get_mut(sink_index)
                        .map(|s| s.subscriptions.get_or_insert_with(Vec::new));
                    match subs {
                        Some(subs) => {
                            subs.push(EventSinkSubscription::default());
                            Some(subs.len() - 1)
                        }
                        None => None,
                    }
                };
                if let Some(new_idx) = new_idx {
                    if let Some(se) = self.sub_editor.as_mut() {
                        se.sel = new_idx;
                    }
                    self.open_sub_editor_row(model, new_idx);
                }
                true
            }
            KeyCode::Char('d') => {
                let sel = self.sub_editor.as_ref().map_or(0, |se| se.sel);
                if sel < n_subs {
                    if let Some(subs) = model
                        .events_mut()
                        .sinks
                        .get_mut(sink_index)
                        .and_then(|s| s.subscriptions.as_mut())
                    {
                        subs.remove(sel);
                        let after = subs.len();
                        if let Some(se) = self.sub_editor.as_mut() {
                            if se.sel >= after && se.sel > 0 {
                                se.sel -= 1;
                            }
                        }
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Render the Events settings region (top-level `[events]` scalars). When
    /// the region is focused the live [`RowEditor`] is rendered (lazily built
    /// on entry); otherwise a read-only summary of the configured scalars.
    fn render_settings(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let active = self.region == Region::Settings;
        if active && self.settings_editor.is_none() {
            self.open_settings_editor(model);
        }
        let title = if active {
            "Events settings* (Enter=edit ↑/↓=move region)"
        } else {
            "Events settings (Tab to focus)"
        };
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        block.render(area, buf);
        if active {
            if let Some(ed) = self.settings_editor.as_ref() {
                ed.render(inner, buf);
                return;
            }
        }
        // Read-only summary (region not focused).
        let e = model.events().cloned().unwrap_or_default();
        let lines = vec![
            Line::from(format!(
                "ring_capacity:     {}",
                e.ring_capacity.map(|c| c.to_string()).unwrap_or_default()
            )),
            Line::from(format!(
                "retry_interval:    {}",
                e.retry_interval.unwrap_or_default()
            )),
            Line::from(format!(
                "spool_dir:         {}",
                e.spool_dir.unwrap_or_default()
            )),
            Line::from(format!(
                "spool_max_bytes:   {}",
                e.spool_max_bytes.unwrap_or_default()
            )),
            Line::from(format!(
                "default_min_level: {}",
                e.default_min_level.unwrap_or_default()
            )),
        ];
        Paragraph::new(lines).render(inner, buf);
    }

    fn render_sinks(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        let sinks = model.events().map_or(&[][..], |e| e.sinks.as_slice());
        let items: Vec<ListItem<'_>> = sinks
            .iter()
            .map(|s| ListItem::new(format!("{:>14} [{}]", s.name, s.kind)))
            .collect();
        if !items.is_empty() {
            self.sink_list_state
                .select(Some(self.sink_sel.min(items.len() - 1)));
        }
        let active = self.region == Region::Sinks;
        let title = if active {
            "Sinks* (a=add d=del Enter=edit)"
        } else {
            "Sinks (Tab to focus)"
        };
        let hl = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let block = Block::default().borders(Borders::ALL).title(title);
        let list = List::new(items)
            .block(block)
            .highlight_style(hl)
            .highlight_symbol("▶ ");
        StatefulWidget::render(list, cols[0], buf, &mut self.sink_list_state);

        if let Some(ed) = self.sink_editor.as_ref() {
            ed.render(cols[1], buf);
        } else if let Some(s) = sinks.get(self.sink_sel) {
            // Both secret-shaped fields (`auth` ref, `vapid_private_key`) are
            // rendered redacted here — cleartext never reaches a snapshot.
            let lines = vec![
                Line::from(format!("name:   {}", s.name)),
                Line::from(format!("type:   {}", s.kind)),
                Line::from(format!("url:    {}", s.url.clone().unwrap_or_default())),
                Line::from(format!("method: {}", s.method.clone().unwrap_or_default())),
                Line::from(format!(
                    "auth:   {}",
                    if s.auth.is_some() { "[REDACTED]" } else { "" }
                )),
                Line::from(format!(
                    "vapid:  {}",
                    if s.vapid_private_key.is_some() {
                        "[REDACTED]"
                    } else {
                        ""
                    }
                )),
            ];
            let block = Block::default().borders(Borders::ALL).title("Sink detail");
            Paragraph::new(lines).block(block).render(cols[1], buf);
        } else {
            let block = Block::default().borders(Borders::ALL).title("Sink detail");
            Paragraph::new("(no sinks — press `a` to add)")
                .block(block)
                .render(cols[1], buf);
        }
    }

    fn render_bindings(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        let bindings = model.events().map_or(&[][..], |e| e.bindings.as_slice());
        let items: Vec<ListItem<'_>> = bindings
            .iter()
            .map(|b| ListItem::new(format!("{:>14} on=[{}]", b.name, b.on.join(","))))
            .collect();
        if !items.is_empty() {
            self.binding_list_state
                .select(Some(self.binding_sel.min(items.len() - 1)));
        }
        let active = self.region == Region::Bindings;
        let title = if active {
            "Bindings* (a=add d=del Enter=edit)"
        } else {
            "Bindings (Tab to focus)"
        };
        let hl = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let block = Block::default().borders(Borders::ALL).title(title);
        let list = List::new(items)
            .block(block)
            .highlight_style(hl)
            .highlight_symbol("▶ ");
        StatefulWidget::render(list, cols[0], buf, &mut self.binding_list_state);

        if let Some(ed) = self.binding_editor.as_ref() {
            ed.render(cols[1], buf);
        } else if let Some(b) = bindings.get(self.binding_sel) {
            let lines = vec![
                Line::from(format!("name:      {}", b.name)),
                Line::from(format!("on:        {}", b.on.join(", "))),
                Line::from(format!("actions:   {}", b.actions.join(", "))),
                Line::from(format!(
                    "min_level: {}",
                    b.min_level.clone().unwrap_or_default()
                )),
                Line::from(format!(
                    "throttle:  {}",
                    b.throttle.clone().unwrap_or_default()
                )),
            ];
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Binding detail");
            Paragraph::new(lines).block(block).render(cols[1], buf);
        } else {
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Binding detail");
            Paragraph::new("(no bindings — press `a` to add)")
                .block(block)
                .render(cols[1], buf);
        }
    }

    fn render_commands(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        let commands = model.events().map_or(&[][..], |e| e.commands.as_slice());
        let items: Vec<ListItem<'_>> = commands
            .iter()
            .map(|c| ListItem::new(format!("{:>14} [{}]", c.name, c.command)))
            .collect();
        if !items.is_empty() {
            self.command_list_state
                .select(Some(self.command_sel.min(items.len() - 1)));
        }
        let active = self.region == Region::Commands;
        let title = if active {
            "Commands* (a=add d=del Enter=edit)"
        } else {
            "Commands (Tab to focus)"
        };
        let hl = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let block = Block::default().borders(Borders::ALL).title(title);
        let list = List::new(items)
            .block(block)
            .highlight_style(hl)
            .highlight_symbol("▶ ");
        StatefulWidget::render(list, cols[0], buf, &mut self.command_list_state);

        if let Some(ed) = self.command_editor.as_ref() {
            ed.render(cols[1], buf);
        } else if let Some(c) = commands.get(self.command_sel) {
            let lines = vec![
                Line::from(format!("name:       {}", c.name)),
                Line::from(format!("command:    {}", c.command)),
                Line::from(format!(
                    "args:       {}",
                    c.args.clone().unwrap_or_default().join(", ")
                )),
                Line::from(format!("allow_exec: {}", c.allow_exec.unwrap_or(false))),
                Line::from(format!(
                    "timeout:    {}",
                    c.timeout.clone().unwrap_or_default()
                )),
            ];
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Command detail");
            Paragraph::new(lines).block(block).render(cols[1], buf);
        } else {
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Command detail");
            Paragraph::new("(no commands — press `a` to add)")
                .block(block)
                .render(cols[1], buf);
        }
    }

    /// Render the modal webpush subscription sub-editor: a list of
    /// subscriptions on the left, the focused subscription's detail/editor on
    /// the right. The per-subscription `auth` secret is always redacted.
    fn render_sub_editor(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let Some(se) = self.sub_editor.as_mut() else {
            return;
        };
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
            .split(area);

        let subs = model
            .events()
            .and_then(|e| e.sinks.get(se.sink_index))
            .and_then(|s| s.subscriptions.as_ref())
            .map_or(&[][..], Vec::as_slice);
        let items: Vec<ListItem<'_>> = subs
            .iter()
            .enumerate()
            .map(|(i, sub)| {
                let ep = if sub.endpoint.is_empty() {
                    "(unset)"
                } else {
                    sub.endpoint.as_str()
                };
                ListItem::new(format!("#{i} {ep}"))
            })
            .collect();
        if !items.is_empty() {
            se.list_state.select(Some(se.sel.min(items.len() - 1)));
        }
        let hl = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Subscriptions* (a=add d=del Enter=edit Left=back)");
        let list = List::new(items)
            .block(block)
            .highlight_style(hl)
            .highlight_symbol("▶ ");
        StatefulWidget::render(list, cols[0], buf, &mut se.list_state);

        if let Some(ed) = se.editor.as_ref() {
            ed.render(cols[1], buf);
        } else if let Some(sub) = subs.get(se.sel) {
            let lines = vec![
                Line::from(format!("endpoint: {}", sub.endpoint)),
                Line::from(format!("p256dh:   {}", sub.p256dh)),
                Line::from(format!(
                    "auth:     {}",
                    if sub.auth.expose().is_empty() {
                        ""
                    } else {
                        "[REDACTED]"
                    }
                )),
            ];
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Subscription detail");
            Paragraph::new(lines).block(block).render(cols[1], buf);
        } else {
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Subscription detail");
            Paragraph::new("(no subscriptions — press `a` to add)")
                .block(block)
                .render(cols[1], buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn model() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        )
    }

    fn model_with_events() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[[events.sinks]]
name = "webhook"
type = "http"
url = "https://example.com/hook"

[[events.bindings]]
name = "notify"
on = ["profile.failed"]
actions = ["webhook"]
"#,
        )
    }

    #[test]
    fn renders_with_no_global_bindings() {
        let mut p = EventsPage::new();
        let m = model();
        let area = Rect::new(0, 0, 100, 20);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn tag_edit_round_trip() {
        let mut p = EventsPage::new();
        let mut m = model();
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (List)
        for c in "prod, eu-west".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        let tags = m.profile().tags.clone().unwrap_or_default();
        assert_eq!(tags, vec!["prod", "eu-west"]);
    }

    #[test]
    fn empty_state_is_detected() {
        let m = model();
        assert!(EventsPage::is_empty_state(&m));
        let m2 = model_with_events();
        assert!(!EventsPage::is_empty_state(&m2));
    }

    #[test]
    fn add_sink_pushes_and_opens_editor() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Sinks;
        assert_eq!(EventsPage::n_sinks(&m), 1);
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(EventsPage::n_sinks(&m), 2);
        assert!(p.sink_editor.is_some());
        assert_eq!(m.events().unwrap().sinks[1].name, "sink-2");
        assert_eq!(m.events().unwrap().sinks[1].kind, "http");
    }

    #[test]
    fn sink_editor_edits_url() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on sink 0
        assert!(p.sink_editor.is_some());
        // Move to url (row 2: name, type, url).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..40 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "https://new/hook".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.events().unwrap().sinks[0].url.as_deref(),
            Some("https://new/hook")
        );
    }

    #[test]
    fn sink_editor_left_closes() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor
        assert!(p.sink_editor.is_some());
        p.on_key(k(KeyCode::Left), &mut m); // close (not field-editing)
        assert!(p.sink_editor.is_none());
    }

    #[test]
    fn sink_auth_secret_invalid_blocks_commit() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor
                                             // auth is row index 6.
        for _ in 0..6 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        for c in "garbage".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit attempt (must fail)
        let ed = p.sink_editor.as_ref().expect("editor still open");
        assert!(ed.editing, "still editing after failed commit");
        assert!(ed.rows[6].last_error.is_some());
        assert!(m.events().unwrap().sinks[0].auth.is_none());
    }

    #[test]
    fn sink_auth_secret_valid_commits() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m);
        for _ in 0..6 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "secret://ns/key".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(
            m.events().unwrap().sinks[0].auth.as_deref(),
            Some("secret://ns/key")
        );
    }

    #[test]
    fn add_binding_pushes_and_opens_editor() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Bindings;
        assert_eq!(EventsPage::n_bindings(&m), 1);
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(EventsPage::n_bindings(&m), 2);
        assert!(p.binding_editor.is_some());
        assert_eq!(m.events().unwrap().bindings[1].name, "binding-2");
    }

    #[test]
    fn binding_editor_edits_on_list() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Bindings;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on binding 0
                                             // Move to `on` (row 1).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..40 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "a, b".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.events().unwrap().bindings[0].on,
            vec!["a".to_owned(), "b".to_owned()]
        );
    }

    #[test]
    fn delete_sink_removes_entry() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Char('d')), &mut m);
        assert_eq!(EventsPage::n_sinks(&m), 0);
    }

    #[test]
    fn tab_cycles_regions_when_populated() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        assert_eq!(p.region, Region::Tags);
        p.on_key(k(KeyCode::Tab), &mut m);
        assert_eq!(p.region, Region::Sinks);
        p.on_key(k(KeyCode::Tab), &mut m);
        assert_eq!(p.region, Region::Bindings);
        p.on_key(k(KeyCode::Tab), &mut m);
        assert_eq!(p.region, Region::Commands);
        p.on_key(k(KeyCode::Tab), &mut m);
        assert_eq!(p.region, Region::Settings);
        p.on_key(k(KeyCode::Tab), &mut m);
        assert_eq!(p.region, Region::Tags);
    }

    #[test]
    fn secret_row_display_is_redacted() {
        let row = EditorRow::secret("auth", "h", "secret://ns/k".to_owned());
        assert_eq!(row.display(), "[REDACTED]");
        let empty = EditorRow::secret("auth", "h", String::new());
        assert_eq!(empty.display(), "");
    }

    #[test]
    fn renders_populated_without_panic() {
        let mut p = EventsPage::new();
        let m = model_with_events();
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    // ---- t-events-tui-complete: new kinds, secrets, subscriptions,
    //      commands, pinned-TLS. ------------------------------------------

    fn model_webpush() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[[events.sinks]]
name = "push"
type = "webpush"
vapid_subject = "mailto:ops@example.com"
"#,
        )
    }

    #[test]
    fn sink_kinds_include_email_sms_webpush() {
        assert!(SINK_KINDS.contains(&"email"));
        assert!(SINK_KINDS.contains(&"sms"));
        assert!(SINK_KINDS.contains(&"webpush"));
        // The push discriminator string is `webpush`, NOT `push`.
        assert!(!SINK_KINDS.contains(&"push"));
    }

    #[test]
    fn webpush_rows_surface_vapid_and_subscriptions() {
        let m = model_webpush();
        let s = &m.events().unwrap().sinks[0];
        let labels: Vec<&str> = sink_rows(s).iter().map(|r| r.label).collect();
        assert!(labels.contains(&"vapid_subject"));
        assert!(labels.contains(&"vapid_private_key"));
        assert!(labels.contains(&"subscriptions"));
        assert!(labels.contains(&"pin_spki_sha256"));
        // The webpush row set must NOT surface http-only `method`.
        assert!(!labels.contains(&"method"));
    }

    #[test]
    fn email_rows_surface_email_fields_only() {
        let s = EventSink {
            name: "mailer".into(),
            kind: "email".into(),
            ..Default::default()
        };
        let labels: Vec<&str> = sink_rows(&s).iter().map(|r| r.label).collect();
        assert!(labels.contains(&"smtp"));
        assert!(labels.contains(&"from"));
        assert!(labels.contains(&"to"));
        assert!(labels.contains(&"subject_template"));
        assert!(labels.contains(&"body_template"));
        assert!(labels.contains(&"auth"));
        assert!(!labels.contains(&"vapid_private_key"));
    }

    #[test]
    fn apply_sink_rows_round_trips_subject_template() {
        let s = EventSink {
            name: "mailer".into(),
            kind: "email".into(),
            ..Default::default()
        };
        let mut rows = sink_rows(&s);
        for row in &mut rows {
            if row.label == "subject_template" {
                row.value = "[{{severity}}] {{kind}}".into();
            }
        }
        let mut out = s.clone();
        apply_sink_rows(&rows, &mut out);
        assert_eq!(
            out.subject_template.as_deref(),
            Some("[{{severity}}] {{kind}}")
        );
    }

    #[test]
    fn type_change_rebuilds_rows_for_new_kind() {
        let mut p = EventsPage::new();
        let mut m = model_with_events(); // sink 0 is http
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on sink 0
                                             // Move to `type` (row 1) and edit.
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit on the type Choice
                                             // http→webhook_post→command→mcp_notify→email; 4 Rights = email.
        for _ in 0..4 {
            p.on_key(k(KeyCode::Right), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit type change
        assert_eq!(m.events().unwrap().sinks[0].kind, "email");
        // Editor rows were rebuilt for the email kind.
        let ed = p.sink_editor.as_ref().expect("editor still open");
        let labels: Vec<&str> = ed.rows.iter().map(|r| r.label).collect();
        assert!(labels.contains(&"smtp"));
        assert!(!labels.contains(&"method"));
    }

    #[test]
    fn vapid_private_key_commits_without_secret_prefix() {
        let mut p = EventsPage::new();
        let mut m = model_webpush();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on the webpush sink
                                             // Rows: name,type,vapid_subject,vapid_private_key,...
                                             // vapid_private_key is row index 3.
        for _ in 0..3 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        let ed = p.sink_editor.as_ref().unwrap();
        assert_eq!(ed.rows[ed.focus].label, "vapid_private_key");
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
                                             // Raw base64url scalar (NOT a secret:// ref) — must commit OK.
        for c in "rawbase64urlkey".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit (no validation block)
        let ed = p.sink_editor.as_ref().expect("editor still open");
        assert!(!ed.editing, "opaque secret committed (no secret:// gate)");
        assert_eq!(
            m.events().unwrap().sinks[0]
                .vapid_private_key
                .as_ref()
                .map(|r| r.expose().to_owned()),
            Some("rawbase64urlkey".to_owned())
        );
    }

    #[test]
    fn secret_opaque_display_is_redacted_and_unvalidated() {
        let row = EditorRow::secret_opaque("vapid_private_key", "h", "rawkeymaterial".to_owned());
        assert_eq!(row.display(), "[REDACTED]");
        // SecretOpaque skips `secret://` validation entirely.
        assert!(row.validate().is_none());
        let empty = EditorRow::secret_opaque("vapid_private_key", "h", String::new());
        assert_eq!(empty.display(), "");
    }

    #[test]
    fn pinned_tls_list_edit_round_trips() {
        let mut p = EventsPage::new();
        let mut m = model_with_events(); // http sink 0
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m);
        // http rows: name,type,url,method,content_type,timeout,auth,
        // pin_spki_sha256,allow_self_signed,max_cert_chain_depth.
        // pin_spki_sha256 is row 7.
        for _ in 0..7 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        let ed = p.sink_editor.as_ref().unwrap();
        assert_eq!(ed.rows[ed.focus].label, "pin_spki_sha256");
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (List)
        for c in "abc, def".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.events().unwrap().sinks[0].pin_spki_sha256,
            vec!["abc".to_owned(), "def".to_owned()]
        );
    }

    #[test]
    fn command_add_edit_delete() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Commands;
        assert_eq!(EventsPage::n_commands(&m), 0);
        // Add.
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(EventsPage::n_commands(&m), 1);
        assert!(p.command_editor.is_some());
        assert_eq!(m.events().unwrap().commands[0].name, "command-1");
        // Edit `command` (row 1).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m);
        for c in "/usr/bin/true".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m);
        assert_eq!(m.events().unwrap().commands[0].command, "/usr/bin/true");
        // Close + delete.
        p.on_key(k(KeyCode::Left), &mut m);
        p.on_key(k(KeyCode::Char('d')), &mut m);
        assert_eq!(EventsPage::n_commands(&m), 0);
    }

    #[test]
    fn command_allow_exec_choice_commits_true() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Commands;
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open editor
                                                 // allow_exec is row 3.
        for _ in 0..3 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        let ed = p.command_editor.as_ref().unwrap();
        assert_eq!(ed.rows[ed.focus].label, "allow_exec");
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (Choice false→…)
        p.on_key(k(KeyCode::Right), &mut m); // cursor → true
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.events().unwrap().commands[0].allow_exec, Some(true));
    }

    #[test]
    fn subscription_add_edit_delete() {
        let mut p = EventsPage::new();
        let mut m = model_webpush();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m); // open sink editor
                                             // Move to the `subscriptions` row and open the sub-editor.
        let sub_row = {
            let ed = p.sink_editor.as_ref().unwrap();
            ed.rows
                .iter()
                .position(|r| r.label == "subscriptions")
                .unwrap()
        };
        for _ in 0..sub_row {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // open sub-editor (modal)
        assert!(p.sub_editor.is_some());
        // Add a subscription + open its row editor.
        p.on_key(k(KeyCode::Char('a')), &mut m);
        let n = m.events().unwrap().sinks[0]
            .subscriptions
            .as_ref()
            .map_or(0, Vec::len);
        assert_eq!(n, 1);
        // Edit `endpoint` (row 0).
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit endpoint
        for c in "https://push.example/ep".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.events().unwrap().sinks[0].subscriptions.as_ref().unwrap()[0].endpoint,
            "https://push.example/ep"
        );
        // Left closes the row editor (back to sub-list), then `d` deletes.
        p.on_key(k(KeyCode::Left), &mut m);
        p.on_key(k(KeyCode::Char('d')), &mut m);
        let n = m.events().unwrap().sinks[0]
            .subscriptions
            .as_ref()
            .map_or(0, Vec::len);
        assert_eq!(n, 0);
        // Left again closes the sub-editor entirely.
        p.on_key(k(KeyCode::Left), &mut m);
        assert!(p.sub_editor.is_none());
    }

    // ---- E7 / t-memleak: events settings region, dedupe rows, KNOWN_KINDS.

    #[test]
    fn known_kinds_includes_memory_leak_suspected() {
        assert!(KNOWN_KINDS.contains(&"memory.leak_suspected"));
        assert!(KNOWN_KINDS.contains(&"profile.failed"));
        // The `on` row help is derived from KNOWN_KINDS, so it surfaces the
        // runtime-detection kind as discoverability.
        assert!(on_help().contains("memory.leak_suspected"));
    }

    #[test]
    fn binding_rows_surface_dedupe_rows() {
        let b = EventBinding {
            name: "b".into(),
            ..Default::default()
        };
        let labels: Vec<&str> = binding_rows(&b).iter().map(|r| r.label).collect();
        assert!(labels.contains(&"dedupe.key"));
        assert!(labels.contains(&"dedupe.window"));
    }

    #[test]
    fn apply_binding_rows_builds_dedupe_lazily() {
        let mut b = EventBinding {
            name: "b".into(),
            ..Default::default()
        };
        // Both dedupe fields empty → None.
        let rows = binding_rows(&b);
        apply_binding_rows(&rows, &mut b);
        assert!(b.dedupe.is_none(), "empty dedupe fields must stay None");

        // Set only the window → Some with key None.
        let mut rows = binding_rows(&b);
        for row in &mut rows {
            if row.label == "dedupe.window" {
                row.value = "90s".into();
            }
        }
        apply_binding_rows(&rows, &mut b);
        let d = b.dedupe.as_ref().expect("dedupe materialized");
        assert_eq!(d.window.as_deref(), Some("90s"));
        assert!(d.key.is_none());

        // Set the key too; round-trips back through binding_rows.
        let mut rows = binding_rows(&b);
        for row in &mut rows {
            if row.label == "dedupe.key" {
                row.value = "kind".into();
            }
        }
        apply_binding_rows(&rows, &mut b);
        let d = b.dedupe.as_ref().unwrap();
        assert_eq!(d.key.as_deref(), Some("kind"));
        assert_eq!(d.window.as_deref(), Some("90s"));

        // Clearing both empties dedupe back to None.
        let mut rows = binding_rows(&b);
        for row in &mut rows {
            if matches!(row.label, "dedupe.key" | "dedupe.window") {
                row.value.clear();
            }
        }
        apply_binding_rows(&rows, &mut b);
        assert!(b.dedupe.is_none());
    }

    #[test]
    fn dedupe_edit_round_trips_through_editor() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Bindings;
        p.on_key(k(KeyCode::Enter), &mut m); // open binding editor (binding 0)
        let win_row = {
            let ed = p.binding_editor.as_ref().unwrap();
            ed.rows
                .iter()
                .position(|r| r.label == "dedupe.window")
                .unwrap()
        };
        for _ in 0..win_row {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        assert_eq!(
            p.binding_editor.as_ref().unwrap().rows[p.binding_editor.as_ref().unwrap().focus].label,
            "dedupe.window"
        );
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        for c in "45s".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.events().unwrap().bindings[0]
                .dedupe
                .as_ref()
                .and_then(|d| d.window.as_deref()),
            Some("45s")
        );
    }

    #[test]
    fn settings_rows_cover_all_scalars() {
        let e = Events::default();
        let labels: Vec<&str> = settings_rows(&e).iter().map(|r| r.label).collect();
        assert_eq!(
            labels,
            vec![
                "ring_capacity",
                "retry_interval",
                "spool_dir",
                "spool_max_bytes",
                "default_min_level",
            ]
        );
    }

    #[test]
    fn has_settings_gates_empty_state() {
        // A model with ONLY a settings scalar set is NOT empty-state, so the
        // populated layout (with the settings region) is shown.
        let m = Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[events]
ring_capacity = 2048
"#,
        );
        assert!(!EventsPage::is_empty_state(&m));
        assert!(has_settings(m.events().unwrap()));
        // A bare model stays empty-state.
        assert!(EventsPage::is_empty_state(&model()));
    }

    /// E4-F8: a non-numeric `ring_capacity` must be rejected with an inline
    /// error (field held open), not silently discarded via `.ok()`.
    #[test]
    fn settings_editor_rejects_non_numeric_ring_capacity() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Settings;
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit ring_capacity (row 0)
        for c in "xyz".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit attempt — rejected
        let ed = p.settings_editor.as_ref().expect("settings editor open");
        assert!(
            ed.rows[0].last_error.is_some(),
            "non-numeric ring_capacity must surface an inline error"
        );
        assert!(ed.editing, "validation failure must hold the field open");
    }

    #[test]
    fn settings_editor_commits_ring_capacity_and_min_level() {
        let mut p = EventsPage::new();
        let mut m = model_with_events();
        p.region = Region::Settings;
        // Entering the region lazily builds the editor on first key.
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit ring_capacity (row 0)
        for c in "4096".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.events().unwrap().ring_capacity, Some(4096));

        // Move to default_min_level (Choice, row 4) and pick `warn`.
        for _ in 0..4 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        assert_eq!(
            p.settings_editor.as_ref().unwrap().rows[p.settings_editor.as_ref().unwrap().focus]
                .label,
            "default_min_level"
        );
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (Choice "")
        for _ in 0..4 {
            p.on_key(k(KeyCode::Right), &mut m); // "" → trace → debug → info → warn
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.events().unwrap().default_min_level.as_deref(),
            Some("warn")
        );
    }

    #[test]
    fn settings_empty_choice_clears_default_min_level() {
        let mut e = Events {
            default_min_level: Some("warn".into()),
            ..Default::default()
        };
        // The empty Choice option maps back to None.
        let mut rows = settings_rows(&e);
        for row in &mut rows {
            if row.label == "default_min_level" {
                row.value = String::new();
            }
        }
        apply_settings_rows(&rows, &mut e);
        assert!(e.default_min_level.is_none());
    }

    #[test]
    fn subscription_auth_commits_as_opaque_secret() {
        let mut p = EventsPage::new();
        let mut m = model_webpush();
        p.region = Region::Sinks;
        p.on_key(k(KeyCode::Enter), &mut m);
        let sub_row = {
            let ed = p.sink_editor.as_ref().unwrap();
            ed.rows
                .iter()
                .position(|r| r.label == "subscriptions")
                .unwrap()
        };
        for _ in 0..sub_row {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // open sub-editor
        p.on_key(k(KeyCode::Char('a')), &mut m); // add + open row editor
                                                 // auth is row 2 (endpoint, p256dh, auth).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Down), &mut m);
        {
            let ed = p
                .sub_editor
                .as_ref()
                .and_then(|se| se.editor.as_ref())
                .unwrap();
            assert_eq!(ed.rows[ed.focus].label, "auth");
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        for c in "rawauthsecret".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit (no secret:// gate)
        assert_eq!(
            m.events().unwrap().sinks[0].subscriptions.as_ref().unwrap()[0]
                .auth
                .expose(),
            "rawauthsecret"
        );
    }
}
