//! Generic field-list runner used by most pages.
//!
//! A page that consists of a vertical list of labeled inputs declares its
//! fields as [`FieldDef`]s (each with a getter/setter pointing at the
//! [`spt_config::schema::Profile`]) and instantiates a [`FieldList`]. The
//! list handles focus movement, edit mode, and rendering uniformly.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};
use spt_config::schema::Profile;

use crate::widgets::{MultiSelect, NumericInput, Select, StringList, TextInput, Toggle};

/// A field's runtime value during editing.
#[derive(Debug, Clone)]
pub enum FieldValue {
    /// String / `Option<String>`.
    Text(String),
    /// Boolean toggle.
    Bool(bool),
    /// Numeric (decimal text storage; parsed on commit).
    Numeric(String),
    /// Single-choice from a fixed slice of options.
    Choice {
        /// Current value (canonical, written to TOML on commit).
        value: String,
        /// Static option list used both for cursor rotation and as the
        /// canonical values written on commit.
        options: &'static [&'static str],
        /// Optional parallel list of **display labels** shown to the
        /// user in place of `options[i]`. If `None`, the canonical
        /// option string is shown. Mapped by index, so it must match
        /// `options.len()` when provided. Used to give friendlier UX
        /// names (e.g. `"ssh3 (francoismichel)"` for the canonical
        /// `"ssh3"`) without breaking config file compatibility.
        display: Option<&'static [&'static str]>,
        /// Optional parallel list of **per-option help strings**
        /// surfaced in the page footer as the operator rotates the
        /// cursor. Indexed against `options` (not `display`). When
        /// `None`, the page footer falls back to `FieldDef::help`.
        /// Must match `options.len()` when `Some` — constructors
        /// validate this and silently drop a mismatched array.
        option_help: Option<&'static [&'static str]>,
    },
    /// Many-of-N choices.
    Multi {
        /// Currently-selected option list.
        value: Vec<String>,
        /// Static option list shown to the user.
        options: &'static [&'static str],
        /// Optional parallel list of **per-option help strings** keyed
        /// off the cursor (`multi.index`). Same contract as
        /// [`FieldValue::Choice::option_help`].
        option_help: Option<&'static [&'static str]>,
    },
    /// Comma-separated list editor, stored as a `Vec<String>`.
    List(Vec<String>),
    /// Free-form secret reference (validated for shape only).
    SecretRef(String),
}

/// A single field within a [`FieldList`].
pub struct FieldDef {
    /// User-visible label.
    pub label: &'static str,
    /// One-line help shown beneath the field when focused.
    pub help: &'static str,
    /// Read the current value out of the [`Profile`].
    pub get: Box<dyn Fn(&Profile) -> FieldValue>,
    /// Apply an edited value back to the [`Profile`].
    pub set: Box<dyn Fn(&mut Profile, FieldValue)>,
    /// Optional inline validator producing an error string.
    pub validate: Option<Box<dyn Fn(&FieldValue) -> Option<String>>>,
    /// Optional per-state help for `Bool` fields. Index `0` is shown
    /// when the value (or edit buffer in edit mode) is `false`; index
    /// `1` when it's `true`. `None` falls back to `help`. Lives on the
    /// `FieldDef` rather than inside the `Bool` variant because Bool has
    /// no `options` slice to parallel — see `FieldValue::Choice::option_help`
    /// for the Choice/Multi sibling.
    pub bool_option_help: Option<[&'static str; 2]>,
}

impl std::fmt::Debug for FieldDef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldDef")
            .field("label", &self.label)
            .finish()
    }
}

/// One row of editable state inside a [`FieldList`].
#[derive(Debug)]
pub struct Field {
    /// Static metadata + accessors.
    pub def: FieldDef,
    /// Buffered edit-mode value (committed back to the profile on Enter).
    pub edit_buf: Option<FieldValue>,
    /// Cursor / focus state for sub-widgets.
    text: TextInput,
    numeric: NumericInput,
    select: Select,
    multi: MultiSelect,
    list_state: StringList,
    pub(crate) last_error: Option<String>,
}

impl Field {
    /// Wrap a [`FieldDef`] with default per-row UI state.
    pub fn new(def: FieldDef) -> Self {
        Self {
            def,
            edit_buf: None,
            text: TextInput::default(),
            numeric: NumericInput::default(),
            select: Select::default(),
            multi: MultiSelect::default(),
            list_state: StringList::default(),
            last_error: None,
        }
    }

    /// Most recent validation error for this field, if any.
    #[must_use]
    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }
}

/// A list of fields rendered vertically with shared focus + edit state.
#[derive(Debug)]
pub struct FieldList {
    /// Rows.
    pub fields: Vec<Field>,
    /// Index of focused row.
    pub focus: usize,
    /// Whether focus is in *edit* mode (vs. navigation mode).
    pub editing: bool,
}

impl FieldList {
    /// Build a list from a vector of definitions.
    #[must_use]
    pub fn new(defs: Vec<FieldDef>) -> Self {
        Self {
            fields: defs.into_iter().map(Field::new).collect(),
            focus: 0,
            editing: false,
        }
    }

    /// Help text for the currently focused field. Surfaced by the App in
    /// the page footer so operators always see a one-line description of
    /// what the highlighted row controls.
    #[must_use]
    pub fn focused_help(&self) -> Option<&'static str> {
        self.fields.get(self.focus).map(|f| f.def.help)
    }

    /// Dynamic, **per-option** help text for the focused field. Falls
    /// back to [`Self::focused_help`] when the focused field has no
    /// option-specific help table for the current cursor position.
    ///
    /// Resolution order:
    ///
    /// * `Bool` editing → `def.bool_option_help[edit_buf as usize]` if set, else `def.help`.
    /// * `Bool` nav     → `def.bool_option_help[current_profile_value as usize]` if set, else `def.help`.
    /// * `Choice` editing → `option_help[select.index]` if set, else `def.help`.
    /// * `Choice` nav    → `option_help[options.position(current_value)]` if set, else `def.help`.
    /// * `Multi` editing → `option_help[multi.index]` if set, else `def.help`.
    /// * `Multi` nav     → `def.help` (no single cursor in nav mode).
    /// * Everything else → `def.help`.
    /// * Empty FieldList → `None`.
    #[must_use]
    pub fn focused_help_dynamic(&self, profile: &Profile) -> Option<&'static str> {
        let field = self.fields.get(self.focus)?;
        let def_help = field.def.help;

        // Bool path uses `bool_option_help` on the FieldDef.
        if let Some(boh) = field.def.bool_option_help {
            // Determine the relevant boolean: edit_buf if editing, else
            // the value currently stored in the profile.
            let b = if self.editing {
                match field.edit_buf.as_ref() {
                    Some(FieldValue::Bool(b)) => *b,
                    _ => match (field.def.get)(profile) {
                        FieldValue::Bool(b) => b,
                        _ => return Some(def_help),
                    },
                }
            } else {
                match (field.def.get)(profile) {
                    FieldValue::Bool(b) => b,
                    _ => return Some(def_help),
                }
            };
            return Some(boh[usize::from(b)]);
        }

        // Choice / Multi paths use `option_help` inside the FieldValue.
        // We need the current FieldValue to pull `option_help` from.
        if self.editing {
            match field.edit_buf.as_ref() {
                Some(FieldValue::Choice {
                    option_help: Some(oh),
                    ..
                }) => {
                    let idx = field.select.index;
                    return Some(oh.get(idx).copied().unwrap_or(def_help));
                }
                Some(FieldValue::Multi {
                    option_help: Some(oh),
                    ..
                }) => {
                    let idx = field.multi.index;
                    return Some(oh.get(idx).copied().unwrap_or(def_help));
                }
                _ => {}
            }
        } else {
            // Nav mode: derive from the profile-backed getter.
            match (field.def.get)(profile) {
                FieldValue::Choice {
                    value,
                    options,
                    option_help: Some(oh),
                    ..
                } => {
                    let idx = options.iter().position(|o| *o == value).unwrap_or(0);
                    return Some(oh.get(idx).copied().unwrap_or(def_help));
                }
                FieldValue::Multi {
                    option_help: Some(_),
                    ..
                } => {
                    // Multi has no cursor in nav mode → show the field help.
                    return Some(def_help);
                }
                _ => {}
            }
        }

        Some(def_help)
    }

    /// `(current_index, total)` for the focused row, 1-based. Surfaced by
    /// the App as `[3/12]` in the page status line so the operator always
    /// knows where they are.
    #[must_use]
    pub fn focus_position(&self) -> Option<(usize, usize)> {
        if self.fields.is_empty() {
            None
        } else {
            Some((self.focus + 1, self.fields.len()))
        }
    }

    /// Label of the focused field, e.g. `"id"` or `"protocol"`. The App
    /// pairs this with [`Self::focused_help`] to build the footer.
    #[must_use]
    pub fn focused_label(&self) -> Option<&'static str> {
        self.fields.get(self.focus).map(|f| f.def.label)
    }

    /// Move focus by `delta`, wrapping at the boundaries.
    pub fn move_focus(&mut self, delta: isize) {
        if self.fields.is_empty() {
            return;
        }
        let n = self.fields.len() as isize;
        let mut new = self.focus as isize + delta;
        while new < 0 {
            new += n;
        }
        self.focus = (new % n) as usize;
    }

    /// Begin editing the focused field. Reads the current value from the
    /// profile to seed the edit buffer.
    pub fn begin_edit(&mut self, profile: &Profile) {
        if let Some(field) = self.fields.get_mut(self.focus) {
            let cur = (field.def.get)(profile);
            // Pre-load widget state for list editors.
            if let FieldValue::List(ref vs) = cur {
                field.list_state = StringList::from_vec(vs);
                field.list_state.text.focused = true;
            }
            if let FieldValue::Text(ref s)
            | FieldValue::Numeric(ref s)
            | FieldValue::SecretRef(ref s) = cur
            {
                field.text.cursor = s.chars().count();
                field.text.focused = true;
                field.numeric.text = field.text.clone();
            }
            // Seed Select / MultiSelect cursor from the current value so
            // the highlight lands on the active option (not always 0).
            // Without this seeding, Enter on a Choice field overwrites
            // the profile with `options[0]` even when the user did not
            // intend a change.
            if let FieldValue::Choice {
                ref value, options, ..
            } = cur
            {
                field.select.index = options.iter().position(|o| *o == value).unwrap_or(0);
            }
            if let FieldValue::Multi {
                ref value, options, ..
            } = cur
            {
                field.multi.index = value
                    .first()
                    .and_then(|v| options.iter().position(|o| *o == v.as_str()))
                    .unwrap_or(0);
            }
            field.edit_buf = Some(cur);
            self.editing = true;
        }
    }

    /// Cancel any pending edit without writing back.
    pub fn cancel_edit(&mut self) {
        if let Some(f) = self.fields.get_mut(self.focus) {
            f.edit_buf = None;
        }
        self.editing = false;
    }

    /// Commit the focused edit back to the profile. Returns `true` if the
    /// model changed.
    pub fn commit_edit(&mut self, profile: &mut Profile) -> bool {
        let Some(field) = self.fields.get_mut(self.focus) else {
            return false;
        };
        let Some(buf) = field.edit_buf.take() else {
            return false;
        };
        // Validate first.
        if let Some(v) = &field.def.validate {
            if let Some(err) = v(&buf) {
                field.last_error = Some(err);
                // Restore the buffer so user can fix.
                field.edit_buf = Some(buf);
                return false;
            }
        }
        field.last_error = None;
        (field.def.set)(profile, buf);
        self.editing = false;
        true
    }

    /// Handle a navigation-mode key. Returns `true` if it consumed the event.
    pub fn on_nav_key(&mut self, key: KeyEvent, profile: &Profile) -> bool {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                self.move_focus(-1);
                true
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.move_focus(1);
                true
            }
            KeyCode::Enter | KeyCode::Char('e') | KeyCode::Char(' ') => {
                self.begin_edit(profile);
                true
            }
            _ => false,
        }
    }

    /// Handle an edit-mode key. Returns `true` if the underlying buffer
    /// changed.
    pub fn on_edit_key(&mut self, key: KeyEvent, profile: &mut Profile) -> bool {
        if matches!(key.code, KeyCode::Esc) {
            self.cancel_edit();
            return false;
        }
        if matches!(key.code, KeyCode::Tab) {
            // Treat Tab as commit-and-move-down for fast multi-field entry.
            let changed = self.commit_edit(profile);
            self.move_focus(1);
            return changed;
        }

        let Some(field) = self.fields.get_mut(self.focus) else {
            return false;
        };
        let Some(buf) = field.edit_buf.as_mut() else {
            return false;
        };

        match buf {
            FieldValue::Text(s) | FieldValue::SecretRef(s) => {
                let changed = field.text.on_key(s, key);
                if matches!(key.code, KeyCode::Char('\n')) {
                    return changed;
                }
                if matches!(key.code, KeyCode::Enter) {
                    return self.commit_edit(profile);
                }
                changed
            }
            FieldValue::Numeric(s) => {
                let changed = field.numeric.on_key(s, key);
                if matches!(key.code, KeyCode::Enter) {
                    return self.commit_edit(profile);
                }
                changed
            }
            FieldValue::Bool(b) => {
                let toggle = Toggle { focused: true };
                let changed = toggle.on_key(b, key);
                if matches!(key.code, KeyCode::Enter) {
                    return self.commit_edit(profile);
                }
                changed
            }
            FieldValue::Choice { value, options, .. } => {
                let changed = field.select.on_key(options, value, key);
                if matches!(key.code, KeyCode::Enter) {
                    return self.commit_edit(profile);
                }
                changed
            }
            FieldValue::Multi { value, options, .. } => {
                let changed = field.multi.on_key(options, value, key);
                // Enter is the universal commit key across every field
                // type. `s` is kept as an alternate commit shortcut for
                // operators used to that keystroke. Esc is handled at
                // the top of this function and cancels the edit.
                if matches!(key.code, KeyCode::Enter | KeyCode::Char('s')) {
                    return self.commit_edit(profile);
                }
                changed
            }
            FieldValue::List(_) => {
                let changed = field.list_state.on_key(key);
                if matches!(key.code, KeyCode::Enter) {
                    if let Some(FieldValue::List(_)) = field.edit_buf.as_ref() {
                        let parsed = field.list_state.parse();
                        field.edit_buf = Some(FieldValue::List(parsed));
                    }
                    return self.commit_edit(profile);
                }
                changed
            }
        }
    }

    /// Render the list into `area`.
    pub fn render(&mut self, area: Rect, buf: &mut Buffer, profile: &Profile) {
        let n = self.fields.len().max(1);
        let row_h = 3u16;
        let constraints: Vec<Constraint> = (0..n).map(|_| Constraint::Length(row_h)).collect();

        // Two-column outer layout: a 3-wide gutter on the left for the
        // selector glyph (`▶`), and the remaining width for the field rows.
        // The gutter is rendered at row 1 (middle of each 3-line block) so
        // the glyph aligns with the field label inside its bordered box.
        let outer = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(3), Constraint::Min(0)])
            .split(area);
        let gutter_area = outer[0];
        let body_area = outer[1];

        // Draw the selector glyph for the focused row before the field
        // boxes overdraw their own region. Using `Cell::set_symbol` keeps
        // this independent of widget styling.
        let gutter_rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints.clone())
            .split(gutter_area);
        for (i, row) in gutter_rows.iter().enumerate() {
            if i != self.focus {
                continue;
            }
            // Anchor glyph at the middle row of each 3-line cell so it
            // lines up with the bordered field label baseline.
            let y = row.y + 1;
            if y < gutter_area.y + gutter_area.height && row.x + 1 < buf.area().width {
                let cell = &mut buf[(row.x + 1, y)];
                cell.set_symbol("▶");
                let style = if self.editing {
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                };
                cell.set_style(style);
            }
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(body_area);

        for (i, field) in self.fields.iter_mut().enumerate() {
            let focused = i == self.focus;
            let editing = self.editing && focused;
            let area = chunks[i];

            // Sync sub-widget focus flags so render styling matches state.
            field.text.focused = editing;
            field.numeric.text.focused = editing;
            field.select.focused = editing;
            field.multi.focused = editing;
            field.list_state.text.focused = editing;

            let value: FieldValue = field
                .edit_buf
                .clone()
                .unwrap_or_else(|| (field.def.get)(profile));

            match value {
                FieldValue::Text(s) => {
                    field.text.render(area, buf, field.def.label, &s);
                }
                FieldValue::SecretRef(s) => {
                    // Secret redaction: in NAV mode (not actively editing
                    // this row) a non-empty secret reference renders the
                    // `[REDACTED]` marker — the cleartext `secret://…` body
                    // must never paint into the buffer where a screenshot
                    // or snapshot could capture it. While the operator is
                    // actively editing the row we show the live edit buffer
                    // so they can see what they are typing/correcting. The
                    // committed value is always the real reference (begin_edit
                    // seeds the edit buffer from the cleartext getter).
                    if editing || s.is_empty() {
                        field.text.render(area, buf, field.def.label, &s);
                    } else {
                        field.text.render(area, buf, field.def.label, "[REDACTED]");
                    }
                }
                FieldValue::Numeric(s) => {
                    field.numeric.render(area, buf, field.def.label, &s);
                }
                FieldValue::Bool(b) => {
                    let t = Toggle { focused: editing };
                    t.render(area, buf, field.def.label, b);
                }
                FieldValue::Choice {
                    ref value,
                    options,
                    display,
                    ..
                } => {
                    // If the FieldDef supplied display labels, use those
                    // for rendering only — the underlying option list and
                    // committed value stay canonical. This lets us show
                    // "ssh3 (francoismichel)" while still writing
                    // `protocol = "ssh3"` to TOML.
                    let render_options: &[&str] = display.unwrap_or(options);
                    // The current value is the canonical option; map it
                    // back to its display label when one exists.
                    let render_current = display
                        .and_then(|d| {
                            options
                                .iter()
                                .position(|o| *o == value)
                                .and_then(|i| d.get(i))
                                .copied()
                        })
                        .unwrap_or(value.as_str());
                    field
                        .select
                        .render(area, buf, field.def.label, render_options, render_current);
                }
                FieldValue::Multi {
                    ref value, options, ..
                } => {
                    field
                        .multi
                        .render(area, buf, field.def.label, options, value);
                }
                FieldValue::List(ref vs) => {
                    let label = field.def.label;
                    if editing {
                        field.list_state.render(area, buf, label);
                    } else {
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
                        let line = Line::from(Span::raw(vs.join(", ")));
                        Paragraph::new(line).block(block).render(area, buf);
                    }
                }
            }
        }

        // Nav-mode focus highlight. Each widget already paints its own
        // bordered Block; in NAV mode (not actively editing) the widget
        // is drawn unstyled (default fg/bg) which makes "which field is
        // pre-selected" hard to see from the box alone — the operator
        // had to find the ▶ gutter glyph. Overlay a soft Yellow fg on
        // the focused row's border cells so the box itself stands out.
        // Edit mode is left untouched: the widget already paints the
        // border in bright Yellow + BOLD, and the gutter ▶ flips to
        // Green to mark the active edit.
        if !self.editing {
            if let Some(focus_chunk) = chunks.get(self.focus) {
                paint_nav_focus_border(buf, *focus_chunk);
            }
        }
    }
}

/// Tint the border cells of `area` Yellow (no BOLD) to indicate
/// nav-mode focus on a field whose widget would otherwise render in
/// the default style. Existing modifiers and bg are preserved.
fn paint_nav_focus_border(buf: &mut Buffer, area: Rect) {
    if area.width < 2 || area.height < 2 {
        return;
    }
    let buf_area = buf.area();
    let max_x = buf_area.x + buf_area.width;
    let max_y = buf_area.y + buf_area.height;
    let right = area.x + area.width - 1;
    let bottom = area.y + area.height - 1;
    // Top and bottom edges.
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
    // Left and right edges (skip the corners we already coloured).
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

// --- Convenience constructors ---------------------------------------------

/// Build a `FieldDef` for a `Option<String>` field on [`Profile`].
pub fn opt_text<F, G>(label: &'static str, help: &'static str, get: G, set: F) -> FieldDef
where
    G: Fn(&Profile) -> Option<String> + 'static,
    F: Fn(&mut Profile, Option<String>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Text(get(p).unwrap_or_default())),
        set: Box::new(move |p, v| {
            if let FieldValue::Text(s) = v {
                set(p, if s.is_empty() { None } else { Some(s) });
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Build a `FieldDef` for a `Option<bool>` field.
///
/// Kept available for callers that don't need per-state help; the
/// in-tree pages all migrated to [`opt_bool_with_help`] in t-option-help.
#[allow(dead_code)]
pub fn opt_bool<F, G>(label: &'static str, help: &'static str, get: G, set: F) -> FieldDef
where
    G: Fn(&Profile) -> Option<bool> + 'static,
    F: Fn(&mut Profile, Option<bool>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Bool(get(p).unwrap_or(false))),
        set: Box::new(move |p, v| {
            if let FieldValue::Bool(b) = v {
                set(p, Some(b));
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Like [`opt_bool`] but with **per-state** help strings surfaced in the
/// page footer: `false_help` while the value/edit buffer is `false`,
/// `true_help` while it's `true`. Falls back to `help` if the array
/// access is somehow out of bounds (defensive; can't happen with
/// `usize::from(bool)`).
pub fn opt_bool_with_help<F, G>(
    label: &'static str,
    help: &'static str,
    false_help: &'static str,
    true_help: &'static str,
    get: G,
    set: F,
) -> FieldDef
where
    G: Fn(&Profile) -> Option<bool> + 'static,
    F: Fn(&mut Profile, Option<bool>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Bool(get(p).unwrap_or(false))),
        set: Box::new(move |p, v| {
            if let FieldValue::Bool(b) = v {
                set(p, Some(b));
            }
        }),
        validate: None,
        bool_option_help: Some([false_help, true_help]),
    }
}

/// Build a `FieldDef` for an `Option<u32>` numeric field.
pub fn opt_u32<F, G>(label: &'static str, help: &'static str, get: G, set: F) -> FieldDef
where
    G: Fn(&Profile) -> Option<u32> + 'static,
    F: Fn(&mut Profile, Option<u32>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| {
            FieldValue::Numeric(get(p).map(|n| n.to_string()).unwrap_or_default())
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Numeric(s) = v {
                if s.is_empty() {
                    set(p, None);
                } else if let Ok(n) = s.parse::<u32>() {
                    set(p, Some(n));
                }
            }
        }),
        validate: Some(Box::new(|v| {
            if let FieldValue::Numeric(s) = v {
                if !s.is_empty() && s.parse::<u32>().is_err() {
                    return Some(format!("`{s}` is not a valid u32"));
                }
            }
            None
        })),
        bool_option_help: None,
    }
}

/// Build a `FieldDef` backed by an `Option<Vec<String>>` list.
pub fn opt_list<F, G>(label: &'static str, help: &'static str, get: G, set: F) -> FieldDef
where
    G: Fn(&Profile) -> Vec<String> + 'static,
    F: Fn(&mut Profile, Vec<String>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::List(get(p))),
        set: Box::new(move |p, v| {
            if let FieldValue::List(vs) = v {
                set(p, vs);
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Build a `FieldDef` for a fixed-choice string with a known option list.
///
/// Kept available for callers that don't need per-option help; the
/// in-tree pages all migrated to [`opt_choice_with_help`] /
/// [`opt_choice_with_display_and_help`] in t-option-help.
#[allow(dead_code)]
pub fn opt_choice<F, G>(
    label: &'static str,
    help: &'static str,
    options: &'static [&'static str],
    get: G,
    set: F,
) -> FieldDef
where
    G: Fn(&Profile) -> Option<String> + 'static,
    F: Fn(&mut Profile, Option<String>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Choice {
            value: get(p).unwrap_or_default(),
            options,
            display: None,
            option_help: None,
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Choice { value, .. } = v {
                set(p, if value.is_empty() { None } else { Some(value) });
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Like [`opt_choice`] but with **per-option** help strings surfaced in
/// the page footer as the operator rotates the cursor. `option_help.len()`
/// must equal `options.len()`; mismatches fall back to `None` (i.e. the
/// constructor silently swallows the mismatch and the footer shows
/// `help`).
pub fn opt_choice_with_help<F, G>(
    label: &'static str,
    help: &'static str,
    options: &'static [&'static str],
    option_help: &'static [&'static str],
    get: G,
    set: F,
) -> FieldDef
where
    G: Fn(&Profile) -> Option<String> + 'static,
    F: Fn(&mut Profile, Option<String>) + 'static,
{
    let option_help = if option_help.len() == options.len() {
        Some(option_help)
    } else {
        None
    };
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Choice {
            value: get(p).unwrap_or_default(),
            options,
            display: None,
            option_help,
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Choice { value, .. } = v {
                set(p, if value.is_empty() { None } else { Some(value) });
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Like [`opt_choice`] but renders `display[i]` instead of `options[i]`
/// in the spinner. The stored value remains the canonical
/// `options[i]`, so this is purely a presentation knob. `display.len()`
/// must match `options.len()`; mismatches fall back to canonical
/// option strings.
///
/// Kept available as a public builder even though the in-tree pages
/// currently all use [`opt_choice_with_display_and_help`] — downstream
/// pages may want display-only without per-option help.
#[allow(dead_code)]
pub fn opt_choice_with_display<F, G>(
    label: &'static str,
    help: &'static str,
    options: &'static [&'static str],
    display: &'static [&'static str],
    get: G,
    set: F,
) -> FieldDef
where
    G: Fn(&Profile) -> Option<String> + 'static,
    F: Fn(&mut Profile, Option<String>) + 'static,
{
    let display = if display.len() == options.len() {
        Some(display)
    } else {
        None
    };
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Choice {
            value: get(p).unwrap_or_default(),
            options,
            display,
            option_help: None,
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Choice { value, .. } = v {
                set(p, if value.is_empty() { None } else { Some(value) });
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Combination of [`opt_choice_with_display`] and [`opt_choice_with_help`]:
/// supplies BOTH a `display` parallel for the rendered spinner labels AND
/// a `option_help` parallel for the per-cursor footer help. Both arrays
/// must be `options.len()` long; mismatches drop silently to `None`.
pub fn opt_choice_with_display_and_help<F, G>(
    label: &'static str,
    help: &'static str,
    options: &'static [&'static str],
    display: &'static [&'static str],
    option_help: &'static [&'static str],
    get: G,
    set: F,
) -> FieldDef
where
    G: Fn(&Profile) -> Option<String> + 'static,
    F: Fn(&mut Profile, Option<String>) + 'static,
{
    let display = if display.len() == options.len() {
        Some(display)
    } else {
        None
    };
    let option_help = if option_help.len() == options.len() {
        Some(option_help)
    } else {
        None
    };
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Choice {
            value: get(p).unwrap_or_default(),
            options,
            display,
            option_help,
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Choice { value, .. } = v {
                set(p, if value.is_empty() { None } else { Some(value) });
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Build a `FieldDef` for a multi-of-N selection backed by `Option<Vec<String>>`.
pub fn opt_multi<F, G>(
    label: &'static str,
    help: &'static str,
    options: &'static [&'static str],
    get: G,
    set: F,
) -> FieldDef
where
    G: Fn(&Profile) -> Vec<String> + 'static,
    F: Fn(&mut Profile, Vec<String>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Multi {
            value: get(p),
            options,
            option_help: None,
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Multi { value, .. } = v {
                set(p, value);
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Like [`opt_multi`] but with **per-option** help strings surfaced in
/// the page footer as the operator moves the cursor through the
/// options. Same length-validation contract as
/// [`opt_choice_with_help`].
pub fn opt_multi_with_help<F, G>(
    label: &'static str,
    help: &'static str,
    options: &'static [&'static str],
    option_help: &'static [&'static str],
    get: G,
    set: F,
) -> FieldDef
where
    G: Fn(&Profile) -> Vec<String> + 'static,
    F: Fn(&mut Profile, Vec<String>) + 'static,
{
    let option_help = if option_help.len() == options.len() {
        Some(option_help)
    } else {
        None
    };
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::Multi {
            value: get(p),
            options,
            option_help,
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Multi { value, .. } = v {
                set(p, value);
            }
        }),
        validate: None,
        bool_option_help: None,
    }
}

/// Build a `FieldDef` for a secret reference (`secret://ns/name` etc.).
pub fn opt_secret<F, G>(label: &'static str, help: &'static str, get: G, set: F) -> FieldDef
where
    G: Fn(&Profile) -> Option<String> + 'static,
    F: Fn(&mut Profile, Option<String>) + 'static,
{
    FieldDef {
        label,
        help,
        get: Box::new(move |p| FieldValue::SecretRef(get(p).unwrap_or_default())),
        set: Box::new(move |p, v| {
            if let FieldValue::SecretRef(s) = v {
                set(p, if s.is_empty() { None } else { Some(s) });
            }
        }),
        validate: Some(Box::new(|v| {
            if let FieldValue::SecretRef(s) = v {
                if s.is_empty() {
                    return None;
                }
                if let Err(e) = spt_auth::SecretRef::parse(s) {
                    return Some(format!("invalid secret reference: {e}"));
                }
            }
            None
        })),
        bool_option_help: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_profile() -> Profile {
        Profile {
            name: "p".into(),
            protocol: "ssh2".into(),
            ..Default::default()
        }
    }

    #[test]
    fn opt_text_round_trip() {
        let def = opt_text(
            "user",
            "remote user",
            |p: &Profile| p.user.clone(),
            |p, v| p.user = v,
        );
        let mut p = sample_profile();
        let mut list = FieldList::new(vec![def]);
        list.begin_edit(&p);
        // Type "alice".
        for c in "alice".chars() {
            let key = crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char(c),
                crossterm::event::KeyModifiers::NONE,
            );
            list.on_edit_key(key, &mut p);
        }
        list.commit_edit(&mut p);
        assert_eq!(p.user.as_deref(), Some("alice"));
    }

    #[test]
    fn invalid_secret_ref_holds_field_open() {
        let def = opt_secret(
            "passphrase",
            "secret ref",
            |p: &Profile| {
                p.auth
                    .as_ref()
                    .and_then(|a| a.passphrase.as_ref().map(|s| s.expose().to_owned()))
            },
            |p, v| {
                p.auth.get_or_insert_with(Default::default).passphrase =
                    v.map(spt_core::RedactedString::from);
            },
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        for c in "garbage".chars() {
            let key = crossterm::event::KeyEvent::new(
                crossterm::event::KeyCode::Char(c),
                crossterm::event::KeyModifiers::NONE,
            );
            list.on_edit_key(key, &mut p);
        }
        let committed = list.commit_edit(&mut p);
        assert!(!committed, "garbage should fail validation");
        assert!(list.fields[0].last_error.is_some());
    }

    fn key(code: crossterm::event::KeyCode) -> crossterm::event::KeyEvent {
        crossterm::event::KeyEvent::new(code, crossterm::event::KeyModifiers::NONE)
    }

    #[test]
    fn empty_list_move_focus_is_noop() {
        let mut list = FieldList::new(vec![]);
        list.move_focus(1);
        list.move_focus(-1);
        assert_eq!(list.focus, 0);
    }

    #[test]
    fn move_focus_wraps_around() {
        let defs = vec![
            opt_text("a", "", |p: &Profile| p.user.clone(), |p, v| p.user = v),
            opt_text("b", "", |p: &Profile| p.host.clone(), |p, v| p.host = v),
            opt_text(
                "c",
                "",
                |p: &Profile| p.description.clone(),
                |p, v| p.description = v,
            ),
        ];
        let mut list = FieldList::new(defs);
        assert_eq!(list.focus, 0);
        list.move_focus(-1);
        assert_eq!(list.focus, 2);
        list.move_focus(1);
        assert_eq!(list.focus, 0);
        list.move_focus(5);
        assert_eq!(list.focus, 2);
    }

    #[test]
    fn nav_key_down_advances() {
        let defs = vec![
            opt_text("a", "", |p: &Profile| p.user.clone(), |p, v| p.user = v),
            opt_text("b", "", |p: &Profile| p.host.clone(), |p, v| p.host = v),
        ];
        let mut list = FieldList::new(defs);
        let p = sample_profile();
        assert!(list.on_nav_key(key(crossterm::event::KeyCode::Down), &p));
        assert_eq!(list.focus, 1);
        assert!(list.on_nav_key(key(crossterm::event::KeyCode::Up), &p));
        assert_eq!(list.focus, 0);
    }

    #[test]
    fn cancel_edit_clears_buffer() {
        let def = opt_text("u", "", |p: &Profile| p.user.clone(), |p, v| p.user = v);
        let mut list = FieldList::new(vec![def]);
        let p = sample_profile();
        list.begin_edit(&p);
        assert!(list.editing);
        list.cancel_edit();
        assert!(!list.editing);
        assert!(list.fields[0].edit_buf.is_none());
    }

    #[test]
    fn opt_bool_round_trip() {
        let def = opt_bool(
            "agent",
            "",
            |p: &Profile| p.auth.as_ref().and_then(|a| a.agent),
            |p, v| p.auth.get_or_insert_with(Default::default).agent = v,
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        // Space flips edit_buf false → true (does not commit).
        list.on_edit_key(key(crossterm::event::KeyCode::Char(' ')), &mut p);
        // Enter commits the now-flipped value (Enter no longer flips —
        // that contract was the user-reported "Enter just untoggles" bug).
        list.on_edit_key(key(crossterm::event::KeyCode::Enter), &mut p);
        assert_eq!(p.auth.as_ref().and_then(|a| a.agent), Some(true));
    }

    #[test]
    fn opt_u32_validation_rejects_bad_text() {
        let def = opt_u32(
            "n",
            "",
            |p: &Profile| p.connection.as_ref().and_then(|c| c.keepalive_retries),
            |p, v| {
                p.connection
                    .get_or_insert_with(Default::default)
                    .keepalive_retries = v;
            },
        );
        let v = FieldValue::Numeric("abc".to_owned());
        let err = def.validate.as_ref().unwrap()(&v);
        assert!(err.is_some());
        // Empty is acceptable (clears).
        let v = FieldValue::Numeric(String::new());
        assert!(def.validate.as_ref().unwrap()(&v).is_none());
    }

    #[test]
    fn opt_choice_commits_chosen() {
        let def = opt_choice(
            "startup",
            "",
            &["eager", "lazy"],
            |p: &Profile| p.startup.clone(),
            |p, v| p.startup = v,
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        // Down then Enter to pick "lazy".
        list.on_edit_key(key(crossterm::event::KeyCode::Down), &mut p);
        list.on_edit_key(key(crossterm::event::KeyCode::Enter), &mut p);
        assert_eq!(p.startup.as_deref(), Some("lazy"));
    }

    #[test]
    fn opt_list_commits_csv() {
        let def = opt_list(
            "tags",
            "",
            |p: &Profile| p.tags.clone().unwrap_or_default(),
            |p, v| p.tags = if v.is_empty() { None } else { Some(v) },
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        for c in "a, b, c".chars() {
            list.on_edit_key(key(crossterm::event::KeyCode::Char(c)), &mut p);
        }
        list.on_edit_key(key(crossterm::event::KeyCode::Enter), &mut p);
        assert_eq!(p.tags, Some(vec!["a".into(), "b".into(), "c".into()]));
    }

    #[test]
    fn opt_multi_commits_on_s() {
        let def = opt_multi(
            "ciphers",
            "",
            &["aes256-gcm", "chacha20"],
            |p: &Profile| {
                p.crypto
                    .as_ref()
                    .and_then(|c| c.ciphers.clone())
                    .unwrap_or_default()
            },
            |p, v| {
                p.crypto.get_or_insert_with(Default::default).ciphers =
                    if v.is_empty() { None } else { Some(v) }
            },
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        // Toggle the first option (Space) then commit via 's'.
        list.on_edit_key(key(crossterm::event::KeyCode::Char(' ')), &mut p);
        list.on_edit_key(key(crossterm::event::KeyCode::Char('s')), &mut p);
        let cs = p.crypto.as_ref().and_then(|c| c.ciphers.clone());
        assert_eq!(cs, Some(vec!["aes256-gcm".into()]));
    }

    #[test]
    fn opt_multi_esc_cancels_without_commit() {
        let def = opt_multi(
            "ciphers",
            "",
            &["aes256-gcm", "chacha20"],
            |p: &Profile| {
                p.crypto
                    .as_ref()
                    .and_then(|c| c.ciphers.clone())
                    .unwrap_or_default()
            },
            |p, v| {
                p.crypto.get_or_insert_with(Default::default).ciphers =
                    if v.is_empty() { None } else { Some(v) }
            },
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        list.on_edit_key(key(crossterm::event::KeyCode::Char(' ')), &mut p);
        list.on_edit_key(key(crossterm::event::KeyCode::Esc), &mut p);
        // Esc cancels — no commit happened.
        assert!(p.crypto.as_ref().and_then(|c| c.ciphers.clone()).is_none());
        assert!(!list.editing);
    }

    #[test]
    fn opt_text_empty_clears_to_none() {
        let mut p = sample_profile();
        p.user = Some("a".into());
        let def = opt_text("u", "", |p: &Profile| p.user.clone(), |p, v| p.user = v);
        let mut list = FieldList::new(vec![def]);
        list.begin_edit(&p);
        list.on_edit_key(key(crossterm::event::KeyCode::Backspace), &mut p);
        list.on_edit_key(key(crossterm::event::KeyCode::Enter), &mut p);
        assert!(p.user.is_none());
    }

    #[test]
    fn tab_commits_and_moves_focus() {
        let defs = vec![
            opt_text("a", "", |p: &Profile| p.user.clone(), |p, v| p.user = v),
            opt_text("b", "", |p: &Profile| p.host.clone(), |p, v| p.host = v),
        ];
        let mut list = FieldList::new(defs);
        let mut p = sample_profile();
        list.begin_edit(&p);
        for c in "abc".chars() {
            list.on_edit_key(key(crossterm::event::KeyCode::Char(c)), &mut p);
        }
        // Tab commits and moves down.
        list.on_edit_key(key(crossterm::event::KeyCode::Tab), &mut p);
        assert_eq!(p.user.as_deref(), Some("abc"));
        assert_eq!(list.focus, 1);
        assert!(!list.editing);
    }

    #[test]
    fn secret_ref_empty_is_valid_and_clears() {
        let def = opt_secret(
            "pw",
            "",
            |p: &Profile| {
                p.auth
                    .as_ref()
                    .and_then(|a| a.password.as_ref().map(|s| s.expose().to_owned()))
            },
            |p, v| {
                p.auth.get_or_insert_with(Default::default).password =
                    v.map(spt_core::RedactedString::from);
            },
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        // No characters; commit empty.
        list.on_edit_key(key(crossterm::event::KeyCode::Enter), &mut p);
        assert!(!list.editing);
    }

    #[test]
    fn field_debug_renders_label() {
        let def = opt_text("x", "", |p: &Profile| p.user.clone(), |p, v| p.user = v);
        let s = format!("{def:?}");
        assert!(s.contains("FieldDef"));
        assert!(s.contains('x'));
    }

    // -----------------------------------------------------------------
    // Phase 1 reproducers — t-tui-rotate (RC1).
    // -----------------------------------------------------------------

    #[test]
    fn begin_edit_seeds_select_index_from_current_value() {
        // RC1 reproducer: when a Choice field's current value is the
        // second option, opening edit mode must seed the select cursor
        // to that index rather than defaulting to 0.
        const OPTS: &[&str] = &["ssh2", "ssh3"];
        let def = FieldDef {
            label: "protocol",
            help: "",
            get: Box::new(|p: &Profile| FieldValue::Choice {
                value: p.protocol.clone(),
                options: OPTS,
                display: None,
                option_help: None,
            }),
            set: Box::new(|p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    p.protocol = value;
                }
            }),
            validate: None,
            bool_option_help: None,
        };
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        p.protocol = "ssh3".into();
        list.begin_edit(&p);
        assert_eq!(
            list.fields[0].select.index, 1,
            "Select.index must be seeded from current value position"
        );
    }

    #[test]
    fn begin_edit_seeds_multi_index_from_first_selected() {
        // RC1 reproducer for Multi: seed the cursor at the first
        // currently-selected option's index (or 0 if none).
        const OPTS: &[&str] = &["a", "b", "c"];
        let def = FieldDef {
            label: "list",
            help: "",
            get: Box::new(|p: &Profile| FieldValue::Multi {
                value: p.tags.clone().unwrap_or_default(),
                options: OPTS,
                option_help: None,
            }),
            set: Box::new(|p, v| {
                if let FieldValue::Multi { value, .. } = v {
                    p.tags = if value.is_empty() { None } else { Some(value) };
                }
            }),
            validate: None,
            bool_option_help: None,
        };
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        p.tags = Some(vec!["c".into()]);
        list.begin_edit(&p);
        assert_eq!(
            list.fields[0].multi.index, 2,
            "MultiSelect.index must be seeded from first selected option's position"
        );
    }

    #[test]
    fn begin_edit_seeds_multi_index_zero_when_empty() {
        // RC1: with no selected value, fall back to 0.
        const OPTS: &[&str] = &["a", "b", "c"];
        let def = FieldDef {
            label: "list",
            help: "",
            get: Box::new(|_p: &Profile| FieldValue::Multi {
                value: Vec::new(),
                options: OPTS,
                option_help: None,
            }),
            set: Box::new(|_p, _v| {}),
            validate: None,
            bool_option_help: None,
        };
        let mut list = FieldList::new(vec![def]);
        let p = sample_profile();
        list.begin_edit(&p);
        assert_eq!(list.fields[0].multi.index, 0);
    }

    #[test]
    fn choice_left_right_rotates_via_on_edit_key() {
        // RC2 integration through on_edit_key: Right should rotate the
        // cursor without committing.
        const OPTS: &[&str] = &["ssh2", "ssh3"];
        let def = FieldDef {
            label: "protocol",
            help: "",
            get: Box::new(|p: &Profile| FieldValue::Choice {
                value: p.protocol.clone(),
                options: OPTS,
                display: None,
                option_help: None,
            }),
            set: Box::new(|p, v| {
                if let FieldValue::Choice { value, .. } = v {
                    p.protocol = value;
                }
            }),
            validate: None,
            bool_option_help: None,
        };
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        p.protocol = "ssh2".into();
        list.begin_edit(&p);
        // Right -> cursor moves to ssh3 but no commit yet.
        list.on_edit_key(key(crossterm::event::KeyCode::Right), &mut p);
        assert_eq!(list.fields[0].select.index, 1);
        assert_eq!(p.protocol, "ssh2", "Right alone must not commit");
        // Enter commits.
        list.on_edit_key(key(crossterm::event::KeyCode::Enter), &mut p);
        assert_eq!(p.protocol, "ssh3");
    }

    #[test]
    fn bool_field_space_flips_without_commit() {
        // Documents the actual semantics: Space flips the toggle inside
        // the edit buffer but does NOT commit. (Enter commits.)
        let def = opt_bool(
            "agent",
            "",
            |p: &Profile| p.auth.as_ref().and_then(|a| a.agent),
            |p, v| p.auth.get_or_insert_with(Default::default).agent = v,
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        // Initial profile value: agent is None (-> false via get).
        list.on_edit_key(key(crossterm::event::KeyCode::Char(' ')), &mut p);
        // After Space: edit buffer flipped, profile unchanged.
        assert!(
            p.auth.as_ref().and_then(|a| a.agent).is_none(),
            "Space must not commit to profile"
        );
        // edit_buf reflects the flip.
        match list.fields[0].edit_buf.as_ref() {
            Some(FieldValue::Bool(b)) => assert!(*b, "edit_buf should be flipped to true"),
            other => panic!("expected Bool edit_buf, got {other:?}"),
        }
        assert!(list.editing, "still editing — Space did not commit");
    }

    // -----------------------------------------------------------------
    // t-option-help — per-option dynamic help for Bool/Choice/Multi.
    // -----------------------------------------------------------------

    #[test]
    fn focused_help_dynamic_choice_follows_cursor() {
        // A Choice field with per-option help; rotating the cursor with
        // Right must change the string returned by focused_help_dynamic.
        const OPTS: &[&str] = &["a", "b", "c"];
        const OH: &[&str] = &["alpha-help", "beta-help", "gamma-help"];
        let def = opt_choice_with_help(
            "startup",
            "static help",
            OPTS,
            OH,
            |p: &Profile| p.startup.clone(),
            |p, v| p.startup = v,
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        p.startup = Some("a".into());
        list.begin_edit(&p);
        assert_eq!(list.focused_help_dynamic(&p), Some("alpha-help"));
        list.on_edit_key(key(crossterm::event::KeyCode::Right), &mut p);
        assert_eq!(list.focused_help_dynamic(&p), Some("beta-help"));
        list.on_edit_key(key(crossterm::event::KeyCode::Right), &mut p);
        assert_eq!(list.focused_help_dynamic(&p), Some("gamma-help"));
    }

    #[test]
    fn focused_help_dynamic_bool_state_dependent() {
        // A Bool field with `bool_option_help`: edit_buf=false → false-help;
        // flipping to true via Space must swap the footer string.
        let def = opt_bool_with_help(
            "agent",
            "static help",
            "FALSE-help",
            "TRUE-help",
            |p: &Profile| p.auth.as_ref().and_then(|a| a.agent),
            |p, v| p.auth.get_or_insert_with(Default::default).agent = v,
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        assert_eq!(list.focused_help_dynamic(&p), Some("FALSE-help"));
        // Space flips edit buffer false -> true (no commit).
        list.on_edit_key(key(crossterm::event::KeyCode::Char(' ')), &mut p);
        assert_eq!(list.focused_help_dynamic(&p), Some("TRUE-help"));
    }

    #[test]
    fn focused_help_dynamic_falls_back_to_def_help() {
        // A Choice without `option_help` returns `def.help`.
        let def = opt_choice(
            "startup",
            "fallback help",
            &["a", "b"],
            |p: &Profile| p.startup.clone(),
            |p, v| p.startup = v,
        );
        let list = FieldList::new(vec![def]);
        let p = sample_profile();
        // Nav mode (not editing): still falls back to def.help.
        assert_eq!(list.focused_help_dynamic(&p), Some("fallback help"));
    }

    #[test]
    fn focused_help_dynamic_multi_follows_cursor() {
        // Multi with per-option help; arrow Right moves the cursor and
        // the returned help string changes.
        const OPTS: &[&str] = &["x", "y", "z"];
        const OH: &[&str] = &["x-help", "y-help", "z-help"];
        let def = opt_multi_with_help(
            "tags",
            "static",
            OPTS,
            OH,
            |p: &Profile| p.tags.clone().unwrap_or_default(),
            |p, v| p.tags = if v.is_empty() { None } else { Some(v) },
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        list.begin_edit(&p);
        assert_eq!(list.focused_help_dynamic(&p), Some("x-help"));
        list.on_edit_key(key(crossterm::event::KeyCode::Right), &mut p);
        assert_eq!(list.focused_help_dynamic(&p), Some("y-help"));
        list.on_edit_key(key(crossterm::event::KeyCode::Right), &mut p);
        assert_eq!(list.focused_help_dynamic(&p), Some("z-help"));
    }

    #[test]
    fn opt_choice_with_help_rejects_length_mismatch_silently() {
        // Wrong-length option_help → constructor silently drops to None;
        // focused_help_dynamic returns `def.help`.
        let def = opt_choice_with_help(
            "startup",
            "fallback",
            &["a", "b", "c"],
            &["only-two", "entries"], // mismatch
            |p: &Profile| p.startup.clone(),
            |p, v| p.startup = v,
        );
        let mut list = FieldList::new(vec![def]);
        let mut p = sample_profile();
        p.startup = Some("a".into());
        list.begin_edit(&p);
        // No option_help table on the FieldValue → fallback to def.help.
        assert_eq!(list.focused_help_dynamic(&p), Some("fallback"));
        // And rotating doesn't change anything.
        list.on_edit_key(key(crossterm::event::KeyCode::Right), &mut p);
        assert_eq!(list.focused_help_dynamic(&p), Some("fallback"));
    }
}
