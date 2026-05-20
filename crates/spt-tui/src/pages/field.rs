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
        /// Current value.
        value: String,
        /// Static option list shown to the user.
        options: &'static [&'static str],
    },
    /// Many-of-N choices.
    Multi {
        /// Currently-selected option list.
        value: Vec<String>,
        /// Static option list shown to the user.
        options: &'static [&'static str],
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
            FieldValue::Choice { value, options } => {
                let changed = field.select.on_key(options, value, key);
                if matches!(key.code, KeyCode::Enter) {
                    return self.commit_edit(profile);
                }
                changed
            }
            FieldValue::Multi { value, options } => {
                let changed = field.multi.on_key(options, value, key);
                if matches!(key.code, KeyCode::Char('s')) || matches!(key.code, KeyCode::Esc) {
                    self.commit_edit(profile);
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
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(area);

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
                FieldValue::Text(s) | FieldValue::SecretRef(s) => {
                    field.text.render(area, buf, field.def.label, &s);
                }
                FieldValue::Numeric(s) => {
                    field.numeric.render(area, buf, field.def.label, &s);
                }
                FieldValue::Bool(b) => {
                    let t = Toggle { focused: editing };
                    t.render(area, buf, field.def.label, b);
                }
                FieldValue::Choice { ref value, options } => {
                    field
                        .select
                        .render(area, buf, field.def.label, options, value);
                }
                FieldValue::Multi { ref value, options } => {
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
    }
}

/// Build a `FieldDef` for a `Option<bool>` field.
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
    }
}

/// Build a `FieldDef` for a fixed-choice string with a known option list.
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
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Choice { value, .. } = v {
                set(p, if value.is_empty() { None } else { Some(value) });
            }
        }),
        validate: None,
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
        }),
        set: Box::new(move |p, v| {
            if let FieldValue::Multi { value, .. } = v {
                set(p, value);
            }
        }),
        validate: None,
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
        // Enter: Toggle flips false → true and commits.
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
}
