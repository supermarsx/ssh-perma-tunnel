//! Reusable form widgets used by every wizard page.
//!
//! Each widget owns a small `State` struct and a stateless render fn.
//! Pages compose widgets and dispatch keyboard events to them.
//!
//! Widget set:
//!
//! * [`TextInput`] — single-line string entry.
//! * [`NumericInput`] — `u32`/`u16` decimal entry; rejects non-digit input.
//! * [`Toggle`] — boolean on/off.
//! * [`Select`] — single-choice from a fixed list.
//! * [`MultiSelect`] — many-of-N choices.
//! * [`StringList`] — comma-separated list editor.
//! * [`RedactedField`] — masked-by-default secret display with timed reveal
//!   (`Ctrl-R`) and clipboard-yank (`Ctrl-Y`) — see [`redacted_field`].
//! * `FilePicker` — alias for [`TextInput`] with a path hint.
//!
//! Widgets do not own their model — the page passes a `&mut String` (or
//! similar) when handling input. This keeps state ownership simple and lets
//! tests drive widgets directly.

pub mod clipboard;
pub mod redacted_field;

pub use clipboard::{
    ClipboardBackend, ClipboardError, ClipboardWrapper, InMemoryBackend, NoopBackend,
    ThreadSleepTimer, Timer,
};
pub use redacted_field::{
    install_audit_hook, AuditEvent, AuditHook, NoopAuditHook, RedactedField, RedactedFieldAction,
    RedactedFieldState,
};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

/// Cursor-aware single-line text input.
#[derive(Debug, Default, Clone)]
pub struct TextInput {
    /// Cursor position (in chars, not bytes).
    pub cursor: usize,
    /// Whether this widget currently owns keyboard focus.
    pub focused: bool,
}

impl TextInput {
    /// Apply a key event to a backing string. Returns `true` if the value
    /// changed.
    pub fn on_key(&mut self, value: &mut String, key: KeyEvent) -> bool {
        // Clamp cursor before any mutation.
        if self.cursor > value.chars().count() {
            self.cursor = value.chars().count();
        }
        match key.code {
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                let byte_idx = char_to_byte(value, self.cursor);
                value.insert(byte_idx, c);
                self.cursor += 1;
                true
            }
            KeyCode::Backspace => {
                if self.cursor == 0 {
                    return false;
                }
                self.cursor -= 1;
                let byte_idx = char_to_byte(value, self.cursor);
                value.remove(byte_idx);
                true
            }
            KeyCode::Delete => {
                if self.cursor >= value.chars().count() {
                    return false;
                }
                let byte_idx = char_to_byte(value, self.cursor);
                value.remove(byte_idx);
                true
            }
            KeyCode::Left => {
                self.cursor = self.cursor.saturating_sub(1);
                false
            }
            KeyCode::Right => {
                if self.cursor < value.chars().count() {
                    self.cursor += 1;
                }
                false
            }
            KeyCode::Home => {
                self.cursor = 0;
                false
            }
            KeyCode::End => {
                self.cursor = value.chars().count();
                false
            }
            _ => false,
        }
    }

    /// Render the input into `area`. `label` is shown as the block title;
    /// `value` is the current contents.
    pub fn render(&self, area: Rect, buf: &mut Buffer, label: &str, value: &str) {
        let style = if self.focused {
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
        let mut text = value.to_string();
        if self.focused {
            // Show a visible caret by inserting a ▏ marker. Real cursor
            // positioning is set by the parent terminal in raw mode.
            let caret_byte = char_to_byte(&text, self.cursor);
            text.insert(caret_byte, '▏');
        }
        Paragraph::new(text).block(block).render(area, buf);
        // After the Paragraph has drawn, paint a REVERSED style on the
        // single caret cell so a focused empty/anywhere field shows a
        // visibly distinguished cursor (the lone ▏ glyph against an
        // otherwise blank background was being lost on some terminals).
        // Gated on `self.focused` so nav-mode rendering is unchanged.
        if self.focused && area.width > 2 && area.height > 2 && self.cursor <= value.chars().count()
        {
            // Content origin is one cell inside each border edge.
            let inner_w = area.width.saturating_sub(2);
            // Cursor column inside the inner content area. Assumes
            // single-cell-width chars (which the existing test suite
            // already covers — full-width chars are out of scope).
            let caret_col_u = self.cursor as u32;
            if caret_col_u < u32::from(inner_w) {
                #[allow(clippy::cast_possible_truncation)]
                let caret_col = caret_col_u as u16;
                let cx = area.x + 1 + caret_col;
                let cy = area.y + 1;
                let buf_area = buf.area();
                if cx < buf_area.x + buf_area.width && cy < buf_area.y + buf_area.height {
                    let cell = &mut buf[(cx, cy)];
                    let merged = cell.style().add_modifier(Modifier::REVERSED);
                    cell.set_style(merged);
                }
            }
        }
    }
}

/// Numeric input restricted to digits; serialized as decimal.
#[derive(Debug, Default, Clone)]
pub struct NumericInput {
    /// Underlying text widget for cursor handling.
    pub text: TextInput,
}

impl NumericInput {
    /// Like [`TextInput::on_key`] but rejects non-digit characters.
    pub fn on_key(&mut self, value: &mut String, key: KeyEvent) -> bool {
        if let KeyCode::Char(c) = key.code {
            if !c.is_ascii_digit() {
                return false;
            }
        }
        self.text.on_key(value, key)
    }

    /// Render at `area`.
    pub fn render(&self, area: Rect, buf: &mut Buffer, label: &str, value: &str) {
        self.text.render(area, buf, label, value);
    }
}

/// Boolean toggle. Flips on **Space** or **`t`** — and only those.
///
/// Other keys (Enter, `y`, `n`, arrows, etc.) are intentionally NOT
/// flip keys. Enter is reserved by the parent
/// [`crate::pages::field::FieldList`] for commit-edit; any other key
/// passes through unchanged. This keeps the toggle keymap tight and
/// predictable: pressing Enter on a Bool field commits the displayed
/// value with no side-effects on the value itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct Toggle {
    /// Whether this widget currently owns focus.
    pub focused: bool,
}

impl Toggle {
    /// Apply a key. Returns `true` if the value flipped.
    ///
    /// Only **Space** and **`t`** flip — see the type-level doc.
    pub fn on_key(&self, value: &mut bool, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(' ') | KeyCode::Char('t') => {
                *value = !*value;
                true
            }
            _ => false,
        }
    }

    /// Render at `area`.
    pub fn render(&self, area: Rect, buf: &mut Buffer, label: &str, value: bool) {
        let style = if self.focused {
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
        let txt = if value { "[x] yes" } else { "[ ] no" };
        Paragraph::new(txt).block(block).render(area, buf);
    }
}

/// Single-choice selector.
#[derive(Debug, Default, Clone)]
pub struct Select {
    /// Index of the highlighted option.
    pub index: usize,
    /// Whether this widget currently owns focus.
    pub focused: bool,
}

impl Select {
    /// Apply a key against an options slice; mutates `index` and writes the
    /// chosen value into `out` on Enter. Returns `true` on selection change.
    ///
    /// Cursor keys (Up/Down/Left/Right) **wrap** at the boundaries — they
    /// never commit. Enter and Space write the cursor's option into `out`.
    pub fn on_key(&mut self, options: &[&str], out: &mut String, key: KeyEvent) -> bool {
        // Wrap-aware cursor moves. Guard against empty option lists so
        // the modulus below never sees `% 0`.
        if options.is_empty() {
            return false;
        }
        match key.code {
            KeyCode::Up | KeyCode::Left => {
                if self.index == 0 {
                    self.index = options.len() - 1;
                } else {
                    self.index -= 1;
                }
                false
            }
            KeyCode::Down | KeyCode::Right => {
                self.index = (self.index + 1) % options.len();
                false
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if let Some(opt) = options.get(self.index) {
                    *out = (*opt).to_owned();
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Render at `area`.
    pub fn render(
        &self,
        area: Rect,
        buf: &mut Buffer,
        label: &str,
        options: &[&str],
        current: &str,
    ) {
        let style = if self.focused {
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

        // Compact spinner path: when there's not enough vertical room to
        // show every option on its own line, render a single line that
        // reflects the actual value (or the cursor + chrome when focused).
        // Every caller in `FieldList::render` hits this branch because
        // `row_h = 3` leaves a single inner content line.
        let inner_h = area.height.saturating_sub(2);
        let inner_w = area.width.saturating_sub(2) as usize;
        if (inner_h as usize) < options.len() {
            let text = if self.focused && !options.is_empty() {
                let idx = self.index.min(options.len() - 1);
                let opt = options[idx];
                // Chrome: "◀  ▶  (N/M)" ≈ 11 chars baseline; account for
                // multi-digit counters by formatting first and measuring.
                let suffix = format!("  ({}/{})", idx + 1, options.len());
                let chrome = 4 + suffix.chars().count(); // "◀ " + " ▶" = 4 chars
                let budget = inner_w.saturating_sub(chrome);
                let opt_s = ellipsize(opt, budget);
                format!("◀ {opt_s} ▶{suffix}")
            } else {
                // Unfocused (or empty options): render the actual current
                // value, ellipsized to the inner width.
                ellipsize(current, inner_w)
            };
            Paragraph::new(text).block(block).render(area, buf);
            return;
        }

        let lines: Vec<Line<'_>> = options
            .iter()
            .enumerate()
            .map(|(i, opt)| {
                let is_current = *opt == current;
                let is_highlight = self.focused && i == self.index;
                let marker = if is_current { "●" } else { "○" };
                let span = Span::raw(format!("{marker} {opt}"));
                if is_highlight {
                    Line::from(span).style(Style::default().bg(Color::DarkGray))
                } else {
                    Line::from(span)
                }
            })
            .collect();
        Paragraph::new(lines).block(block).render(area, buf);
    }
}

/// Multi-of-N selector (used for crypto allow-lists).
#[derive(Debug, Default, Clone)]
pub struct MultiSelect {
    /// Cursor index inside the option list.
    pub index: usize,
    /// Whether this widget currently owns focus.
    pub focused: bool,
}

impl MultiSelect {
    /// Apply a key. Toggles membership of the cursor's option in `selected`
    /// only on **Space** or **`t`** — Enter is reserved for parent commit.
    ///
    /// Cursor keys (Up/Down/Left/Right) **wrap** at the boundaries.
    /// Each `[x]`/`[ ]` checkbox in this widget flips ONLY on Space or
    /// `t`, matching the [`Toggle`] keymap. Enter passes through unchanged
    /// so the parent [`crate::pages::field::FieldList`] can handle commit
    /// (alongside `s` and Esc, which are also treated as commit by the
    /// parent for multi-selection workflows).
    pub fn on_key(&mut self, options: &[&str], selected: &mut Vec<String>, key: KeyEvent) -> bool {
        if options.is_empty() {
            // Still allow Space/`t` to no-op cleanly.
            return false;
        }
        match key.code {
            KeyCode::Up | KeyCode::Left => {
                if self.index == 0 {
                    self.index = options.len() - 1;
                } else {
                    self.index -= 1;
                }
                false
            }
            KeyCode::Down | KeyCode::Right => {
                self.index = (self.index + 1) % options.len();
                false
            }
            KeyCode::Char(' ') | KeyCode::Char('t') => {
                if let Some(opt) = options.get(self.index) {
                    let s = (*opt).to_owned();
                    if let Some(pos) = selected.iter().position(|x| x == &s) {
                        selected.remove(pos);
                    } else {
                        selected.push(s);
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    /// Render at `area`.
    pub fn render(
        &self,
        area: Rect,
        buf: &mut Buffer,
        label: &str,
        options: &[&str],
        selected: &[String],
    ) {
        let style = if self.focused {
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

        // Compact spinner path: mirror Select. Focused shows the cursor
        // option with its current mark plus `◀ … ▶  (k/N)`; unfocused
        // shows a comma-joined summary of `selected` with `, +K` overflow.
        let inner_h = area.height.saturating_sub(2);
        let inner_w = area.width.saturating_sub(2) as usize;
        if (inner_h as usize) < options.len() {
            let text = if self.focused && !options.is_empty() {
                let idx = self.index.min(options.len() - 1);
                let opt = options[idx];
                let on = selected.iter().any(|s| s == opt);
                let mark = if on { "[x]" } else { "[ ]" };
                let suffix = format!("  ({}/{})", selected.len(), options.len());
                // "◀ [x] " + " ▶" = 8 chars chrome.
                let chrome = 8 + suffix.chars().count();
                let budget = inner_w.saturating_sub(chrome);
                let opt_s = ellipsize(opt, budget);
                format!("◀ {mark} {opt_s} ▶{suffix}")
            } else if selected.is_empty() {
                "(none)".to_string()
            } else {
                multi_select_summary(selected, inner_w)
            };
            Paragraph::new(text).block(block).render(area, buf);
            return;
        }

        let lines: Vec<Line<'_>> = options
            .iter()
            .enumerate()
            .map(|(i, opt)| {
                let on = selected.iter().any(|s| s == *opt);
                let mark = if on { "[x]" } else { "[ ]" };
                let span = Span::raw(format!("{mark} {opt}"));
                if self.focused && i == self.index {
                    Line::from(span).style(Style::default().bg(Color::DarkGray))
                } else {
                    Line::from(span)
                }
            })
            .collect();
        Paragraph::new(lines).block(block).render(area, buf);
    }
}

/// Comma-separated list input. Underlying storage is `Vec<String>`; the user
/// edits a flat string and the page parses it on commit.
#[derive(Debug, Default, Clone)]
pub struct StringList {
    /// Raw text being edited.
    pub raw: String,
    /// Underlying [`TextInput`] for cursor handling.
    pub text: TextInput,
}

impl StringList {
    /// Initialize from an existing list.
    #[must_use]
    pub fn from_vec(values: &[String]) -> Self {
        let raw = values.join(", ");
        let cursor = raw.chars().count();
        Self {
            raw,
            text: TextInput {
                cursor,
                focused: false,
            },
        }
    }

    /// Apply a key event.
    pub fn on_key(&mut self, key: KeyEvent) -> bool {
        let mut tmp = std::mem::take(&mut self.raw);
        let changed = self.text.on_key(&mut tmp, key);
        self.raw = tmp;
        changed
    }

    /// Parse the raw buffer back into a `Vec<String>`.
    #[must_use]
    pub fn parse(&self) -> Vec<String> {
        self.raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect()
    }

    /// Render at `area`.
    pub fn render(&self, area: Rect, buf: &mut Buffer, label: &str) {
        self.text.render(area, buf, label, &self.raw);
    }
}

/// Convert a *char* index to a *byte* index for `String::insert`.
fn char_to_byte(s: &str, char_idx: usize) -> usize {
    s.char_indices()
        .nth(char_idx)
        .map_or_else(|| s.len(), |(b, _)| b)
}

/// Truncate `s` to at most `max_chars` *characters*, replacing the tail
/// with `…` when truncation happens. Returns `s` unchanged if it already
/// fits. If `max_chars == 0` returns an empty string.
fn ellipsize(s: &str, max_chars: usize) -> String {
    let len = s.chars().count();
    if len <= max_chars {
        return s.to_string();
    }
    if max_chars == 0 {
        return String::new();
    }
    if max_chars == 1 {
        return "…".to_string();
    }
    let mut out: String = s.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

/// Build the unfocused MultiSelect summary: comma-joined `selected`,
/// trimmed to fit `inner_w` chars, with a trailing ` +K` indicator when
/// items had to be dropped. Empty selection is handled by the caller.
fn multi_select_summary(selected: &[String], inner_w: usize) -> String {
    // Try the full join first — when it fits, return it verbatim.
    let full: String = selected
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ");
    if full.chars().count() <= inner_w {
        return full;
    }
    // Otherwise, accumulate the longest prefix that fits leaving room for
    // " +K" where K is the remaining count. We try every prefix length
    // from len-1 down to 0 and pick the largest that still fits.
    let n = selected.len();
    for take in (0..n).rev() {
        let remaining = n - take;
        let suffix = format!(" +{remaining}");
        let suffix_len = suffix.chars().count();
        if take == 0 {
            // Just the suffix, no prefix.
            if suffix_len <= inner_w {
                return suffix.trim_start().to_string();
            }
            continue;
        }
        let prefix: String = selected[..take]
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join(", ");
        if prefix.chars().count() + suffix_len <= inner_w {
            return format!("{prefix}{suffix}");
        }
    }
    // Pathological narrow width — last resort, ellipsize the join.
    ellipsize(&full, inner_w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyEventKind;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        }
    }

    #[test]
    fn text_input_inserts_chars_and_moves_cursor() {
        let mut t = TextInput::default();
        let mut v = String::new();
        t.on_key(&mut v, key(KeyCode::Char('h')));
        t.on_key(&mut v, key(KeyCode::Char('i')));
        assert_eq!(v, "hi");
        assert_eq!(t.cursor, 2);
        t.on_key(&mut v, key(KeyCode::Backspace));
        assert_eq!(v, "h");
    }

    #[test]
    fn numeric_input_rejects_non_digits() {
        let mut n = NumericInput::default();
        let mut v = String::new();
        assert!(!n.on_key(&mut v, key(KeyCode::Char('a'))));
        assert!(n.on_key(&mut v, key(KeyCode::Char('7'))));
        assert_eq!(v, "7");
    }

    #[test]
    fn toggle_flips() {
        let t = Toggle::default();
        let mut v = false;
        t.on_key(&mut v, key(KeyCode::Char(' ')));
        assert!(v);
        t.on_key(&mut v, key(KeyCode::Char(' ')));
        assert!(!v);
    }

    #[test]
    fn toggle_enter_does_not_flip() {
        // Enter is reserved for commit by the parent FieldList; the
        // Toggle widget must NOT flip on Enter or the user gets a value
        // committed that's the inverse of what was displayed.
        let t = Toggle::default();
        let mut v = false;
        let changed = t.on_key(&mut v, key(KeyCode::Enter));
        assert!(!changed, "Enter must not report a value change");
        assert!(!v, "Enter must not flip the underlying value");
    }

    #[test]
    fn toggle_t_key_flips() {
        // `t` is the explicit toggle key — a mnemonic alternative to
        // Space that's discoverable in the focused-field help footer.
        let t = Toggle::default();
        let mut v = false;
        assert!(t.on_key(&mut v, key(KeyCode::Char('t'))));
        assert!(v, "t should flip false -> true");
        assert!(t.on_key(&mut v, key(KeyCode::Char('t'))));
        assert!(!v, "t should flip true -> false");
    }

    #[test]
    fn select_enter_writes_value() {
        let mut s = Select::default();
        let mut out = String::new();
        let opts = ["ssh2", "ssh3"];
        s.on_key(&opts, &mut out, key(KeyCode::Down));
        s.on_key(&opts, &mut out, key(KeyCode::Enter));
        assert_eq!(out, "ssh3");
    }

    #[test]
    fn multi_select_toggles() {
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b", "c"];
        m.on_key(&opts, &mut sel, key(KeyCode::Char(' ')));
        m.on_key(&opts, &mut sel, key(KeyCode::Down));
        m.on_key(&opts, &mut sel, key(KeyCode::Char(' ')));
        assert_eq!(sel, vec!["a".to_string(), "b".to_string()]);
        m.on_key(&opts, &mut sel, key(KeyCode::Up));
        m.on_key(&opts, &mut sel, key(KeyCode::Char(' ')));
        assert_eq!(sel, vec!["b".to_string()]);
    }

    #[test]
    fn string_list_round_trips() {
        let l = StringList::from_vec(&["aes256-gcm".into(), "chacha20".into()]);
        assert_eq!(l.parse(), vec!["aes256-gcm", "chacha20"]);
    }

    fn render_into(area: Rect, draw: impl FnOnce(&mut Buffer)) -> String {
        let mut buf = Buffer::empty(area);
        draw(&mut buf);
        let mut out = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn text_input_left_right_home_end() {
        let mut t = TextInput::default();
        let mut v = String::from("hello");
        t.cursor = 5;
        t.on_key(&mut v, key(KeyCode::Left));
        assert_eq!(t.cursor, 4);
        t.on_key(&mut v, key(KeyCode::Home));
        assert_eq!(t.cursor, 0);
        t.on_key(&mut v, key(KeyCode::Right));
        assert_eq!(t.cursor, 1);
        t.on_key(&mut v, key(KeyCode::End));
        assert_eq!(t.cursor, 5);
        // Left at 0 saturates.
        t.cursor = 0;
        t.on_key(&mut v, key(KeyCode::Left));
        assert_eq!(t.cursor, 0);
        // Right past end is noop.
        t.cursor = 5;
        t.on_key(&mut v, key(KeyCode::Right));
        assert_eq!(t.cursor, 5);
    }

    #[test]
    fn text_input_delete_at_end_is_noop() {
        let mut t = TextInput::default();
        let mut v = String::from("hi");
        t.cursor = 2;
        let changed = t.on_key(&mut v, key(KeyCode::Delete));
        assert!(!changed);
        assert_eq!(v, "hi");
    }

    #[test]
    fn text_input_delete_removes_char_at_cursor() {
        let mut t = TextInput::default();
        let mut v = String::from("abc");
        t.cursor = 1;
        let changed = t.on_key(&mut v, key(KeyCode::Delete));
        assert!(changed);
        assert_eq!(v, "ac");
    }

    #[test]
    fn text_input_backspace_at_zero_is_noop() {
        let mut t = TextInput::default();
        let mut v = String::from("x");
        t.cursor = 0;
        assert!(!t.on_key(&mut v, key(KeyCode::Backspace)));
        assert_eq!(v, "x");
    }

    #[test]
    fn text_input_ctrl_chars_are_ignored() {
        let mut t = TextInput::default();
        let mut v = String::new();
        let k = KeyEvent {
            code: KeyCode::Char('s'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        };
        assert!(!t.on_key(&mut v, k));
        assert!(v.is_empty());
    }

    #[test]
    fn text_input_clamp_handles_too_large_cursor() {
        let mut t = TextInput {
            cursor: 99, // way out of range
            ..TextInput::default()
        };
        let mut v = String::from("abc");
        t.on_key(&mut v, key(KeyCode::Char('x')));
        // Cursor was clamped to len=3, char appended.
        assert_eq!(v, "abcx");
    }

    #[test]
    fn text_input_unicode_inserts() {
        let mut t = TextInput::default();
        let mut v = String::new();
        t.on_key(&mut v, key(KeyCode::Char('ö')));
        t.on_key(&mut v, key(KeyCode::Char('日')));
        assert_eq!(v, "ö日");
        assert_eq!(t.cursor, 2);
    }

    #[test]
    fn text_input_render_shows_caret_when_focused() {
        let t = TextInput {
            cursor: 1,
            focused: true,
        };
        let area = Rect::new(0, 0, 30, 3);
        let s = render_into(area, |buf| t.render(area, buf, "label", "ab"));
        assert!(s.contains('▏'));
        assert!(s.contains("label"));
    }

    #[test]
    fn text_input_render_no_caret_when_unfocused() {
        let t = TextInput {
            cursor: 0,
            focused: false,
        };
        let area = Rect::new(0, 0, 30, 3);
        let s = render_into(area, |buf| t.render(area, buf, "label", "ab"));
        assert!(!s.contains('▏'));
    }

    #[test]
    fn numeric_input_renders_via_underlying_text() {
        let n = NumericInput::default();
        let area = Rect::new(0, 0, 30, 3);
        let s = render_into(area, |buf| n.render(area, buf, "port", "22"));
        assert!(s.contains("22"));
        assert!(s.contains("port"));
    }

    #[test]
    fn toggle_renders_distinct_states() {
        let t = Toggle { focused: false };
        let area = Rect::new(0, 0, 30, 3);
        let yes = render_into(area, |buf| t.render(area, buf, "agent", true));
        let no = render_into(area, |buf| t.render(area, buf, "agent", false));
        assert!(yes.contains("yes"));
        assert!(no.contains("no"));
    }

    #[test]
    fn toggle_y_and_n_keys_no_longer_flip() {
        // Per user contract: ONLY Space and `t` flip a Toggle. Every
        // other key — including the historical y/n shortcuts — must
        // leave the value untouched.
        let t = Toggle::default();
        let mut v = false;
        let changed_y = t.on_key(&mut v, key(KeyCode::Char('y')));
        assert!(!changed_y, "y must not report a value change");
        assert!(!v, "y must not flip the value");
        let changed_n = t.on_key(&mut v, key(KeyCode::Char('n')));
        assert!(!changed_n, "n must not report a value change");
        assert!(!v, "n must not flip the value");
    }

    /// Exhaustive matrix: every plausible key the user might press
    /// while focused on a Bool field. Only Space and `t` must flip;
    /// every other entry must leave the value untouched.
    #[test]
    fn toggle_only_space_and_t_flip() {
        use KeyCode::*;
        // (keycode, expected_to_flip)
        let cases: &[(KeyCode, bool)] = &[
            // Allowed flip keys
            (Char(' '), true),
            (Char('t'), true),
            // Disallowed — must NOT flip
            (Enter, false),
            (Char('y'), false),
            (Char('n'), false),
            (Char('T'), false), // case-sensitive: capital T not allowed
            (Char('Y'), false),
            (Char('N'), false),
            (Tab, false),
            (Esc, false),
            (Up, false),
            (Down, false),
            (Left, false),
            (Right, false),
            (Home, false),
            (End, false),
            (PageUp, false),
            (PageDown, false),
            (Backspace, false),
            (Delete, false),
            (Insert, false),
            (BackTab, false),
            (Char('a'), false),
            (Char('1'), false),
            (Char('!'), false),
            (Char('\u{1b}'), false),
            (F(1), false),
            (F(5), false),
        ];
        for (code, should_flip) in cases {
            let t = Toggle::default();
            let mut v = false;
            let changed = t.on_key(&mut v, key(*code));
            assert_eq!(
                changed, *should_flip,
                "key {code:?}: expected changed={should_flip}, got {changed}"
            );
            assert_eq!(
                v, *should_flip,
                "key {code:?}: expected value={should_flip}, got {v}"
            );
        }
    }

    #[test]
    fn select_up_at_zero_wraps() {
        // Wrap semantics: Up at 0 jumps to the last option.
        let mut s = Select::default();
        let mut out = String::new();
        let opts = ["a", "b"];
        s.on_key(&opts, &mut out, key(KeyCode::Up));
        assert_eq!(s.index, 1);
    }

    #[test]
    fn select_down_past_end_wraps() {
        // Wrap semantics: Down at last wraps back to 0.
        let mut s = Select::default();
        let mut out = String::new();
        let opts = ["a", "b"];
        s.on_key(&opts, &mut out, key(KeyCode::Down));
        s.on_key(&opts, &mut out, key(KeyCode::Down)); // wraps to 0
        assert_eq!(s.index, 0);
    }

    #[test]
    fn select_renders_current_marker() {
        let s = Select {
            index: 1,
            focused: true,
        };
        let area = Rect::new(0, 0, 30, 6);
        let opts = ["a", "b"];
        let out = render_into(area, |buf| s.render(area, buf, "kind", &opts, "b"));
        assert!(out.contains('●'));
        assert!(out.contains('○'));
    }

    #[test]
    fn multi_select_render_shows_marks() {
        let m = MultiSelect::default();
        let area = Rect::new(0, 0, 30, 6);
        let opts = ["aa", "bb"];
        let sel = vec!["aa".to_owned()];
        let out = render_into(area, |buf| m.render(area, buf, "lst", &opts, &sel));
        assert!(out.contains("[x] aa"));
        assert!(out.contains("[ ] bb"));
    }

    #[test]
    fn multi_select_up_wraps() {
        // Wrap semantics: Up at 0 jumps to last.
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b"];
        m.on_key(&opts, &mut sel, key(KeyCode::Up));
        assert_eq!(m.index, 1);
    }

    #[test]
    fn multi_select_down_past_end_wraps() {
        // Wrap semantics: Down at last wraps to 0.
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b"];
        m.on_key(&opts, &mut sel, key(KeyCode::Down));
        m.on_key(&opts, &mut sel, key(KeyCode::Down)); // wraps to 0
        assert_eq!(m.index, 0);
    }

    #[test]
    fn string_list_render_does_not_panic() {
        let l = StringList::from_vec(&["a".into()]);
        let area = Rect::new(0, 0, 30, 3);
        let out = render_into(area, |buf| l.render(area, buf, "lst"));
        assert!(out.contains("lst"));
    }

    #[test]
    fn string_list_on_key_inserts_chars() {
        let mut l = StringList::default();
        assert!(l.on_key(key(KeyCode::Char('x'))));
        assert_eq!(l.raw, "x");
    }

    #[test]
    fn string_list_from_vec_seeds_raw() {
        let l = StringList::from_vec(&["aa".into(), "bb".into()]);
        assert_eq!(l.raw, "aa, bb");
        assert_eq!(l.text.cursor, "aa, bb".chars().count());
    }

    #[test]
    fn select_no_match_no_panic() {
        let mut s = Select::default();
        let mut out = String::new();
        let opts: [&str; 0] = [];
        // Empty options + Enter: index stays 0 and no value written.
        assert!(!s.on_key(&opts, &mut out, key(KeyCode::Enter)));
        assert!(out.is_empty());
    }

    #[test]
    fn multi_select_empty_options_enter_noop() {
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts: [&str; 0] = [];
        assert!(!m.on_key(&opts, &mut sel, key(KeyCode::Enter)));
    }

    #[test]
    fn text_input_unhandled_keys_return_false() {
        let mut t = TextInput::default();
        let mut v = String::new();
        let k = KeyEvent {
            code: KeyCode::F(5),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: crossterm::event::KeyEventState::NONE,
        };
        assert!(!t.on_key(&mut v, k));
    }

    #[test]
    fn numeric_input_pass_through_navigation() {
        let mut n = NumericInput::default();
        let mut v = String::from("12");
        n.text.cursor = 2;
        // Left arrow should pass through.
        assert!(!n.on_key(&mut v, key(KeyCode::Left)));
        assert_eq!(n.text.cursor, 1);
    }

    // -----------------------------------------------------------------
    // Phase 1 reproducers — t-tui-rotate (RC2, RC3).
    // -----------------------------------------------------------------

    #[test]
    fn select_left_right_rotate_value() {
        // RC2 reproducer: Left/Right should rotate the cursor through
        // the option list, with wrap.
        let mut s = Select {
            index: 1,
            focused: true,
        };
        let mut out = String::new();
        let opts = ["a", "b", "c"];
        // Left from 1 -> 0.
        s.on_key(&opts, &mut out, key(KeyCode::Left));
        assert_eq!(s.index, 0, "Left should decrement");
        // Right from 0 -> 1, then 1 -> 2, then 2 wraps to 0.
        s.on_key(&opts, &mut out, key(KeyCode::Right));
        assert_eq!(s.index, 1);
        s.on_key(&opts, &mut out, key(KeyCode::Right));
        assert_eq!(s.index, 2);
        s.on_key(&opts, &mut out, key(KeyCode::Right));
        assert_eq!(s.index, 0, "Right past end should wrap");
        // Left at 0 -> wraps to last.
        s.on_key(&opts, &mut out, key(KeyCode::Left));
        assert_eq!(s.index, 2, "Left at 0 should wrap to last");
    }

    #[test]
    fn select_up_at_zero_wraps_to_last() {
        // RC3 reproducer.
        let mut s = Select::default();
        let mut out = String::new();
        let opts = ["a", "b", "c"];
        s.on_key(&opts, &mut out, key(KeyCode::Up));
        assert_eq!(s.index, 2, "Up at index 0 wraps to last");
    }

    #[test]
    fn select_down_at_end_wraps_to_zero() {
        // RC3 reproducer.
        let mut s = Select {
            index: 2,
            focused: true,
        };
        let mut out = String::new();
        let opts = ["a", "b", "c"];
        s.on_key(&opts, &mut out, key(KeyCode::Down));
        assert_eq!(s.index, 0, "Down at last index wraps to zero");
    }

    #[test]
    fn multi_select_up_at_zero_wraps_to_last() {
        // RC3 reproducer for MultiSelect.
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b", "c"];
        m.on_key(&opts, &mut sel, key(KeyCode::Up));
        assert_eq!(m.index, 2, "MultiSelect Up at 0 wraps to last");
    }

    #[test]
    fn multi_select_down_at_end_wraps_to_zero() {
        // RC3 reproducer for MultiSelect.
        let mut m = MultiSelect {
            index: 2,
            focused: true,
        };
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b", "c"];
        m.on_key(&opts, &mut sel, key(KeyCode::Down));
        assert_eq!(m.index, 0, "MultiSelect Down at last wraps to zero");
    }

    #[test]
    fn multi_select_space_toggles_at_focused_index() {
        // Regression guard: Space must still toggle membership at the
        // cursor's option, independent of wrap behavior.
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b", "c"];
        // Move to index 1 via Down then toggle.
        m.on_key(&opts, &mut sel, key(KeyCode::Down));
        assert_eq!(m.index, 1);
        m.on_key(&opts, &mut sel, key(KeyCode::Char(' ')));
        assert_eq!(sel, vec!["b".to_string()]);
        // Toggle again removes.
        m.on_key(&opts, &mut sel, key(KeyCode::Char(' ')));
        assert!(sel.is_empty());
    }

    #[test]
    fn multi_select_t_key_toggles_at_focused_index() {
        // `t` is the new mnemonic toggle key — must work identically
        // to Space for Multi checkboxes.
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b", "c"];
        m.on_key(&opts, &mut sel, key(KeyCode::Char('t')));
        assert_eq!(sel, vec!["a".to_string()]);
        m.on_key(&opts, &mut sel, key(KeyCode::Char('t')));
        assert!(sel.is_empty());
    }

    #[test]
    fn multi_select_enter_no_longer_toggles() {
        // User contract: Enter never toggles a tickbox. Pressing Enter
        // on a MultiSelect must leave `selected` unchanged so the
        // parent FieldList can use Enter for commit unambiguously.
        let mut m = MultiSelect::default();
        let mut sel: Vec<String> = vec![];
        let opts = ["a", "b", "c"];
        let changed = m.on_key(&opts, &mut sel, key(KeyCode::Enter));
        assert!(!changed, "Enter must not report a selection change");
        assert!(sel.is_empty(), "Enter must not toggle membership");
    }

    /// Exhaustive lockdown matrix for MultiSelect checkboxes. Mirrors
    /// the Toggle widget's matrix: only Space and `t` flip; every
    /// other key including Enter is a no-op for membership state.
    /// Cursor keys (arrows) move the cursor but must not mutate
    /// `selected`.
    #[test]
    fn multi_select_only_space_and_t_toggle_membership() {
        use KeyCode::*;
        // (keycode, should_toggle_membership)
        let cases: &[(KeyCode, bool)] = &[
            (Char(' '), true),
            (Char('t'), true),
            (Enter, false),
            (Char('y'), false),
            (Char('n'), false),
            (Char('T'), false),
            (Char('a'), false),
            (Char('1'), false),
            (Up, false),
            (Down, false),
            (Left, false),
            (Right, false),
            (Home, false),
            (End, false),
            (Tab, false),
            (Esc, false),
            (Backspace, false),
            (Delete, false),
            (F(1), false),
        ];
        for (code, should_toggle) in cases {
            let mut m = MultiSelect::default();
            let mut sel: Vec<String> = vec![];
            let opts = ["a", "b", "c"];
            let changed = m.on_key(&opts, &mut sel, key(*code));
            assert_eq!(
                changed, *should_toggle,
                "key {code:?}: expected changed={should_toggle}"
            );
            if *should_toggle {
                assert_eq!(sel, vec!["a".to_string()], "key {code:?} must toggle in");
            } else {
                assert!(sel.is_empty(), "key {code:?} must not touch selected");
            }
        }
    }

    // -----------------------------------------------------------------
    // Phase 1 reproducers — t-tui-spinner.
    //
    // These pin the compact-area render path for Select / MultiSelect.
    // Field rows allocated by `FieldList::render` use `row_h = 3`, which
    // leaves a single inner line after `Borders::ALL`. The legacy code
    // path rendered each option on its own line — only row 0 was visible,
    // and unfocused rows always showed `options[0]` rather than the
    // configured value. The new compact-spinner path is selected when
    // `inner_height < options.len()` and renders a single line that
    // reflects the actual value (unfocused) or the cursor (focused, with
    // chrome `◀ … ▶  (i/N)`).
    // -----------------------------------------------------------------

    #[test]
    fn select_compact_focused_shows_cursor_option_not_first() {
        // Area 30x3 → inner height = 1, options.len() = 3 → compact path.
        // Cursor on index 1 ("b") with focus: must render the cursor's
        // option, not options[0]. Chrome `◀` / `▶` must be present.
        let s = Select {
            index: 1,
            focused: true,
        };
        let area = Rect::new(0, 0, 30, 3);
        let opts = ["a", "b", "c"];
        let out = render_into(area, |buf| s.render(area, buf, "kind", &opts, "a"));
        assert!(
            out.contains('b'),
            "compact focused render must show cursor option `b`:\n{out}"
        );
        assert!(
            out.contains('◀') && out.contains('▶'),
            "compact focused render must show rotate chrome:\n{out}"
        );
    }

    #[test]
    fn select_compact_unfocused_shows_current_not_options_zero() {
        // Killer demo of the user-reported bug: unfocused row must show
        // the actual `current` value, not the first option.
        let s = Select {
            index: 0,
            focused: false,
        };
        let area = Rect::new(0, 0, 30, 3);
        let opts = ["a", "b", "c"];
        let out = render_into(area, |buf| s.render(area, buf, "kind", &opts, "c"));
        assert!(
            out.contains('c'),
            "compact unfocused render must show current value `c`:\n{out}"
        );
        // The legacy code rendered `○ a` (options[0]) — guard against that.
        assert!(
            !out.contains("○ a"),
            "compact unfocused render must not mislabel as options[0]:\n{out}"
        );
    }

    #[test]
    fn multi_select_compact_focused_shows_cursor_option_with_mark() {
        // Focused multi at 30x3 with cursor on index 1 ("b"), already
        // selected: must show `[x] b` plus the rotate chrome.
        let m = MultiSelect {
            index: 1,
            focused: true,
        };
        let area = Rect::new(0, 0, 30, 3);
        let opts = ["a", "b", "c"];
        let sel = vec!["b".to_owned()];
        let out = render_into(area, |buf| m.render(area, buf, "lst", &opts, &sel));
        assert!(
            out.contains("[x] b"),
            "compact focused multi must show `[x] b`:\n{out}"
        );
        assert!(
            out.contains('◀') && out.contains('▶'),
            "compact focused multi must show rotate chrome:\n{out}"
        );
    }

    #[test]
    fn multi_select_compact_unfocused_shows_summary_with_overflow() {
        // Narrow area + long item names so the joined summary overflows
        // the inner width, forcing a `+K` indicator. inner_w = 18, joined
        // `"alpha, bravo, charlie, delta, echo"` is 34 chars → overflow.
        let m = MultiSelect {
            index: 0,
            focused: false,
        };
        let area = Rect::new(0, 0, 20, 3);
        let opts = ["alpha", "bravo", "charlie", "delta", "echo"];
        let sel = vec![
            "alpha".to_owned(),
            "bravo".to_owned(),
            "charlie".to_owned(),
            "delta".to_owned(),
            "echo".to_owned(),
        ];
        let out = render_into(area, |buf| m.render(area, buf, "lst", &opts, &sel));
        assert!(
            out.contains('+'),
            "compact unfocused multi must show overflow marker:\n{out}"
        );
        assert!(
            out.contains("alpha"),
            "compact unfocused multi must show at least the first item:\n{out}"
        );
    }

    #[test]
    fn select_tall_area_still_uses_list_render() {
        // 30x6 → inner height = 4 ≥ options.len() = 3 → list path is
        // used. Both the highlight marker (●) and the unfocused marker
        // (○) must be present, demonstrating the multi-line fallback
        // is preserved when there's room.
        let s = Select {
            index: 1,
            focused: true,
        };
        let area = Rect::new(0, 0, 30, 6);
        let opts = ["a", "b", "c"];
        let out = render_into(area, |buf| s.render(area, buf, "kind", &opts, "b"));
        assert!(
            out.contains("● b"),
            "tall area should still use multi-line list render:\n{out}"
        );
        assert!(
            out.contains("○ a"),
            "tall area should still show non-current options:\n{out}"
        );
    }

    #[test]
    fn text_input_render_caret_visible_on_empty() {
        // RC4 reproducer: an empty focused TextInput must render a
        // visually distinguishable caret cell at the inner content
        // origin (x=1, y=1 inside the bordered block).
        //
        // Distinguishing = REVERSED modifier specifically. The block
        // border cells are styled BOLD/Yellow, so weaker checks would
        // false-positive against neighboring borders. The REVERSED
        // modifier is what makes the caret cell visibly stand out
        // against an otherwise-default-styled content area.
        use ratatui::style::Modifier;

        let t = TextInput {
            cursor: 0,
            focused: true,
        };
        let area = Rect::new(0, 0, 30, 3);
        let mut buf = Buffer::empty(area);
        t.render(area, &mut buf, "label", "");

        // The caret cell sits at (1, 1) — content origin inside borders.
        let cell = &buf[(1, 1)];
        let sym = cell.symbol();
        assert!(
            sym == "▏" || sym == "█",
            "expected caret glyph at (1,1), got {sym:?}"
        );
        // REVERSED modifier on that cell so it stands out against an
        // empty content area.
        let style = cell.style();
        assert!(
            style.add_modifier.contains(Modifier::REVERSED),
            "caret cell at (1,1) must have REVERSED modifier: {style:?}"
        );
    }
}
