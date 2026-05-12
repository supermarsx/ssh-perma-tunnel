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
//! * `FilePicker` — alias for [`TextInput`] with a path hint.
//!
//! Widgets do not own their model — the page passes a `&mut String` (or
//! similar) when handling input. This keeps state ownership simple and lets
//! tests drive widgets directly.

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

/// Boolean toggle. Space/Enter flips.
#[derive(Debug, Default, Clone, Copy)]
pub struct Toggle {
    /// Whether this widget currently owns focus.
    pub focused: bool,
}

impl Toggle {
    /// Apply a key. Returns `true` if the value flipped.
    pub fn on_key(&self, value: &mut bool, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(' ') | KeyCode::Enter | KeyCode::Char('y') | KeyCode::Char('n') => {
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
    pub fn on_key(&mut self, options: &[&str], out: &mut String, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Up => {
                if self.index > 0 {
                    self.index -= 1;
                }
                false
            }
            KeyCode::Down => {
                if self.index + 1 < options.len() {
                    self.index += 1;
                }
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
    /// Apply a key. Toggles membership of the cursor's option in `selected`.
    pub fn on_key(&mut self, options: &[&str], selected: &mut Vec<String>, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Up => {
                self.index = self.index.saturating_sub(1);
                false
            }
            KeyCode::Down => {
                if self.index + 1 < options.len() {
                    self.index += 1;
                }
                false
            }
            KeyCode::Char(' ') | KeyCode::Enter => {
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
}
