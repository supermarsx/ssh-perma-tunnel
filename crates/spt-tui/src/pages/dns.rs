//! "DNS" page — per-forward `dns_names` registration plus a global
//! `[[dns.records]]` list editor.
//!
//! The page has two stacked regions:
//!
//! 1. **Forward DNS names** (top) — a [`FieldList`] editing the selected
//!    forward's [`Forward::dns_names`]. Historically this only edited
//!    `forwards[0]`; it now covers **all** forwards via a forward selector
//!    (`Left`/`Right` cycle the selected forward when more than one exists).
//!    This is per-profile data, so it stays on the [`FieldList`]/[`Profile`]
//!    machinery. When there are 0 or 1 forwards the region renders exactly as
//!    before (`forward[0].dns_names`) so the default-state snapshot stays
//!    byte-identical.
//! 2. **Global `[[dns.records]]`** (bottom) — a hand-rolled add/`d`elete/
//!    `Enter`-edit list editor over [`Model::dns_mut`]`().records`, mirroring
//!    [`crate::pages::events::EventsPage`]'s sink editor. This is **global**
//!    config (`config.dns`), independent of the selected profile.
//!
//! **Snapshot parity:** the records editor only paints its interactive
//! list/detail when the Records region is focused or an editor is open. When
//! the Records region is unfocused (the page's default state) it renders the
//! exact original read-only `[[dns.records]]` paragraph, so the default DNS
//! snapshot — which is generated against a sample that *does* carry one
//! record — stays byte-identical.
//!
//! `DnsRecord` carries no secret material, so (unlike the events sink editor)
//! there are no redacted rows here.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::buffer::Buffer;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, StatefulWidget, Widget,
};
use spt_config::schema::{DnsRecord, Profile};

use crate::model::Model;
use crate::pages::field::{opt_list, FieldDef, FieldList};
use crate::pages::Page;
use crate::widgets::{Select, TextInput};

/// Record `type` discriminator options.
const RECORD_KINDS: &[&str] = &["A", "AAAA", "SRV", "TXT"];

/// Which stacked region currently owns keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Region {
    /// Per-forward `dns_names` FieldList (+ forward selector).
    Forwards,
    /// Global `[[dns.records]]` list/editor.
    Records,
}

/// Kind of value a hand-rolled record editor row holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowKind {
    /// Free-form single-line text.
    Text,
    /// Fixed-choice from `RECORD_KINDS`.
    Choice,
    /// Numeric text parsed to `Option<u16>` on commit (empty → None).
    Numeric,
}

/// One editable row inside the hand-rolled record editor.
struct EditorRow {
    /// Display label / TOML key.
    label: &'static str,
    /// One-line help.
    help: &'static str,
    /// Value kind (drives widget + validation).
    kind: RowKind,
    /// Working buffer (canonical for Text/Numeric; materialized for Choice).
    value: String,
    /// Cursor-aware text input state (Text / Numeric).
    text: TextInput,
    /// Choice spinner state.
    select: Select,
    /// Static option list for `Choice`.
    options: &'static [&'static str],
    /// Whether this row is required (non-empty).
    required: bool,
    /// Last validation error, if any.
    last_error: Option<String>,
}

impl EditorRow {
    fn text(label: &'static str, help: &'static str, value: String, required: bool) -> Self {
        Self::new(label, help, RowKind::Text, value, &[], required)
    }
    fn numeric(label: &'static str, help: &'static str, value: String) -> Self {
        Self::new(label, help, RowKind::Numeric, value, &[], false)
    }
    fn choice(
        label: &'static str,
        help: &'static str,
        options: &'static [&'static str],
        value: String,
    ) -> Self {
        let mut row = Self::new(label, help, RowKind::Choice, value, options, true);
        row.select.index = options.iter().position(|o| *o == row.value).unwrap_or(0);
        row
    }

    fn new(
        label: &'static str,
        help: &'static str,
        kind: RowKind,
        value: String,
        options: &'static [&'static str],
        required: bool,
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
            select: Select::default(),
            options,
            required,
            last_error: None,
        }
    }

    /// Sync the working `value` from the row's active widget at commit time.
    /// For `Choice`, the spinner only moves its cursor index while editing.
    fn commit_value(&mut self) {
        if self.kind == RowKind::Choice {
            if let Some(opt) = self.options.get(self.select.index) {
                self.value = (*opt).to_owned();
            }
        }
    }

    /// Validate the current buffer; `Some(err)` blocks commit.
    ///
    /// * required text rows must be non-empty;
    /// * numeric rows allow empty (→ None) but reject non-`u16` input.
    fn validate(&self) -> Option<String> {
        match self.kind {
            RowKind::Text => {
                if self.required && self.value.trim().is_empty() {
                    return Some(format!("{} must not be empty", self.label));
                }
                None
            }
            RowKind::Numeric => {
                if !self.value.is_empty() && self.value.parse::<u16>().is_err() {
                    return Some(format!("`{}` is not a valid u16", self.value));
                }
                None
            }
            RowKind::Choice => None,
        }
    }

    /// Apply an edit-mode key. Returns `true` if the buffer changed.
    fn on_key(&mut self, key: KeyEvent) -> bool {
        match self.kind {
            RowKind::Text => {
                let mut tmp = std::mem::take(&mut self.value);
                let changed = self.text.on_key(&mut tmp, key);
                self.value = tmp;
                changed
            }
            RowKind::Numeric => {
                // Restrict to digits so a non-numeric char never lands in the
                // buffer (the validator is a second line of defence).
                if let KeyCode::Char(c) = key.code {
                    if !c.is_ascii_digit() {
                        return false;
                    }
                }
                let mut tmp = std::mem::take(&mut self.value);
                let changed = self.text.on_key(&mut tmp, key);
                self.value = tmp;
                changed
            }
            RowKind::Choice => self.select.on_key(self.options, &mut self.value, key),
        }
    }

    fn render(&self, area: Rect, buf: &mut Buffer, editing: bool, focused: bool) {
        match self.kind {
            RowKind::Text | RowKind::Numeric => {
                if editing {
                    let mut t = self.text.clone();
                    t.focused = true;
                    t.render(area, buf, self.label, &self.value);
                } else {
                    render_static(area, buf, self.label, &self.value, focused);
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

/// A hand-rolled multi-row editor for one DNS record.
struct RecordEditor {
    /// Index of the record being edited within `Dns.records`.
    index: usize,
    /// Editable rows.
    rows: Vec<EditorRow>,
    /// Focused row.
    focus: usize,
    /// Whether the focused row is in active edit mode.
    editing: bool,
}

impl RecordEditor {
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

    /// Handle a key while the editor is open. Returns `(committed, close)`.
    /// `committed` is only true when a field edit passed validation; mid-edit
    /// keystrokes return `false` so a half-typed buffer never reaches the
    /// model. `close` requests the editor be torn down (pane-nav left).
    fn on_key(&mut self, key: KeyEvent) -> (bool, bool) {
        if self.editing {
            match key.code {
                KeyCode::Esc => {
                    self.editing = false;
                    (false, false)
                }
                KeyCode::Enter => {
                    if let Some(row) = self.rows.get_mut(self.focus) {
                        row.commit_value();
                        if let Some(err) = row.validate() {
                            row.last_error = Some(err);
                            return (false, false);
                        }
                        row.last_error = None;
                    }
                    self.editing = false;
                    (true, false)
                }
                _ => {
                    if let Some(row) = self.rows.get_mut(self.focus) {
                        row.on_key(key);
                    }
                    (false, false)
                }
            }
        } else {
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
                    }
                    self.editing = true;
                    (false, false)
                }
                _ => (false, false),
            }
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

/// Build the editor rows for one DNS record. All seven fields are shown
/// always; the SRV-only numeric rows are blank for non-SRV records.
fn record_rows(r: &DnsRecord) -> Vec<EditorRow> {
    vec![
        EditorRow::text("name", "Owner name / FQDN (required)", r.name.clone(), true),
        EditorRow::choice(
            "type",
            "Record type (A/AAAA/SRV/TXT)",
            RECORD_KINDS,
            if r.kind.is_empty() {
                RECORD_KINDS[0].to_owned()
            } else {
                r.kind.clone()
            },
        ),
        EditorRow::text(
            "value",
            "Record value (IP for A/AAAA, target for SRV/TXT)",
            r.value.clone(),
            false,
        ),
        EditorRow::text(
            "ttl",
            "Per-record TTL (optional, e.g. 300s)",
            r.ttl.clone().unwrap_or_default(),
            false,
        ),
        EditorRow::numeric(
            "priority",
            "SRV priority (u16, optional)",
            r.priority.map(|n| n.to_string()).unwrap_or_default(),
        ),
        EditorRow::numeric(
            "weight",
            "SRV weight (u16, optional)",
            r.weight.map(|n| n.to_string()).unwrap_or_default(),
        ),
        EditorRow::numeric(
            "port",
            "SRV port (u16, optional)",
            r.port.map(|n| n.to_string()).unwrap_or_default(),
        ),
    ]
}

/// Write the editor rows back into a record. Empty numeric/text optionals
/// clear to `None`; non-numeric input is blocked at commit time so it never
/// reaches here.
fn apply_record_rows(rows: &[EditorRow], r: &mut DnsRecord) {
    let opt = |v: &str| {
        if v.is_empty() {
            None
        } else {
            Some(v.to_owned())
        }
    };
    let opt_u16 = |v: &str| -> Option<u16> {
        if v.is_empty() {
            None
        } else {
            v.parse::<u16>().ok()
        }
    };
    for row in rows {
        match row.label {
            "name" => r.name = row.value.clone(),
            "type" => r.kind = row.value.clone(),
            "value" => r.value = row.value.clone(),
            "ttl" => r.ttl = opt(&row.value),
            "priority" => r.priority = opt_u16(&row.value),
            "weight" => r.weight = opt_u16(&row.value),
            "port" => r.port = opt_u16(&row.value),
            _ => {}
        }
    }
}

/// DNS page: per-forward `dns_names` + global `[[dns.records]]`.
pub struct DnsPage {
    /// Per-forward `dns_names` FieldList (region 1). Rebuilt when the
    /// selected forward changes so the label/accessor track the selection.
    list: FieldList,
    /// Index of the forward whose `dns_names` the FieldList currently edits.
    forward_sel: usize,
    /// Active region for keyboard input.
    region: Region,
    /// Selected record index (list mode).
    record_sel: usize,
    /// Open record editor, if any.
    editor: Option<RecordEditor>,
    /// Cached list state for rendering.
    record_list_state: ListState,
}

impl DnsPage {
    /// Build the page.
    #[must_use]
    pub fn new() -> Self {
        Self {
            list: FieldList::new(vec![dns_names_field(0)]),
            forward_sel: 0,
            region: Region::Forwards,
            record_sel: 0,
            editor: None,
            record_list_state: ListState::default(),
        }
    }

    fn n_records(model: &Model) -> usize {
        model.dns().map_or(0, |d| d.records.len())
    }

    fn n_forwards(model: &Model) -> usize {
        model.profile().forwards.len()
    }

    /// Rebuild the `dns_names` FieldList so it targets `forward_sel`. When
    /// `forward_sel == 0` the label stays `forward[0].dns_names` (byte-
    /// identical to the historical single-forward page).
    fn rebuild_list(&mut self) {
        self.list = FieldList::new(vec![dns_names_field(self.forward_sel)]);
    }

    fn open_editor(&mut self, model: &Model, idx: usize) {
        if let Some(r) = model.dns().and_then(|d| d.records.get(idx)) {
            self.editor = Some(RecordEditor::new(idx, record_rows(r)));
        }
    }

    /// Write the open editor's rows back into the model after a field commit.
    fn commit_editor(&mut self, model: &mut Model) {
        if let Some(ed) = self.editor.as_ref() {
            let idx = ed.index;
            if let Some(r) = model.dns_mut().records.get_mut(idx) {
                apply_record_rows(&ed.rows, r);
            }
        }
    }
}

/// Build the single `dns_names` FieldList field bound to `forwards[i]`. The
/// label keeps the historical `forward[0].dns_names` form for index 0.
fn dns_names_field(i: usize) -> FieldDef {
    let label: &'static str = match i {
        0 => "forward[0].dns_names",
        1 => "forward[1].dns_names",
        2 => "forward[2].dns_names",
        3 => "forward[3].dns_names",
        4 => "forward[4].dns_names",
        5 => "forward[5].dns_names",
        6 => "forward[6].dns_names",
        7 => "forward[7].dns_names",
        _ => "forward[n].dns_names",
    };
    opt_list(
        label,
        "DNS names registered by this forward (CSV) — ←/→ to pick a forward",
        move |p: &Profile| {
            p.forwards
                .get(i)
                .and_then(|f| f.dns_names.clone())
                .unwrap_or_default()
        },
        move |p: &mut Profile, v| {
            if let Some(f) = p.forwards.get_mut(i) {
                f.dns_names = if v.is_empty() { None } else { Some(v) };
            }
        },
    )
}

impl Default for DnsPage {
    fn default() -> Self {
        Self::new()
    }
}

impl Page for DnsPage {
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(5), Constraint::Min(0)])
            .split(area);

        // Region 1: per-forward dns_names FieldList.
        self.list.render(chunks[0], buf, model.profile());

        // Region 2: global [[dns.records]].
        //
        // When the Records region is unfocused AND no editor is open, render
        // the original read-only paragraph (byte-identical default snapshot).
        // Once the operator focuses the region (or opens an editor) it becomes
        // an interactive list/detail editor.
        let interactive = self.region == Region::Records || self.editor.is_some();
        if interactive {
            self.render_records(chunks[1], buf, model);
        } else {
            render_records_readonly(chunks[1], buf, model);
        }
    }

    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        match self.region {
            Region::Forwards => self.on_key_forwards(key, model),
            Region::Records => self.on_key_records(key, model),
        }
    }

    fn focused_help(&self) -> Option<&str> {
        match self.region {
            Region::Forwards => self.list.focused_help(),
            Region::Records => self
                .editor
                .as_ref()
                .and_then(|e| e.rows.get(e.focus))
                .map(|r| r.help)
                .or(Some("Records: a=add d=del Enter=edit ↑/↓=move ←=back")),
        }
    }

    fn focused_position(&self) -> Option<(usize, usize)> {
        match self.region {
            Region::Forwards => self.list.focus_position(),
            Region::Records => None,
        }
    }

    fn is_editing(&self) -> bool {
        match self.region {
            Region::Forwards => self.list.editing,
            Region::Records => self.editor.as_ref().is_some_and(|e| e.editing),
        }
    }
}

impl DnsPage {
    fn on_key_forwards(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if self.list.editing {
            let changed = self.list.on_edit_key(key, model.profile_mut_silent());
            if changed {
                model.mark_dirty();
            }
            return changed;
        }
        match key.code {
            // Left/Right cycle the selected forward (only meaningful with >1).
            KeyCode::Right => {
                let n = Self::n_forwards(model);
                if n > 1 {
                    self.forward_sel = (self.forward_sel + 1) % n;
                    self.rebuild_list();
                }
                false
            }
            KeyCode::Left => {
                let n = Self::n_forwards(model);
                if n > 1 {
                    self.forward_sel = if self.forward_sel == 0 {
                        n - 1
                    } else {
                        self.forward_sel - 1
                    };
                    self.rebuild_list();
                }
                false
            }
            // Down at the (single-row) FieldList crosses into Records.
            KeyCode::Down | KeyCode::Char('j') => {
                self.region = Region::Records;
                false
            }
            _ => {
                self.list.on_nav_key(key, model.profile());
                false
            }
        }
    }

    fn on_key_records(&mut self, key: KeyEvent, model: &mut Model) -> bool {
        if let Some(ed) = self.editor.as_mut() {
            let (changed, close) = ed.on_key(key);
            if changed {
                self.commit_editor(model);
                return true;
            }
            if close {
                self.editor = None;
            }
            return false;
        }
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                // At the top of the list, Up crosses up into Forwards.
                if self.record_sel == 0 {
                    self.region = Region::Forwards;
                } else {
                    self.record_sel -= 1;
                }
                false
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let n = Self::n_records(model);
                if self.record_sel + 1 < n {
                    self.record_sel += 1;
                }
                false
            }
            KeyCode::Left => {
                // Pane-nav left: return to the Forwards region.
                self.region = Region::Forwards;
                false
            }
            KeyCode::Enter | KeyCode::Right => {
                if self.record_sel < Self::n_records(model) {
                    self.open_editor(model, self.record_sel);
                }
                false
            }
            KeyCode::Char('a') => {
                let n = Self::n_records(model);
                let record = DnsRecord {
                    name: format!("record-{}", n + 1),
                    kind: RECORD_KINDS[0].to_owned(),
                    ..Default::default()
                };
                model.dns_mut().records.push(record);
                self.record_sel = n;
                self.open_editor(model, n);
                true
            }
            KeyCode::Char('d') => {
                let n = Self::n_records(model);
                if self.record_sel < n {
                    model.dns_mut().records.remove(self.record_sel);
                    let after = Self::n_records(model);
                    if self.record_sel >= after && self.record_sel > 0 {
                        self.record_sel -= 1;
                    }
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    fn render_records(&mut self, area: Rect, buf: &mut Buffer, model: &Model) {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        let records = model.dns().map_or(&[][..], |d| d.records.as_slice());
        let items: Vec<ListItem<'_>> = records
            .iter()
            .map(|r| ListItem::new(format!("{:<24} [{}]", r.name, r.kind)))
            .collect();
        if !items.is_empty() {
            self.record_list_state
                .select(Some(self.record_sel.min(items.len() - 1)));
        }
        let hl = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        let block = Block::default()
            .borders(Borders::ALL)
            .title("Records* (a=add d=del Enter=edit)");
        let list = List::new(items)
            .block(block)
            .highlight_style(hl)
            .highlight_symbol("▶ ");
        StatefulWidget::render(list, cols[0], buf, &mut self.record_list_state);

        if let Some(ed) = self.editor.as_ref() {
            ed.render(cols[1], buf);
        } else if let Some(r) = records.get(self.record_sel) {
            let lines = vec![
                Line::from(format!("name:     {}", r.name)),
                Line::from(format!("type:     {}", r.kind)),
                Line::from(format!("value:    {}", r.value)),
                Line::from(format!("ttl:      {}", r.ttl.clone().unwrap_or_default())),
                Line::from(format!(
                    "priority: {}",
                    r.priority.map(|n| n.to_string()).unwrap_or_default()
                )),
                Line::from(format!(
                    "weight:   {}",
                    r.weight.map(|n| n.to_string()).unwrap_or_default()
                )),
                Line::from(format!(
                    "port:     {}",
                    r.port.map(|n| n.to_string()).unwrap_or_default()
                )),
            ];
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Record detail");
            Paragraph::new(lines).block(block).render(cols[1], buf);
        } else {
            let block = Block::default()
                .borders(Borders::ALL)
                .title("Record detail");
            Paragraph::new("(no records — press `a` to add)")
                .block(block)
                .render(cols[1], buf);
        }
    }
}

/// Render the original read-only `[[dns.records]]` paragraph. This is the
/// page's default (unfocused-region) presentation; keeping it byte-for-byte
/// identical to the pre-editor layout preserves the default DNS snapshot.
fn render_records_readonly(area: Rect, buf: &mut Buffer, model: &Model) {
    let lines: Vec<Line<'_>> = model
        .config()
        .dns
        .as_ref()
        .map(|d| {
            d.records
                .iter()
                .map(|r| Line::from(format!("{:<32} {:<5} {}", r.name, r.kind, r.value)))
                .collect()
        })
        .unwrap_or_default();
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Global [[dns.records]] (read-only here — edit via `spt config render`)");
    Paragraph::new(lines).block(block).render(area, buf);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::buffer::Buffer;
    use ratatui::layout::Rect;
    use spt_config::schema::Forward;

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    fn model_bare() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
"#,
        )
    }

    fn model_with_forward() -> Model {
        let mut m = model_bare();
        m.profile_mut().forwards.push(Forward {
            name: "f1".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            ..Default::default()
        });
        m
    }

    fn model_with_two_forwards() -> Model {
        let mut m = model_with_forward();
        m.profile_mut().forwards.push(Forward {
            name: "f2".into(),
            kind: "local".into(),
            transport: "tcp".into(),
            ..Default::default()
        });
        m
    }

    fn model_with_records() -> Model {
        Model::from_str(
            r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

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
"#,
        )
    }

    fn buffer_to_string(buf: &Buffer, area: Rect) -> String {
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
        }
        s
    }

    #[test]
    fn renders_without_forwards() {
        let mut p = DnsPage::new();
        let m = model_bare();
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
    }

    #[test]
    fn default_region_renders_readonly_records_paragraph() {
        // The page's default state (Forwards region, no editor) must render
        // the read-only paragraph — this is what keeps the default snapshot
        // byte-identical.
        let mut p = DnsPage::new();
        let m = model_with_records();
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let s = buffer_to_string(&buf, area);
        assert!(s.contains("read-only here"));
        assert!(s.contains("service.local"));
    }

    #[test]
    fn focusing_records_region_shows_interactive_editor() {
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        // Down crosses from Forwards into Records.
        p.on_key(k(KeyCode::Down), &mut m);
        assert_eq!(p.region, Region::Records);
        let area = Rect::new(0, 0, 100, 30);
        let mut buf = Buffer::empty(area);
        p.render(area, &mut buf, &m);
        let s = buffer_to_string(&buf, area);
        assert!(s.contains("a=add"));
    }

    #[test]
    fn dns_names_round_trip_first_forward() {
        let mut p = DnsPage::new();
        let mut m = model_with_forward();
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (List)
        for c in "a.example, b.example".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        let names = m.profile().forwards[0]
            .dns_names
            .clone()
            .unwrap_or_default();
        assert_eq!(names, vec!["a.example", "b.example"]);
    }

    #[test]
    fn dns_names_reachable_for_forward_index_above_zero() {
        // PART B: the all-forwards change must let the operator edit a
        // forward at index > 0. Right cycles the forward selector.
        let mut p = DnsPage::new();
        let mut m = model_with_two_forwards();
        assert_eq!(p.forward_sel, 0);
        p.on_key(k(KeyCode::Right), &mut m); // select forward index 1
        assert_eq!(p.forward_sel, 1);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit on forwards[1]
        for c in "second.example".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(
            m.profile().forwards[1]
                .dns_names
                .clone()
                .unwrap_or_default(),
            vec!["second.example"]
        );
        // forwards[0] untouched.
        assert!(m.profile().forwards[0].dns_names.is_none());
    }

    #[test]
    fn forward_selector_is_noop_with_single_forward() {
        // With 0/1 forwards the selector must not move (snapshot parity).
        let mut p = DnsPage::new();
        let mut m = model_with_forward();
        p.on_key(k(KeyCode::Right), &mut m);
        assert_eq!(p.forward_sel, 0);
        p.on_key(k(KeyCode::Left), &mut m);
        assert_eq!(p.forward_sel, 0);
    }

    #[test]
    fn add_record_pushes_and_opens_editor() {
        let mut p = DnsPage::new();
        let mut m = model_bare();
        p.on_key(k(KeyCode::Down), &mut m); // focus Records region
        assert_eq!(DnsPage::n_records(&m), 0);
        p.on_key(k(KeyCode::Char('a')), &mut m);
        assert_eq!(DnsPage::n_records(&m), 1);
        assert!(p.editor.is_some());
        assert_eq!(m.dns().unwrap().records[0].name, "record-1");
        assert_eq!(m.dns().unwrap().records[0].kind, "A");
    }

    #[test]
    fn delete_record_removes_entry() {
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        p.region = Region::Records;
        assert_eq!(DnsPage::n_records(&m), 2);
        p.on_key(k(KeyCode::Char('d')), &mut m);
        assert_eq!(DnsPage::n_records(&m), 1);
    }

    #[test]
    fn record_editor_left_closes() {
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        p.region = Region::Records;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on record 0
        assert!(p.editor.is_some());
        p.on_key(k(KeyCode::Left), &mut m); // close (not field-editing)
        assert!(p.editor.is_none());
    }

    #[test]
    fn record_editor_edits_value() {
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        p.region = Region::Records;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on record 0
                                             // Move to `value` (rows: name, type, value).
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..20 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        for c in "10.0.0.1".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.dns().unwrap().records[0].value, "10.0.0.1");
    }

    #[test]
    fn record_type_choice_commits() {
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        p.region = Region::Records;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on record 0 (type A)
        p.on_key(k(KeyCode::Down), &mut m); // focus `type`
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit (Choice)
        p.on_key(k(KeyCode::Right), &mut m); // A -> AAAA
        p.on_key(k(KeyCode::Enter), &mut m); // commit
        assert_eq!(m.dns().unwrap().records[0].kind, "AAAA");
    }

    #[test]
    fn srv_numeric_invalid_blocks_commit() {
        // A non-numeric value must never reach a numeric row, and an
        // out-of-range u16 must hold the field open without mutating.
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        p.region = Region::Records;
        // Edit record 1 (the SRV record). Move list selection down first.
        p.on_key(k(KeyCode::Down), &mut m);
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on record 1
                                             // priority is row index 4.
        for _ in 0..4 {
            p.on_key(k(KeyCode::Down), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit on priority (= "10")
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..4 {
            p.on_key(k(KeyCode::Backspace), &mut m);
        }
        // Non-digit chars are rejected by the numeric row outright.
        for c in "abc".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        // Type a u16 overflow value.
        for c in "99999".chars() {
            p.on_key(k(KeyCode::Char(c)), &mut m);
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit attempt (must fail)
        let ed = p.editor.as_ref().expect("editor still open");
        assert!(ed.editing, "still editing after failed commit");
        assert!(ed.rows[4].last_error.is_some());
        // Record priority unchanged (still 10).
        assert_eq!(m.dns().unwrap().records[1].priority, Some(10));
    }

    #[test]
    fn srv_numeric_empty_clears_to_none() {
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        p.region = Region::Records;
        p.on_key(k(KeyCode::Down), &mut m); // select SRV record
        p.on_key(k(KeyCode::Enter), &mut m); // open editor
        for _ in 0..4 {
            p.on_key(k(KeyCode::Down), &mut m); // focus priority
        }
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit ("10")
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..4 {
            p.on_key(k(KeyCode::Backspace), &mut m); // clear
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit empty -> None
        assert_eq!(m.dns().unwrap().records[1].priority, None);
    }

    #[test]
    fn empty_state_detection_records_count() {
        let m_empty = model_bare();
        assert_eq!(DnsPage::n_records(&m_empty), 0);
        let m_pop = model_with_records();
        assert_eq!(DnsPage::n_records(&m_pop), 2);
    }

    #[test]
    fn record_name_required_blocks_commit_when_empty() {
        let mut p = DnsPage::new();
        let mut m = model_with_records();
        p.region = Region::Records;
        p.on_key(k(KeyCode::Enter), &mut m); // open editor on record 0
        p.on_key(k(KeyCode::Enter), &mut m); // begin edit on `name`
        p.on_key(k(KeyCode::End), &mut m);
        for _ in 0..40 {
            p.on_key(k(KeyCode::Backspace), &mut m); // clear name
        }
        p.on_key(k(KeyCode::Enter), &mut m); // commit attempt (must fail)
        let ed = p.editor.as_ref().expect("editor still open");
        assert!(ed.editing, "empty required name holds the field open");
        assert!(ed.rows[0].last_error.is_some());
        assert_eq!(m.dns().unwrap().records[0].name, "service.local");
    }
}
