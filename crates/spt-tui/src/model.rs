//! Bridge between TUI state and [`spt_config::schema::Profile`].
//!
//! The [`Model`] owns:
//!
//! * the parsed [`spt_config::Config`] (semantic view),
//! * the original raw TOML source as a [`spt_config::mutate::Document`]
//!   (comment-preserving view),
//! * a "dirty" flag plus the selected profile index.
//!
//! Editors mutate `config.profiles[selected]`. On save, the model serializes
//! the edited [`Profile`] into a `toml_edit::Table` and replaces the matching
//! entry in the round-trip document, preserving every other byte of the file.

use std::path::{Path, PathBuf};

use spt_config::mutate::Document;
use spt_config::schema::{Config, Dns, Events, Profile};
use spt_config::{render, validate, ValidationDiagnostics};
use spt_core::{Error, RedactionMode, Result};

/// State of the configurator at any point. Cheap to clone for tests.
#[derive(Debug, Clone)]
pub struct Model {
    config_path: PathBuf,
    /// Round-trip TOML source; updated on save.
    document: Document,
    /// Parsed semantic view; the source of truth for editors.
    config: Config,
    /// Index into [`Config::profiles`] of the currently-edited profile.
    selected: usize,
    /// `true` if any field has been edited since load/save.
    dirty: bool,
    /// `true` if the global `[events]` table specifically was mutated since
    /// load/save. Tracked separately from [`Self::dirty`] so that a
    /// profile-only edit does not cause [`crate::save::save_to`] to
    /// re-serialize (and thereby reorder/canonicalize) an otherwise-untouched
    /// `[events]` block — preserving it byte-for-byte. Set by
    /// [`Self::events_mut`] / [`Self::config_mut`]; cleared on save.
    events_dirty: bool,
    /// `true` if the global `[dns]` table specifically was mutated since
    /// load/save. Tracked separately from [`Self::dirty`] (mirroring
    /// [`Self::events_dirty`]) so that a profile-only edit does not cause
    /// [`crate::save::save_to`] to re-serialize (and thereby
    /// reorder/canonicalize) an otherwise-untouched `[dns]` block —
    /// preserving it byte-for-byte. Set by [`Self::dns_mut`] /
    /// [`Self::config_mut`]; cleared on save.
    dns_dirty: bool,
    /// Last successful save target (for restore-on-error reporting).
    last_saved: Option<PathBuf>,
}

impl Model {
    /// Load a config file from disk into a [`Model`]. The file is parsed both
    /// semantically (via [`spt_config::load()`]) and structurally (via
    /// [`Document::read`]).
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| Error::InvalidConfig(format!("read `{}`: {e}", path.display())))?;
        let document = Document::parse(&raw)?;
        let (config, _warnings) = spt_config::load_str(&raw, false)?;
        Ok(Self {
            config_path: path.to_path_buf(),
            document,
            config,
            selected: 0,
            dirty: false,
            events_dirty: false,
            dns_dirty: false,
            last_saved: None,
        })
    }

    /// Construct a [`Model`] in-memory (no file backing). Used by tests.
    #[must_use]
    pub fn from_str(raw: &str) -> Self {
        let document = Document::parse(raw).expect("test input must parse");
        let (config, _w) = spt_config::load_str(raw, false).expect("test input must load");
        Self {
            config_path: PathBuf::from("<memory>"),
            document,
            config,
            selected: 0,
            dirty: false,
            events_dirty: false,
            dns_dirty: false,
            last_saved: None,
        }
    }

    /// Borrow the current [`Config`].
    #[must_use]
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// All profiles in the loaded config.
    #[must_use]
    pub fn profiles(&self) -> &[Profile] {
        &self.config.profiles
    }

    /// Index of the profile currently being edited.
    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected
    }

    /// Borrow the currently-selected profile.
    ///
    /// # Panics
    ///
    /// Panics if there are no profiles. Call [`Model::create_profile`] first
    /// when starting from an empty config.
    #[must_use]
    pub fn profile(&self) -> &Profile {
        &self.config.profiles[self.selected]
    }

    /// Mutably borrow the selected profile and mark the model dirty.
    ///
    /// Use this for unconditional mutations (e.g. `push`/`remove` on a
    /// `Vec`, direct field assignment from outside the edit-buffer
    /// flow). For the `Page::on_key` → `FieldList::on_edit_key` path
    /// where the mutation is conditional on the user's keystroke,
    /// prefer [`Self::profile_mut_silent`] so cursor moves and other
    /// no-op keys don't flip the dirty bit on every press.
    pub fn profile_mut(&mut self) -> &mut Profile {
        self.dirty = true;
        &mut self.config.profiles[self.selected]
    }

    /// Mutably borrow the selected profile **without** marking the
    /// model dirty. The caller is responsible for calling
    /// [`Self::mark_dirty`] (typically based on a `bool changed`
    /// return value) if and only if the keystroke actually mutated
    /// the profile.
    ///
    /// Background: the TUI's edit-mode dispatch routes every key
    /// (Up/Down/Left/Right, Esc, …) through `on_edit_key`, but only
    /// commit-style keys (Enter/Space/typing) actually mutate the
    /// profile. Auto-dirtying on every borrow turned navigation into
    /// "unsaved changes" — see the rotate-cursor cycle test in
    /// `tests/pages_keyboard.rs`.
    pub fn profile_mut_silent(&mut self) -> &mut Profile {
        &mut self.config.profiles[self.selected]
    }

    /// Mark the model as having unsaved changes. Pages should call
    /// this after a `on_edit_key` (or other handler) returns `true`,
    /// indicating an actual profile mutation took place.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// Mutably borrow the whole [`Config`] and mark the model dirty.
    ///
    /// The global counterpart of [`Self::profile_mut`]: use it for
    /// unconditional mutations of top-level (non-profile) tables such as
    /// `[events]`. Mirrors the same dirty contract — every borrow flips
    /// the dirty bit. For the conditional `on_edit_key` path prefer
    /// [`Self::config_mut_silent`] + [`Self::mark_dirty`].
    pub fn config_mut(&mut self) -> &mut Config {
        self.dirty = true;
        // A whole-config mutable borrow may touch `[events]` or `[dns]`, so
        // flag both for re-serialization on save. Editors that only touch a
        // profile should use `profile_mut` instead, keeping `[events]`/`[dns]`
        // byte-preserved.
        self.events_dirty = true;
        self.dns_dirty = true;
        &mut self.config
    }

    /// Mutably borrow the whole [`Config`] **without** marking the model
    /// dirty. The global counterpart of [`Self::profile_mut_silent`]: the
    /// caller must call [`Self::mark_dirty`] iff the keystroke actually
    /// mutated the config (so navigation keys routed through `on_edit_key`
    /// don't flip the dirty bit on every press).
    pub fn config_mut_silent(&mut self) -> &mut Config {
        &mut self.config
    }

    /// Immutably borrow the global `[events]` table, if present.
    #[must_use]
    pub fn events(&self) -> Option<&Events> {
        self.config.events.as_ref()
    }

    /// Mutably borrow the global `[events]` table, lazily initializing it
    /// to [`Events::default`] if the config has none yet, and mark the
    /// model dirty.
    ///
    /// Like [`Self::config_mut`] (and unlike the `*_silent` accessors),
    /// every borrow flips the dirty bit — use it for unconditional
    /// mutations (add/remove a sink or binding). The lazy `Some(..)` init
    /// is what lets `[events]` go from absent to present on first edit;
    /// [`crate::save::save_to`] only splices `[events]` when it is both
    /// dirty and present, so an untouched config keeps `[events]` absent.
    pub fn events_mut(&mut self) -> &mut Events {
        self.dirty = true;
        self.events_dirty = true;
        self.config.events.get_or_insert_with(Events::default)
    }

    /// `true` if the `[events]` table was specifically mutated since the last
    /// load/save (via [`Self::events_mut`] / [`Self::config_mut`]).
    ///
    /// [`crate::save::save_to`] uses this — not the global [`Self::is_dirty`]
    /// flag — to decide whether to re-splice `[events]`, so a profile-only
    /// edit leaves the source `[events]` block byte-for-byte.
    #[must_use]
    pub fn is_events_dirty(&self) -> bool {
        self.events_dirty
    }

    /// Immutably borrow the global `[dns]` table, if present.
    #[must_use]
    pub fn dns(&self) -> Option<&Dns> {
        self.config.dns.as_ref()
    }

    /// Mutably borrow the global `[dns]` table, lazily initializing it to
    /// [`Dns::default`] if the config has none yet, and mark the model dirty.
    ///
    /// Like [`Self::events_mut`] (and unlike the `*_silent` accessors), every
    /// borrow flips the dirty bit — use it for unconditional mutations
    /// (add/remove/edit a `[[dns.records]]` entry). The lazy `Some(..)` init
    /// is what lets `[dns]` go from absent to present on first edit;
    /// [`crate::save::save_to`] only splices `[dns]` when it is both dirty and
    /// present, so an untouched config keeps `[dns]` absent.
    pub fn dns_mut(&mut self) -> &mut Dns {
        self.dirty = true;
        self.dns_dirty = true;
        self.config.dns.get_or_insert_with(Dns::default)
    }

    /// `true` if the `[dns]` table was specifically mutated since the last
    /// load/save (via [`Self::dns_mut`] / [`Self::config_mut`]).
    ///
    /// [`crate::save::save_to`] uses this — not the global [`Self::is_dirty`]
    /// flag — to decide whether to re-splice `[dns]`, so a profile-only edit
    /// leaves the source `[dns]` block byte-for-byte.
    #[must_use]
    pub fn is_dns_dirty(&self) -> bool {
        self.dns_dirty
    }

    /// Select a profile by index. No-op if out of range.
    pub fn select_profile_index(&mut self, idx: usize) {
        if idx < self.config.profiles.len() {
            self.selected = idx;
        }
    }

    /// Select a profile by name. Returns `Some(idx)` on hit, `None` on miss.
    pub fn select_profile_by_name(&mut self, name: &str) -> Option<usize> {
        let idx = self.config.profiles.iter().position(|p| p.name == name)?;
        self.selected = idx;
        Some(idx)
    }

    /// Create a fresh profile with the given id and protocol and select it.
    pub fn create_profile(&mut self, name: &str, protocol: &str) {
        let p = Profile {
            name: name.to_owned(),
            protocol: protocol.to_owned(),
            ..Default::default()
        };
        self.config.profiles.push(p);
        self.selected = self.config.profiles.len() - 1;
        self.dirty = true;
    }

    /// `true` if any edit has occurred since the last save.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Run the schema validator and return its diagnostics.
    #[must_use]
    pub fn validate(&self) -> ValidationDiagnostics {
        validate(&self.config)
    }

    /// Render the *current* (in-memory) config as canonical, redacted TOML.
    /// Used by the review page to show what would be written.
    #[must_use]
    pub fn render_redacted(&self) -> String {
        render(&self.config, RedactionMode::Standard)
    }

    /// Render the *original* document (round-trip surface). Used by the
    /// review page's diff view.
    #[must_use]
    pub fn original_toml(&self) -> String {
        self.document.to_string()
    }

    /// Path the model was loaded from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.config_path
    }

    /// Path of the most recently-successful save (often `path()`).
    #[must_use]
    pub fn last_saved(&self) -> Option<&Path> {
        self.last_saved.as_deref()
    }

    /// Replace the round-trip document and clear the dirty flag. Called by
    /// [`crate::save`] after a successful atomic write.
    pub fn mark_saved(&mut self, document: Document, target: PathBuf) {
        self.document = document;
        self.last_saved = Some(target);
        self.dirty = false;
        self.events_dirty = false;
        self.dns_dirty = false;
    }

    /// Mutably borrow the round-trip document so [`crate::save`] can splice
    /// the edited profile into it.
    pub fn document_mut(&mut self) -> &mut Document {
        &mut self.document
    }
}

#[cfg(test)]
mod tests {
    use super::Model;

    const RAW: &str = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"
host = "h.example.com"
"#;

    #[test]
    fn load_str_picks_first_profile() {
        let m = Model::from_str(RAW);
        assert_eq!(m.profiles().len(), 1);
        assert_eq!(m.profile().name, "p");
        assert!(!m.is_dirty());
    }

    #[test]
    fn editing_marks_dirty() {
        let mut m = Model::from_str(RAW);
        m.profile_mut().user = Some("alice".into());
        assert!(m.is_dirty());
        assert_eq!(m.profile().user.as_deref(), Some("alice"));
    }

    #[test]
    fn create_profile_appends_and_selects() {
        let mut m = Model::from_str(RAW);
        m.create_profile("q", "ssh3");
        assert_eq!(m.profiles().len(), 2);
        assert_eq!(m.profile().name, "q");
        assert!(m.is_dirty());
    }

    #[test]
    fn validate_returns_diagnostics() {
        let m = Model::from_str(RAW);
        let diag = m.validate();
        assert!(diag.is_ok(), "expected clean config, got {:?}", diag);
    }

    #[test]
    fn select_profile_by_name_misses() {
        let mut m = Model::from_str(RAW);
        assert!(m.select_profile_by_name("not-there").is_none());
        assert_eq!(m.selected_index(), 0);
    }

    #[test]
    fn select_profile_by_name_hits() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[[profiles]]
name = "q"
protocol = "ssh3"
endpoint = "https://q.example.com"
"#;
        let mut m = Model::from_str(raw);
        assert_eq!(m.select_profile_by_name("q"), Some(1));
        assert_eq!(m.profile().name, "q");
    }

    #[test]
    fn select_profile_index_out_of_range_is_noop() {
        let mut m = Model::from_str(RAW);
        m.select_profile_index(99);
        assert_eq!(m.selected_index(), 0);
    }

    #[test]
    fn original_toml_matches_input() {
        let m = Model::from_str(RAW);
        assert_eq!(m.original_toml().trim(), RAW.trim());
    }

    #[test]
    fn render_redacted_returns_canonical_toml() {
        let m = Model::from_str(RAW);
        let out = m.render_redacted();
        assert!(out.contains("name = \"p\""));
        assert!(out.contains("protocol = \"ssh2\""));
    }

    #[test]
    fn path_reports_memory_for_inline_models() {
        let m = Model::from_str(RAW);
        assert_eq!(m.path().to_string_lossy(), "<memory>");
        assert!(m.last_saved().is_none());
    }

    #[test]
    fn load_reports_io_error_for_missing_path() {
        let p = std::path::Path::new("F:/Projects/ssh-perma-tunnel/__not_real__.toml");
        let err = Model::load(p).unwrap_err();
        // Just confirm an Err comes back; surface variant is InvalidConfig.
        let s = format!("{err}");
        assert!(s.contains("__not_real__") || !s.is_empty());
    }

    #[test]
    fn load_round_trips_through_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.toml");
        std::fs::write(&path, RAW).unwrap();
        let m = Model::load(&path).unwrap();
        assert_eq!(m.profile().name, "p");
        assert_eq!(m.path(), path);
    }

    #[test]
    fn config_accessor_exposes_full_config() {
        let m = Model::from_str(RAW);
        let cfg = m.config();
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.version, 1);
    }

    #[test]
    fn create_profile_marks_dirty_and_picks_default() {
        let mut m = Model::from_str(RAW);
        assert!(!m.is_dirty());
        m.create_profile("brand-new", "ssh2");
        assert!(m.is_dirty());
        assert_eq!(m.profile().name, "brand-new");
        assert_eq!(m.profile().protocol, "ssh2");
    }

    #[test]
    fn profile_mut_marks_dirty_even_without_visible_change() {
        let mut m = Model::from_str(RAW);
        let _p = m.profile_mut();
        assert!(m.is_dirty());
    }

    #[test]
    fn config_mut_marks_dirty() {
        let mut m = Model::from_str(RAW);
        assert!(!m.is_dirty());
        let _c = m.config_mut();
        assert!(m.is_dirty());
    }

    #[test]
    fn config_mut_silent_does_not_mark_dirty() {
        let mut m = Model::from_str(RAW);
        let _c = m.config_mut_silent();
        assert!(!m.is_dirty());
    }

    #[test]
    fn events_accessor_is_none_when_absent() {
        let m = Model::from_str(RAW);
        assert!(m.events().is_none());
    }

    #[test]
    fn events_mut_lazily_inits_and_marks_dirty() {
        let mut m = Model::from_str(RAW);
        assert!(m.events().is_none());
        assert!(!m.is_dirty());
        // First borrow materializes `Some(Events::default())`.
        m.events_mut().sinks.push(spt_config::schema::EventSink {
            name: "s".into(),
            kind: "http".into(),
            ..Default::default()
        });
        assert!(m.is_dirty());
        let ev = m.events().expect("events present after events_mut");
        assert_eq!(ev.sinks.len(), 1);
        assert_eq!(ev.sinks[0].name, "s");
    }

    #[test]
    fn events_mut_reuses_existing_table() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[[events.bindings]]
name = "b"
on = ["profile.failed"]
actions = ["notify"]
"#;
        let mut m = Model::from_str(raw);
        assert_eq!(m.events().unwrap().bindings.len(), 1);
        // Mutating must not wipe the pre-existing binding.
        m.events_mut().bindings[0].min_level = Some("warn".into());
        let ev = m.events().unwrap();
        assert_eq!(ev.bindings.len(), 1);
        assert_eq!(ev.bindings[0].min_level.as_deref(), Some("warn"));
    }

    #[test]
    fn dns_accessor_is_none_when_absent() {
        let m = Model::from_str(RAW);
        assert!(m.dns().is_none());
        assert!(!m.is_dns_dirty());
    }

    #[test]
    fn dns_mut_lazily_inits_and_marks_dirty() {
        let mut m = Model::from_str(RAW);
        assert!(m.dns().is_none());
        assert!(!m.is_dirty());
        assert!(!m.is_dns_dirty());
        // First borrow materializes `Some(Dns::default())`.
        m.dns_mut().records.push(spt_config::schema::DnsRecord {
            name: "a.example.com".into(),
            kind: "A".into(),
            value: "10.0.0.1".into(),
            ..Default::default()
        });
        assert!(m.is_dirty());
        assert!(m.is_dns_dirty());
        let dns = m.dns().expect("dns present after dns_mut");
        assert_eq!(dns.records.len(), 1);
        assert_eq!(dns.records[0].name, "a.example.com");
    }

    #[test]
    fn dns_mut_reuses_existing_table() {
        let raw = r#"version = 1
[[profiles]]
name = "p"
protocol = "ssh2"

[dns]
mode = "transparent_forwarder"

[[dns.records]]
name = "a.example.com"
type = "A"
value = "10.0.0.1"
"#;
        let mut m = Model::from_str(raw);
        assert_eq!(m.dns().unwrap().records.len(), 1);
        // Mutating must not wipe the pre-existing record or scalar.
        m.dns_mut().records[0].ttl = Some("300".into());
        let dns = m.dns().unwrap();
        assert_eq!(dns.records.len(), 1);
        assert_eq!(dns.mode.as_deref(), Some("transparent_forwarder"));
        assert_eq!(dns.records[0].ttl.as_deref(), Some("300"));
    }

    #[test]
    fn config_mut_marks_dns_dirty() {
        let mut m = Model::from_str(RAW);
        assert!(!m.is_dns_dirty());
        let _c = m.config_mut();
        assert!(m.is_dns_dirty());
    }
}
