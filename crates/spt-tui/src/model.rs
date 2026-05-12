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
use spt_config::schema::{Config, Profile};
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
    pub fn profile_mut(&mut self) -> &mut Profile {
        self.dirty = true;
        &mut self.config.profiles[self.selected]
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
}
