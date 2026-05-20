//! Test facilities for `spt-tui`.
//!
//! [`AppHarness`] wraps the [`App`] state machine against a
//! [`ratatui::backend::TestBackend`], exposing key-injection plus buffer
//! snapshot helpers. [`fixtures::test_profile`] builds a minimal profile
//! good enough to drive the wizard.
//!
//! ```
//! use spt_tui::testing::{AppHarness, fixtures};
//! let mut h = AppHarness::with_profile(fixtures::test_profile());
//! let _buf = h.render();
//! assert_eq!(h.current_page(), "Basics");
//! ```

use crossterm::event::KeyEvent;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;
use spt_config::schema::Profile;

use crate::app::App;
use crate::model::Model;

/// Default terminal dimensions used by [`AppHarness::with_profile`].
pub const DEFAULT_WIDTH: u16 = 100;
/// Default terminal height.
pub const DEFAULT_HEIGHT: u16 = 30;

/// Test harness around [`App`] driven against a [`TestBackend`].
pub struct AppHarness {
    /// Underlying app under test.
    pub app: App,
    /// Test backend the harness renders into.
    pub terminal: Terminal<TestBackend>,
}

impl AppHarness {
    /// Build a harness with a single profile loaded into a fresh [`Model`].
    ///
    /// ```
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let h = AppHarness::with_profile(fixtures::test_profile());
    /// assert_eq!(h.current_page(), "Basics");
    /// ```
    #[must_use]
    pub fn with_profile(profile: Profile) -> Self {
        Self::with_profile_sized(profile, DEFAULT_WIDTH, DEFAULT_HEIGHT)
    }

    /// Build a harness with custom terminal dimensions.
    #[must_use]
    pub fn with_profile_sized(profile: Profile, width: u16, height: u16) -> Self {
        let toml = serialize_profile(&profile);
        let model = Model::from_str(&toml);
        let app = App::new(model);
        let backend = TestBackend::new(width, height);
        let terminal = Terminal::new(backend).expect("TestBackend always builds a terminal");
        Self { app, terminal }
    }

    /// Feed a sequence of key events into the app.
    ///
    /// ```
    /// use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let mut h = AppHarness::with_profile(fixtures::test_profile());
    /// h.type_keys(&[KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)]);
    /// assert_eq!(h.current_page(), "Connection");
    /// ```
    pub fn type_keys(&mut self, keys: &[KeyEvent]) {
        for k in keys {
            self.app.on_key(*k);
        }
    }

    /// Run one render pass and return a clone of the resulting buffer.
    ///
    /// ```
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let mut h = AppHarness::with_profile(fixtures::test_profile());
    /// let buf = h.render();
    /// assert!(buf.area.width > 0);
    /// ```
    pub fn render(&mut self) -> Buffer {
        let app = &mut self.app;
        self.terminal
            .draw(|f| app.render_frame(f.area(), f.buffer_mut()))
            .expect("draw");
        self.terminal.backend().buffer().clone()
    }

    /// Flatten the most recent terminal buffer to plain text.
    ///
    /// ```
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let mut h = AppHarness::with_profile(fixtures::test_profile());
    /// let _ = h.render();
    /// assert!(h.buffer_text().contains("Basics"));
    /// ```
    #[must_use]
    pub fn buffer_text(&self) -> String {
        let buf = self.terminal.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Identifier (title) of the currently-displayed page.
    ///
    /// ```
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let h = AppHarness::with_profile(fixtures::test_profile());
    /// assert_eq!(h.current_page(), "Basics");
    /// ```
    #[must_use]
    pub fn current_page(&self) -> &'static str {
        self.app.current.title()
    }

    /// Assert that the most recently rendered buffer contains `needle`
    /// somewhere in its flattened text. Panics with a helpful message if not.
    ///
    /// ```
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let mut h = AppHarness::with_profile(fixtures::test_profile());
    /// let _ = h.render();
    /// h.assert_buffer_contains("Basics");
    /// ```
    pub fn assert_buffer_contains(&self, needle: &str) {
        let txt = self.buffer_text();
        assert!(
            txt.contains(needle),
            "buffer does not contain `{needle}`. \nbuffer:\n{txt}"
        );
    }

    /// Capture the current buffer as a multi-line snapshot string suitable
    /// for use with `insta::assert_snapshot!`. The output is a deterministic,
    /// trimmed plain-text rendering of the most recent render pass.
    ///
    /// ```
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let mut h = AppHarness::with_profile(fixtures::test_profile());
    /// let _ = h.render();
    /// let snap = h.snapshot("basics");
    /// assert!(!snap.is_empty());
    /// ```
    pub fn snapshot(&mut self, _name: &str) -> String {
        let _ = self.render();
        let txt = self.buffer_text();
        // Trim trailing spaces on each line for stable snapshots.
        txt.lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Apply an arbitrary mutation to the underlying [`Model`]. Convenience
    /// hook for tests that need to seed state without driving the keyboard.
    ///
    /// ```
    /// use spt_tui::testing::{AppHarness, fixtures};
    /// let mut h = AppHarness::with_profile(fixtures::test_profile());
    /// h.mutate_model(|m| { m.profile_mut().user = Some("bob".into()); });
    /// assert!(h.app.model.is_dirty());
    /// ```
    pub fn mutate_model<F: FnOnce(&mut crate::model::Model)>(&mut self, f: F) {
        f(&mut self.app.model);
    }
}

/// Pre-baked profile fixtures.
pub mod fixtures {
    use spt_config::schema::Profile;

    /// Build a minimal valid profile pointing at `test.example.com:22` over
    /// `ssh2`. Sufficient for wizard navigation and rendering tests.
    ///
    /// ```
    /// let p = spt_tui::testing::fixtures::test_profile();
    /// assert_eq!(p.protocol, "ssh2");
    /// ```
    #[must_use]
    pub fn test_profile() -> Profile {
        Profile {
            name: "test".to_owned(),
            protocol: "ssh2".to_owned(),
            host: Some("test.example.com".to_owned()),
            port: Some(22),
            user: Some("alice".to_owned()),
            ..Default::default()
        }
    }
}

/// Serialize a single profile into a self-contained TOML config string.
fn serialize_profile(p: &Profile) -> String {
    let mut s = String::from("version = 1\n\n[[profiles]]\n");
    s.push_str(&format!("name = \"{}\"\n", p.name));
    s.push_str(&format!("protocol = \"{}\"\n", p.protocol));
    if let Some(h) = &p.host {
        s.push_str(&format!("host = \"{h}\"\n"));
    }
    if let Some(port) = p.port {
        s.push_str(&format!("port = {port}\n"));
    }
    if let Some(u) = &p.user {
        s.push_str(&format!("user = \"{u}\"\n"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    #[test]
    fn harness_renders_and_navigates() {
        let mut h = AppHarness::with_profile(fixtures::test_profile());
        let _ = h.render();
        assert_eq!(h.current_page(), "Basics");
        h.type_keys(&[KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE)]);
        let _ = h.render();
        assert_eq!(h.current_page(), "Connection");
    }

    #[test]
    fn buffer_text_contains_page_title() {
        let mut h = AppHarness::with_profile(fixtures::test_profile());
        let _ = h.render();
        assert!(h.buffer_text().contains("Basics"));
    }

    #[test]
    fn snapshot_is_deterministic() {
        let mut h1 = AppHarness::with_profile(fixtures::test_profile());
        let mut h2 = AppHarness::with_profile(fixtures::test_profile());
        let b1 = h1.render();
        let b2 = h2.render();
        assert_eq!(b1, b2);
    }

    #[test]
    fn assert_buffer_contains_finds_title() {
        let mut h = AppHarness::with_profile(fixtures::test_profile());
        let _ = h.render();
        h.assert_buffer_contains("Basics");
        h.assert_buffer_contains("Connection");
    }

    #[test]
    #[should_panic(expected = "does not contain")]
    fn assert_buffer_contains_panics_when_missing() {
        let mut h = AppHarness::with_profile(fixtures::test_profile());
        let _ = h.render();
        h.assert_buffer_contains("ThisStringIsNotRendered_zzzzzz");
    }

    #[test]
    fn snapshot_returns_trimmed_text() {
        let mut h = AppHarness::with_profile(fixtures::test_profile());
        let snap = h.snapshot("basics");
        assert!(snap.contains("Basics"));
        // No trailing spaces per line.
        for line in snap.lines() {
            assert_eq!(line, line.trim_end());
        }
    }

    #[test]
    fn mutate_model_changes_state() {
        let mut h = AppHarness::with_profile(fixtures::test_profile());
        assert!(!h.app.model.is_dirty());
        h.mutate_model(|m| {
            m.profile_mut().user = Some("bob".into());
        });
        assert!(h.app.model.is_dirty());
        assert_eq!(h.app.model.profile().user.as_deref(), Some("bob"));
    }

    #[test]
    fn fixtures_test_profile_is_complete_enough_for_wizard() {
        let p = fixtures::test_profile();
        assert_eq!(p.name, "test");
        assert_eq!(p.protocol, "ssh2");
        assert_eq!(p.host.as_deref(), Some("test.example.com"));
        assert_eq!(p.port, Some(22));
        assert_eq!(p.user.as_deref(), Some("alice"));
    }

    #[test]
    fn harness_with_custom_size() {
        let mut h = AppHarness::with_profile_sized(fixtures::test_profile(), 80, 24);
        let buf = h.render();
        assert_eq!(buf.area.width, 80);
        assert_eq!(buf.area.height, 24);
    }

    #[test]
    fn serialize_profile_round_trips_minimal_fields() {
        let p = fixtures::test_profile();
        let toml = serialize_profile(&p);
        assert!(toml.contains("name = \"test\""));
        assert!(toml.contains("protocol = \"ssh2\""));
        assert!(toml.contains("host = \"test.example.com\""));
        assert!(toml.contains("port = 22"));
        assert!(toml.contains("user = \"alice\""));
    }
}
