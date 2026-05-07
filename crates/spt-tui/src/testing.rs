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
}
