//! Wizard pages.
//!
//! Each module under `pages/` exposes a [`Page`] that can render itself and
//! handle key events given a mutable reference to the [`Model`]. To minimize
//! code duplication, fields shared across many pages are described as
//! [`FieldDef`] entries and rendered by the generic [`FieldList`] runner.

mod auth;
mod basics;
mod connection;
mod crypto;
mod diagnostics;
mod dns;
mod endpoints;
mod events;
mod failover;
mod field;
mod forwards;
mod keepalive;
mod limits;
mod review;
mod trust;

pub use field::{Field, FieldDef, FieldList, FieldValue};

use crossterm::event::KeyEvent;
use ratatui::buffer::Buffer;
use ratatui::layout::Rect;

use crate::model::Model;

/// Stable identifier for each wizard page. Used for navigation and for
/// keying snapshot tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageKind {
    /// `1. Profile basics` — id, description, protocol.
    Basics,
    /// `2. Connection` — endpoints, hops, timings.
    Connection,
    /// `3. Endpoints` — multi-target failover list. §9.11.
    Endpoints,
    /// `4. Auth` — auth method + secret refs.
    Auth,
    /// `5. Trust` — known_hosts, SHA-256 pins, TLS pins.
    Trust,
    /// `6. Crypto` — cipher / kex / mac / hostkey allow-lists.
    Crypto,
    /// `7. Keepalive`.
    Keepalive,
    /// `8. Reconnect / instability / failover`.
    Failover,
    /// `9. Limits` — connection caps, throttles.
    Limits,
    /// `10. Forwards` — local / remote / udp forward entries.
    Forwards,
    /// `11. DNS` — managed records bound to this profile.
    Dns,
    /// `12. Events` — per-profile binding tags.
    Events,
    /// `13. Diagnostics / observability` — tags + metrics labels.
    Diagnostics,
    /// `14. Review & save`.
    Review,
}

impl PageKind {
    /// Total number of pages in the wizard.
    pub const COUNT: usize = 14;

    /// Ordered list, in the order shown in the navigation tabs.
    #[must_use]
    pub fn all() -> [PageKind; Self::COUNT] {
        [
            PageKind::Basics,
            PageKind::Connection,
            PageKind::Endpoints,
            PageKind::Auth,
            PageKind::Trust,
            PageKind::Crypto,
            PageKind::Keepalive,
            PageKind::Failover,
            PageKind::Limits,
            PageKind::Forwards,
            PageKind::Dns,
            PageKind::Events,
            PageKind::Diagnostics,
            PageKind::Review,
        ]
    }

    /// Human-readable label for the page tab.
    #[must_use]
    pub fn title(self) -> &'static str {
        match self {
            PageKind::Basics => "Basics",
            PageKind::Connection => "Connection",
            PageKind::Endpoints => "Endpoints",
            PageKind::Auth => "Auth",
            PageKind::Trust => "Trust",
            PageKind::Crypto => "Crypto",
            PageKind::Keepalive => "Keepalive",
            PageKind::Failover => "Reconnect/Failover",
            PageKind::Limits => "Limits",
            PageKind::Forwards => "Forwards",
            PageKind::Dns => "DNS",
            PageKind::Events => "Events",
            PageKind::Diagnostics => "Diagnostics",
            PageKind::Review => "Review & Save",
        }
    }

    /// Index in the [`PageKind::all`] order.
    #[must_use]
    pub fn index(self) -> usize {
        Self::all().iter().position(|p| *p == self).unwrap_or(0)
    }
}

/// Trait implemented by every wizard page.
pub trait Page {
    /// Render the page into the provided rect.
    fn render(&mut self, area: Rect, buf: &mut Buffer, model: &Model);
    /// Handle a key event. Returns `true` if the model was changed.
    fn on_key(&mut self, key: KeyEvent, model: &mut Model) -> bool;

    /// One-line operator-facing description of the currently-focused
    /// field/control on the page. The App renders this in the footer so
    /// operators always see what the highlighted row does.
    ///
    /// Default: `None` — pages that don't have a field-style focus model
    /// (e.g. the read-only Review page) opt out by leaving this default.
    fn focused_help(&self) -> Option<&str> {
        None
    }

    /// Like [`Page::focused_help`] but **option-aware**: when the
    /// focused field is a Bool/Choice/Multi with a per-option help
    /// table, the App surfaces the help string for the currently
    /// selected option (in edit mode) or the profile's stored value
    /// (in nav mode) rather than the field's static one-line help.
    ///
    /// Default impl delegates to [`Page::focused_help`] so pages
    /// without dynamic help — Endpoints, Connection, DNS, Events,
    /// Review — keep behaving exactly as before.
    fn focused_help_dynamic(&self, _model: &Model) -> Option<&str> {
        self.focused_help()
    }

    /// `(current_index_1based, total)` for the focused row within the
    /// page. Surfaced by the App as `[3/12]` so the operator knows where
    /// they are. `None` for pages with no item list.
    fn focused_position(&self) -> Option<(usize, usize)> {
        None
    }

    /// Whether the focused row is currently in edit mode. Drives the
    /// status-line key-hint text (different keys are useful when
    /// navigating vs. editing).
    fn is_editing(&self) -> bool {
        false
    }
}

/// Construct one [`Page`] per [`PageKind`], with state ready for the first
/// render. Pages own only their UI state; the [`Model`] is the source of truth
/// for the underlying [`spt_config::Profile`].
#[must_use]
pub fn build_pages() -> Vec<Box<dyn Page>> {
    vec![
        Box::new(basics::BasicsPage::new()),
        Box::new(connection::ConnectionPage::new()),
        Box::new(endpoints::EndpointsPage::new()),
        Box::new(auth::AuthPage::new()),
        Box::new(trust::TrustPage::new()),
        Box::new(crypto::CryptoPage::new()),
        Box::new(keepalive::KeepalivePage::new()),
        Box::new(failover::FailoverPage::new()),
        Box::new(limits::LimitsPage::new()),
        Box::new(forwards::ForwardsPage::new()),
        Box::new(dns::DnsPage::new()),
        Box::new(events::EventsPage::new()),
        Box::new(diagnostics::DiagnosticsPage::new()),
        Box::new(review::ReviewPage::new()),
    ]
}
