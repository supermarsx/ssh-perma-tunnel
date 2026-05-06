//! Terminal UI profile configurator for `spt`.
//!
//! This crate implements `spt profile configure --tui` (spec §7.3): a
//! ratatui + crossterm wizard that edits a single [`spt_config::Profile`] at
//! a time and writes the result back through `spt-config`'s comment-preserving
//! mutation paths.
//!
//! # Architecture
//!
//! * [`app`] — top-level state machine and key/event loop.
//! * [`pages`] — one module per wizard page (basics, connection, auth, …).
//! * [`widgets`] — reusable form widgets (text input, select, multi-select).
//! * [`model`] — bridge between TUI state and a [`spt_config::Profile`];
//!   converts simulated key events into profile edits and produces a diff
//!   for review.
//! * [`save`] — calls into [`spt_config::mutate`] to write the canonical TOML
//!   atomically while preserving comments.
//!
//! # Public entry point
//!
//! [`run`] opens the configurator on a config file. It wires up the terminal,
//! enters the alternate screen, runs the event loop, and restores the
//! terminal on exit.
#![forbid(unsafe_code)]
// Pedantic lints we deliberately allow in this TUI crate. Forms code is
// inherently boilerplate-heavy; the categories below would force noise
// that obscures intent.
#![allow(
    clippy::needless_pass_by_value,
    clippy::trivially_copy_pass_by_ref,
    clippy::unused_self,
    clippy::type_complexity,
    clippy::missing_const_for_fn,
    clippy::manual_let_else,
    clippy::doc_markdown,
    clippy::uninlined_format_args,
    clippy::assigning_clones,
    clippy::unnested_or_patterns,
    clippy::match_same_arms,
    clippy::should_implement_trait,
    clippy::missing_fields_in_debug,
    clippy::ignored_unit_patterns,
    clippy::redundant_closure_for_method_calls
)]

pub mod app;
pub mod model;
pub mod pages;
pub mod save;
pub mod widgets;

use std::io;
use std::path::Path;

pub use app::{App, AppEvent, PageId};
pub use model::Model;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use spt_core::{Error, Result};

/// Run the TUI profile configurator on `config_path`. If `profile_id` is
/// `None`, the user is shown a profile picker (or prompted to create one).
///
/// On success the chosen profile has been saved back to disk. The function
/// always restores the terminal before returning, even on error.
pub fn run(config_path: &Path, profile_id: Option<&str>) -> Result<()> {
    let mut model = Model::load(config_path)?;
    if let Some(id) = profile_id {
        model.select_profile_by_name(id).ok_or_else(|| {
            Error::InvalidArgs(format!("profile `{id}` not found in `{}`", config_path.display()))
        })?;
    } else if model.profiles().is_empty() {
        // Seed an empty profile so the wizard has something to edit.
        model.create_profile("new-profile", "ssh2");
    } else {
        model.select_profile_index(0);
    }

    enable_raw_mode().map_err(io_err)?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).map_err(io_err)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(io_err)?;

    let mut app = App::new(model);
    let res = app.run(&mut terminal);

    // Always restore.
    disable_raw_mode().map_err(io_err)?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(io_err)?;
    terminal.show_cursor().map_err(io_err)?;
    res
}

fn io_err(e: io::Error) -> Error {
    Error::RuntimeFailure(format!("tui io: {e}"))
}
