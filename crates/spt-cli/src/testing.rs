//! Test facilities for `spt-cli`.
//!
//! Gated behind the `testing` feature (and always available under `cfg(test)`).
//! Helpers wrap [`Cli::try_parse_from`] so downstream crates can assert on the
//! parsed command tree without re-implementing clap glue.
//!
//! ```
//! use spt_cli::testing::parse_argv;
//! let cli = parse_argv(["spt", "config", "validate"]).expect("parses");
//! assert!(matches!(cli.command, spt_cli::Command::Config(_)));
//! ```

use std::ffi::OsString;

use clap::{CommandFactory, Parser};
use spt_core::{Error, Result};

use crate::{Cli, Command};

/// Parse a `Cli` from any iterable of OsString-convertible arguments.
///
/// Wraps [`clap::Error`] in [`spt_core::Error::InvalidArgs`] so callers can use
/// the standard `Result` type. Use this for tests that want to inspect the
/// parsed command tree.
///
/// ```
/// use spt_cli::testing::parse_argv;
/// let cli = parse_argv(["spt", "tunnel", "status"]).unwrap();
/// assert!(matches!(cli.command, spt_cli::Command::Tunnel(_)));
/// ```
pub fn parse_argv<I, T>(argv: I) -> Result<Cli>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    Cli::try_parse_from(argv).map_err(|e| Error::InvalidArgs(e.to_string()))
}

/// Parse a `Cli` and panic on error with the clap-rendered diagnostic.
///
/// ```
/// use spt_cli::testing::parse_or_panic;
/// let cli = parse_or_panic(&["spt", "config", "validate"]);
/// assert!(matches!(cli.command, spt_cli::Command::Config(_)));
/// ```
#[must_use]
pub fn parse_or_panic(argv: &[&str]) -> Cli {
    match Cli::try_parse_from(argv) {
        Ok(c) => c,
        Err(e) => panic!("clap rejected argv {argv:?}:\n{e}"),
    }
}

/// Render the help text for the root command (when `group` is `None`) or for
/// a named top-level subcommand group such as `"config"` or `"tunnel"`.
///
/// Returns the rendered help string, suitable for `insta::assert_snapshot!`.
/// Panics if the requested group does not exist — that is a test-author bug.
///
/// ```
/// use spt_cli::testing::help_snapshot;
/// let root = help_snapshot(None);
/// assert!(root.contains("spt"));
/// let cfg = help_snapshot(Some("config"));
/// assert!(cfg.contains("validate"));
/// ```
#[must_use]
pub fn help_snapshot(group: Option<&str>) -> String {
    let mut cmd = Cli::command();
    cmd.build();
    let target = match group {
        None => &mut cmd,
        Some(name) => cmd
            .find_subcommand_mut(name)
            .unwrap_or_else(|| panic!("unknown command group `{name}`")),
    };
    target.render_help().to_string()
}

/// Parse `argv` and assert that the resulting [`Command`] matches `predicate`.
///
/// The predicate receives a borrowed [`Command`] so callers can pattern-match
/// on the variant they expect. Panics on parse error or predicate failure.
///
/// ```
/// use spt_cli::testing::assert_parses;
/// use spt_cli::Command;
/// assert_parses(&["spt", "profile", "list"], |c| matches!(c, Command::Profile(_)));
/// ```
pub fn assert_parses(argv: &[&str], predicate: fn(&Command) -> bool) {
    let cli = parse_or_panic(argv);
    assert!(
        predicate(&cli.command),
        "parsed command {:?} did not match the predicate (argv={argv:?})",
        cli.command
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_argv_returns_command() {
        let cli = parse_argv(["spt", "config", "validate"]).unwrap();
        assert!(matches!(cli.command, Command::Config(_)));
    }

    #[test]
    fn parse_argv_wraps_clap_error() {
        let err = parse_argv(["spt", "no-such-group"]).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)));
    }

    #[test]
    fn help_snapshot_root_non_empty() {
        let s = help_snapshot(None);
        assert!(s.contains("spt"));
        assert!(!s.is_empty());
    }

    #[test]
    fn help_snapshot_for_group() {
        let s = help_snapshot(Some("config"));
        assert!(s.contains("validate"));
    }

    #[test]
    fn assert_parses_matches() {
        assert_parses(&["spt", "tunnel", "status"], |c| {
            matches!(c, Command::Tunnel(_))
        });
    }
}
