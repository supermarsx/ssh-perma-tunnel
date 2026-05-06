//! `spt completion generate bash` produces a non-empty bash completion
//! script. This test calls the generator directly so it doesn't depend on a
//! built binary on the path.

use clap::CommandFactory;
use clap_complete::{generate, Shell};
use spt_cli::Cli;

#[test]
fn bash_completion_is_nonempty() {
    let mut cmd = Cli::command();
    let mut out = Vec::new();
    let bin_name = cmd.get_name().to_string();
    generate(Shell::Bash, &mut cmd, bin_name, &mut out);
    let s = String::from_utf8(out).unwrap();
    assert!(!s.is_empty());
    assert!(s.contains("_spt"));
}

#[test]
fn fish_completion_is_nonempty() {
    let mut cmd = Cli::command();
    let mut out = Vec::new();
    let bin_name = cmd.get_name().to_string();
    generate(Shell::Fish, &mut cmd, bin_name, &mut out);
    let s = String::from_utf8(out).unwrap();
    assert!(!s.is_empty());
}
