//! `spt completion` — generate shell completions.

use std::io;

use clap::{Args, CommandFactory, Subcommand};
use clap_complete::{generate, Shell};

use crate::Cli;

/// `spt completion` group.
#[derive(Args, Debug)]
pub struct CompletionCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: CompletionSub,
}

impl CompletionCmd {
    /// Generate completions to stdout for the given shell.
    pub fn generate(shell: Shell) {
        let mut cmd = Cli::command();
        let bin_name = cmd.get_name().to_string();
        generate(shell, &mut cmd, bin_name, &mut io::stdout());
    }
}

/// Subcommands of `spt completion`.
#[derive(Subcommand, Debug)]
pub enum CompletionSub {
    /// Print completions for a shell to stdout.
    Generate(CompletionGenerate),
}

/// `spt completion generate <shell>`.
#[derive(Args, Debug)]
pub struct CompletionGenerate {
    /// Target shell.
    #[arg(value_enum)]
    pub shell: Shell,
}
