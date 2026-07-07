//! `spt completion` — generate shell completions.

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
        // Generate into an in-memory buffer first, then emit through the
        // `print!` macro rather than writing to `io::stdout()` directly.
        //
        // Why not stream straight to `io::stdout()`: the full completion script
        // is tens of KB, and a *direct* `io::stdout()` write bypasses libtest's
        // per-test output capture (capture only intercepts the `print!`/`write!`
        // macro family, not raw handle writes). Under `cargo test` the test
        // binary's stdout is an inherited pipe, and on Windows that pipe can be
        // in overlapped/async mode (e.g. an MSYS/Cygwin pipe, as used by CI's
        // bash steps). A large raw write to such a handle whose reader has
        // stalled makes std's `synchronous_write` observe `STATUS_PENDING` and
        // `rtabort!` the whole process ("operation failed to complete
        // synchronously", exit 0xC0000409) — see rust-lang/rust#81357. Routing
        // through `print!` keeps the script inside the in-memory capture during
        // tests so it never reaches that pipe, while production output is
        // byte-identical (the completion script is valid UTF-8).
        let mut buf = Vec::new();
        generate(shell, &mut cmd, bin_name, &mut buf);
        print!("{}", String::from_utf8_lossy(&buf));
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
