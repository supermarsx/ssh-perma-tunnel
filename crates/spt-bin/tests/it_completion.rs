//! `spt completion generate bash` produces a non-empty bash completion
//! script. This test calls the generator directly so it doesn't depend on a
//! built binary on the path.

use clap::CommandFactory;
use clap_complete::{generate, Shell};
use spt_cli::Cli;

#[test]
fn supported_shell_completions_are_nonempty() {
    for shell in [
        Shell::Bash,
        Shell::Zsh,
        Shell::Fish,
        Shell::PowerShell,
        Shell::Elvish,
    ] {
        let script = completion_for(shell);
        assert!(
            !script.is_empty(),
            "{shell:?} completion should not be empty"
        );
        assert!(
            script.to_lowercase().contains("spt"),
            "{shell:?} completion should mention spt"
        );
    }
}

#[test]
fn bash_completion_uses_spt_function_name() {
    let s = completion_for(Shell::Bash);
    assert!(s.contains("_spt"));
}

fn completion_for(shell: Shell) -> String {
    let mut cmd = Cli::command();
    let mut out = Vec::new();
    let bin_name = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin_name, &mut out);
    String::from_utf8(out).unwrap()
}
