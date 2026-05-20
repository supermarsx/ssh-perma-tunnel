//! `spt completion generate bash` produces a non-empty bash completion
//! script. This test calls the generator directly so it doesn't depend on a
//! built binary on the path.

use std::fs;
use std::path::{Path, PathBuf};

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

#[test]
fn committed_completion_artifacts_match_live_cli_tree() {
    let root = workspace_root();
    let cases = [
        (Shell::Bash, "packaging/completions/bash/spt"),
        (Shell::Zsh, "packaging/completions/zsh/_spt"),
        (Shell::Fish, "packaging/completions/fish/spt.fish"),
        (
            Shell::PowerShell,
            "packaging/completions/powershell/spt.ps1",
        ),
        (
            Shell::PowerShell,
            "packaging/completions/powershell/spt.psm1",
        ),
        (Shell::Elvish, "packaging/completions/elvish/spt.elv"),
    ];

    for (shell, relative_path) in cases {
        let path = root.join(relative_path);
        let committed = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read committed completion `{}`: {e}", path.display()));
        let generated = completion_for(shell);
        assert_eq!(
            normalize(&committed),
            normalize(&generated),
            "{relative_path} is stale; run scripts/gen_completions.ps1 or scripts/gen_completions.sh"
        );
    }
}

fn completion_for(shell: Shell) -> String {
    let mut cmd = Cli::command();
    let mut out = Vec::new();
    let bin_name = cmd.get_name().to_string();
    generate(shell, &mut cmd, bin_name, &mut out);
    String::from_utf8(out).unwrap()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("spt-bin lives under crates/spt-bin")
        .to_path_buf()
}

fn normalize(s: &str) -> String {
    s.replace("\r\n", "\n")
}
