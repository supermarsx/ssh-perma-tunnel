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

/// The committed shell completions under `packaging/completions/` are generated
/// for the **default (shipped) CLI surface**. The release binary is built with
/// default features (CI's `cargo build --release`), so build-time feature-gated
/// subcommands — currently only `snmp` (compiled in solely under
/// `--features snmp`) — are *intentionally excluded* from the committed
/// artifacts: they are not present in the binary users install, so shipping
/// completions for them would be misleading. Regenerate the artifacts with
/// `scripts/gen_completions.ps1` / `scripts/gen_completions.sh` (both run the
/// default-feature `spt-completions` bin) after any change to the default CLI
/// tree.
///
/// Strict byte-equality runs in the default build — the configuration CI's
/// `cargo test --workspace` exercises and that ships — so a drift in any
/// *shipped* command's completion is caught here. Under `--features snmp` an
/// exact match is impossible by design (the live tree gains the `snmp`
/// subcommand absent from the default-surface artifacts); that build instead
/// asserts the documented exclusion holds (committed = default surface, live
/// tree adds `snmp`), so the test stays meaningful rather than failing on a
/// known, intentional divergence.
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
        let committed = normalize(&committed);
        let generated = normalize(&completion_for(shell));

        if cfg!(feature = "snmp") {
            // Feature-gated build: the committed (default-surface) artifact must
            // NOT carry the `snmp` subcommand, while the live tree (built with
            // the feature) MUST add it. This proves the intentional exclusion
            // holds and catches the mistake of committing snmp-enabled
            // completions as the default artifacts.
            assert!(
                !committed.contains("snmp"),
                "{relative_path} unexpectedly contains the feature-gated `snmp` \
                 subcommand; the committed artifacts must reflect the DEFAULT \
                 (shipped) CLI surface — regenerate without --features snmp"
            );
            assert!(
                generated.contains("snmp"),
                "live CLI tree built with --features snmp should expose the `snmp` \
                 subcommand in {relative_path}; the generator may have regressed"
            );
        } else {
            assert_eq!(
                committed, generated,
                "{relative_path} is stale; run scripts/gen_completions.ps1 or scripts/gen_completions.sh"
            );
        }
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
