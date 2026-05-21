//! Snapshot tests of `--help` for the root command and every group.
//!
//! Run `cargo insta accept` to refresh fixtures after intentional changes.

use clap::CommandFactory;
use spt_cli::Cli;

fn render_help(args: &[&str]) -> String {
    let mut cmd = Cli::command();
    let mut full = vec!["spt"];
    full.extend_from_slice(args);
    let err = cmd.try_get_matches_from_mut(&full).unwrap_err();
    err.render().to_string()
}

macro_rules! help_snapshot {
    ($name:ident, $args:expr) => {
        #[test]
        fn $name() {
            let mut args = Vec::from($args);
            args.push("--help");
            let out = render_help(&args);
            insta::assert_snapshot!(stringify!($name), out);
        }
    };
}

help_snapshot!(help_root, [] as [&str; 0]);
help_snapshot!(help_config, ["config"]);
help_snapshot!(help_profile, ["profile"]);
help_snapshot!(help_forward, ["forward"]);
help_snapshot!(help_tunnel, ["tunnel"]);
help_snapshot!(help_service, ["service"]);
help_snapshot!(help_key, ["key"]);
help_snapshot!(help_secret, ["secret"]);
help_snapshot!(help_auth, ["auth"]);
help_snapshot!(help_dns, ["dns"]);
help_snapshot!(help_firewall, ["firewall"]);
help_snapshot!(help_log, ["log"]);
help_snapshot!(help_observe, ["observe"]);
help_snapshot!(help_event, ["event"]);
help_snapshot!(help_stats, ["stats"]);
help_snapshot!(help_session, ["session"]);
help_snapshot!(help_sftp, ["sftp"]);
help_snapshot!(help_diagnose, ["diagnose"]);
help_snapshot!(help_benchmark, ["benchmark"]);
help_snapshot!(help_mcp, ["mcp"]);
help_snapshot!(help_status, ["status"]);
help_snapshot!(help_completion, ["completion"]);
