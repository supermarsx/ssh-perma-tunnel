//! One module per top-level command group from spec §7.

pub mod about;
pub mod auth;
pub mod benchmark;
pub mod completion;
pub mod config;
pub mod diagnose;
pub mod dns;
pub mod event;
pub mod firewall;
// t6-e6:start — FTP→SFTP translator group. Bwire wires the matching
// `Command::Ftp` variant into `crate::Command` at registration time.
pub mod ftp;
// t6-e6:end
pub mod forward;
pub mod key;
pub mod kill;
pub mod log;
pub mod mcp;
pub mod observe;
pub mod profile;
pub mod secret;
pub mod service;
pub mod session;
pub mod sftp;
pub mod stats;
pub mod status;
pub mod tunnel;
pub mod update;

#[cfg(test)]
mod examples_roundtrip {
    //! E4-F7: every invocation advertised in a group's `--help` EXAMPLES
    //! block must actually parse through the real clap tree. Hand-written
    //! examples drift from the flag declarations (a positional shown as a
    //! `--flag`, a rejected enum value, a renamed option); this test parses
    //! each EXAMPLES line through `Cli::try_parse_from` so a broken example
    //! fails CI instead of greeting an operator at the copy-paste prompt.

    use crate::Cli;
    use clap::Parser;

    /// Split one example command line into argv tokens, honoring
    /// double-quoted segments (e.g. `--reason "primary degraded"`).
    fn tokenize(line: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        let mut cur = String::new();
        let mut in_quotes = false;
        let mut has_token = false;
        for ch in line.chars() {
            match ch {
                '"' => {
                    in_quotes = !in_quotes;
                    has_token = true;
                }
                c if c.is_whitespace() && !in_quotes => {
                    if has_token {
                        tokens.push(std::mem::take(&mut cur));
                        has_token = false;
                    }
                }
                c => {
                    cur.push(c);
                    has_token = true;
                }
            }
        }
        assert!(!in_quotes, "unbalanced quotes in example: {line}");
        if has_token {
            tokens.push(cur);
        }
        tokens
    }

    /// Iterate the example lines of an EXAMPLES block, dropping the
    /// `EXAMPLES:` header and any blank lines.
    fn example_lines(block: &str) -> impl Iterator<Item = &str> {
        block
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && *l != "EXAMPLES:")
    }

    /// Round-trip a single EXAMPLES block through the real `Cli` parser.
    /// Returns the number of example lines verified.
    fn assert_block_parses(group: &str, block: &str) -> usize {
        let mut count = 0;
        for line in example_lines(block) {
            let argv = tokenize(line);
            assert_eq!(
                argv.first().map(String::as_str),
                Some("spt"),
                "{group} example does not start with `spt`: {line}"
            );
            Cli::try_parse_from(&argv).unwrap_or_else(|e| {
                panic!("{group} EXAMPLES line failed to parse:\n  {line}\n{e}")
            });
            count += 1;
        }
        count
    }

    #[test]
    fn every_examples_line_parses() {
        // Every group whose EXAMPLES block is owned by t-fill-p3-cli-groups.
        // Adding a group here makes its advertised invocations CI-checked.
        let blocks: &[(&str, &str)] = &[
            ("log", super::log::EXAMPLES),
            ("session", super::session::EXAMPLES),
            ("tunnel", super::tunnel::EXAMPLES),
            ("dns", super::dns::EXAMPLES),
            ("profile", super::profile::EXAMPLES),
        ];

        let mut total = 0;
        for (group, block) in blocks {
            total += assert_block_parses(group, block);
        }

        // Guard against a future edit silently emptying an EXAMPLES block
        // (which would make this test vacuously pass).
        assert_eq!(
            total, 27,
            "expected 27 round-tripped EXAMPLES lines across the 5 groups, got {total}"
        );
    }

    #[test]
    fn tokenize_handles_quoted_segments() {
        let argv = tokenize("spt session close abc --reason \"drain now\"");
        assert_eq!(
            argv,
            vec!["spt", "session", "close", "abc", "--reason", "drain now"]
        );
    }
}
