//! Minimal tracing initialiser used by every `spt` invocation.
//!
//! Long-running commands (`tunnel run`, `service run`, `mcp serve`) replace
//! this with the full `spt-observability` pipeline once they own the parsed
//! config. This bootstrap subscriber only writes to stderr.

use spt_cli::GlobalOpts;
use spt_observability::{
    config::{Destination, LogFormat, LoggingConfig},
    init_for_test, TracingGuard,
};

/// Initialise a stderr-only tracing subscriber. Returns the guard owned by
/// `main` for lifetime control.
pub fn init_minimal(global: &GlobalOpts) -> Option<TracingGuard> {
    let level = crate::log_level_directive(global.log_level, global.verbose);
    let cfg = LoggingConfig {
        level,
        format: if global.json {
            LogFormat::Json
        } else {
            LogFormat::Compact
        },
        no_color: global.no_color || matches!(global.color, spt_cli::ColorMode::Never),
        destinations: vec![Destination::Stderr],
        file: None,
        redact: spt_core::RedactionMode::Standard,
        remote: Vec::new(),
    };
    // Use init_for_test which uses try_init under the hood, so re-entry from
    // tests doesn't panic. Real init failures are warned about and ignored —
    // a logging failure must not block the CLI.
    init_for_test(&cfg)
        .map_err(|e| {
            eprintln!("spt: tracing init warning: {e}");
            e
        })
        .ok()
}
