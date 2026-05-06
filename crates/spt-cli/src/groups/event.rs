//! `spt event` — event bindings and sinks.

use clap::{Args, Subcommand};

const EXAMPLES: &str = "EXAMPLES:
  spt event list --json
  spt event test ops-pager
  spt event replay --since 1h --binding ops-pager
  spt event sink test smtp-primary --json
  spt event sink list";

/// `spt event` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct EventCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: EventSub,
}

/// Subcommands of `spt event`.
#[derive(Subcommand, Debug)]
pub enum EventSub {
    /// List configured event bindings.
    List(EventList),
    /// Trigger a binding by name.
    Test(EventTest),
    /// Replay historical events through a binding.
    Replay(EventReplay),
    /// Manage event sinks.
    Sink(EventSinkCmd),
}

/// `spt event list`.
#[derive(Args, Debug)]
pub struct EventList {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt event test`.
#[derive(Args, Debug)]
pub struct EventTest {
    /// Binding name.
    #[arg(value_name = "BINDING-NAME")]
    pub binding: String,
}

/// `spt event replay`.
#[derive(Args, Debug)]
pub struct EventReplay {
    /// Lookback window.
    #[arg(long, value_name = "DURATION")]
    pub since: String,
    /// Binding name.
    #[arg(long, value_name = "NAME")]
    pub binding: String,
}

/// `spt event sink`.
#[derive(Args, Debug)]
pub struct EventSinkCmd {
    /// Sink subcommand.
    #[command(subcommand)]
    pub command: EventSinkSub,
}

/// Subcommands of `spt event sink`.
#[derive(Subcommand, Debug)]
pub enum EventSinkSub {
    /// Test a sink.
    Test(EventSinkTest),
    /// List configured sinks.
    List(EventList),
}

/// `spt event sink test`.
#[derive(Args, Debug)]
pub struct EventSinkTest {
    /// Sink name.
    #[arg(value_name = "SINK-NAME")]
    pub sink: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}
