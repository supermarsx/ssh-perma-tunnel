//! `spt dns` — built-in resolver and hosts-file management.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt dns serve --foreground
  spt dns record add svc.local --addr 10.0.0.1 --ttl 5m
  spt dns hosts render --out /etc/hosts.spt
  spt dns hosts apply --backup
  spt dns hosts restore --backup /var/lib/spt/hosts/backup-2024-01-01";

/// `spt dns` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct DnsCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: DnsSub,
}

/// Subcommands of `spt dns`.
#[derive(Subcommand, Debug)]
pub enum DnsSub {
    /// Run the resolver.
    Serve(DnsServe),
    /// Resolver status.
    Status(DnsStatus),
    /// Issue a query against the configured resolver.
    Query(DnsQuery),
    /// Manage upstream resolvers.
    Upstream(DnsUpstream),
    /// Manage managed records.
    Record(DnsRecord),
    /// Manage hosts-file rendering / apply / restore.
    Hosts(DnsHosts),
}

/// `spt dns serve`.
#[derive(Args, Debug)]
pub struct DnsServe {
    /// Run in the foreground.
    #[arg(long)]
    pub foreground: bool,
    /// Override config path.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
}

/// `spt dns status`.
#[derive(Args, Debug)]
pub struct DnsStatus {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// DNS record types selectable by `spt dns query --type`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum RecordType {
    A,
    Aaaa,
    Srv,
    Txt,
}

/// `spt dns query <name>`.
#[derive(Args, Debug)]
pub struct DnsQuery {
    /// Name to resolve.
    pub name: String,
    /// Record type.
    #[arg(long, value_enum, value_name = "TYPE")]
    pub r#type: Option<RecordType>,
}

/// `spt dns upstream`.
#[derive(Args, Debug)]
pub struct DnsUpstream {
    /// Upstream subcommand.
    #[command(subcommand)]
    pub command: DnsUpstreamSub,
}

/// Subcommands of `spt dns upstream`.
#[derive(Subcommand, Debug)]
pub enum DnsUpstreamSub {
    /// Replace the upstream list.
    Set(DnsUpstreamSet),
}

/// `spt dns upstream set`.
#[derive(Args, Debug)]
pub struct DnsUpstreamSet {
    /// Upstream `addr:port` entries.
    #[arg(value_name = "ADDR:PORT", required = true)]
    pub upstreams: Vec<String>,
}

/// `spt dns record`.
#[derive(Args, Debug)]
pub struct DnsRecord {
    /// Record subcommand.
    #[command(subcommand)]
    pub command: DnsRecordSub,
}

/// Subcommands of `spt dns record`.
#[derive(Subcommand, Debug)]
pub enum DnsRecordSub {
    /// Add a managed record.
    Add(DnsRecordAdd),
    /// Remove a managed record.
    Remove(DnsRecordRemove),
}

/// `spt dns record add`.
#[derive(Args, Debug)]
pub struct DnsRecordAdd {
    /// Record name.
    pub name: String,
    /// IP address.
    #[arg(long, value_name = "ADDR")]
    pub addr: String,
    /// TTL (e.g. `5m`).
    #[arg(long, value_name = "DURATION")]
    pub ttl: Option<String>,
}

/// `spt dns record remove`.
#[derive(Args, Debug)]
pub struct DnsRecordRemove {
    /// Record name.
    pub name: String,
}

/// `spt dns hosts`.
#[derive(Args, Debug)]
pub struct DnsHosts {
    /// Hosts-file subcommand.
    #[command(subcommand)]
    pub command: DnsHostsSub,
}

/// Subcommands of `spt dns hosts`.
#[derive(Subcommand, Debug)]
pub enum DnsHostsSub {
    /// Render the would-be hosts file.
    Render(DnsHostsRender),
    /// Apply the rendered hosts file.
    Apply(DnsHostsApply),
    /// Restore a previous hosts backup.
    Restore(DnsHostsRestore),
}

/// `spt dns hosts render`.
#[derive(Args, Debug)]
pub struct DnsHostsRender {
    /// Output path (otherwise stdout).
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// `spt dns hosts apply`.
#[derive(Args, Debug)]
pub struct DnsHostsApply {
    /// Hosts file to write.
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Take a timestamped backup first.
    #[arg(long)]
    pub backup: bool,
}

/// `spt dns hosts restore`.
#[derive(Args, Debug)]
pub struct DnsHostsRestore {
    /// Specific backup to restore.
    #[arg(long, value_name = "PATH")]
    pub backup: Option<PathBuf>,
}
