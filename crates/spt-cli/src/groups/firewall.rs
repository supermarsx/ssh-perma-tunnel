//! `spt firewall` — packet-filter rule planning and application.

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt firewall plan --profile edge --json
  spt firewall apply --system --dry-run
  spt firewall remove --user
  spt firewall bind-preview --forward edge/db
  spt firewall gateway show --json
  spt firewall gateway set --default-interface Ethernet --tcp-nodelay true
  spt firewall gateway set --load-balance-strategy weighted --load-balance-fail-after 3
  spt firewall policy list --json
  spt firewall policy set Network.DefaultInterface Ethernet --scope user";

/// `spt firewall` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct FirewallCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: FirewallSub,
}

/// Subcommands of `spt firewall`.
#[derive(Subcommand, Debug)]
pub enum FirewallSub {
    /// Plan rules without applying.
    Plan(FirewallPlan),
    /// Apply rules (idempotent).
    Apply(FirewallApply),
    /// Remove rules.
    Remove(FirewallApply),
    /// Show current applied state.
    Status(FirewallStatus),
    /// List interfaces / bind targets.
    Interfaces(FirewallStatus),
    /// Preview the bind for a forward.
    BindPreview(FirewallBindPreview),
    /// Manage gateway/interface defaults in config.
    Gateway(FirewallGateway),
    /// Inspect and manage GPO-style policy values.
    Policy(FirewallPolicy),
}

/// `spt firewall plan`.
#[derive(Args, Debug)]
pub struct FirewallPlan {
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall apply` / `remove`.
#[derive(Args, Debug)]
pub struct FirewallApply {
    /// Filter by profile.
    #[arg(long)]
    pub profile: Option<String>,
    /// Filter by forward.
    #[arg(long)]
    pub forward: Option<String>,
    /// User-scoped scope.
    #[arg(long, group = "fw_scope")]
    pub user: bool,
    /// System-scoped scope.
    #[arg(long, group = "fw_scope")]
    pub system: bool,
    /// Print actions without changing system state.
    #[arg(long)]
    pub dry_run: bool,
}

/// `spt firewall status` / `interfaces`.
#[derive(Args, Debug)]
pub struct FirewallStatus {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall bind-preview`.
#[derive(Args, Debug)]
pub struct FirewallBindPreview {
    /// `<profile>/<forward>`.
    #[arg(long, value_name = "PROFILE/FORWARD")]
    pub forward: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall gateway`.
#[derive(Args, Debug)]
pub struct FirewallGateway {
    /// Gateway subcommand.
    #[command(subcommand)]
    pub command: FirewallGatewaySub,
}

/// Subcommands of `spt firewall gateway`.
#[derive(Subcommand, Debug)]
pub enum FirewallGatewaySub {
    /// Show configured interface/gateway policy.
    Show(FirewallGatewayShow),
    /// Update configured interface/gateway policy.
    Set(FirewallGatewaySet),
}

/// `spt firewall gateway show`.
#[derive(Args, Debug)]
pub struct FirewallGatewayShow {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall gateway set`.
#[derive(Args, Debug)]
pub struct FirewallGatewaySet {
    /// Set `[network.interface].default_interface`.
    #[arg(long, value_name = "IFACE")]
    pub default_interface: Option<String>,
    /// Set `[network.interface].allowed_interfaces`.
    #[arg(long, value_name = "IFACE", value_delimiter = ',')]
    pub allowed_interface: Vec<String>,
    /// Set `[network.interface].denied_interfaces`.
    #[arg(long, value_name = "IFACE", value_delimiter = ',')]
    pub denied_interface: Vec<String>,
    /// Set `[network.interface].require_explicit_interface`.
    #[arg(long, value_name = "BOOL")]
    pub require_explicit_interface: Option<bool>,
    /// Set `[network.interface].allow_all_interfaces`.
    #[arg(long, value_name = "BOOL")]
    pub allow_all_interfaces: Option<bool>,
    /// Set `[network.interface].bind_ipv6` (`auto|prefer|disable`).
    #[arg(long, value_name = "MODE")]
    pub bind_ipv6: Option<String>,
    /// Set `[network.gateway].default_gateway`.
    #[arg(long, value_name = "ADDR")]
    pub default_gateway: Option<String>,
    /// Set `[network.gateway].interface`.
    #[arg(long, value_name = "IFACE")]
    pub gateway_interface: Option<String>,
    /// Set `[network.gateway].route_check_target`.
    #[arg(long, value_name = "HOST_OR_IP")]
    pub route_check_target: Option<String>,
    /// Set `[network.gateway].policy`.
    #[arg(long, value_name = "POLICY")]
    pub policy: Option<String>,
    /// Set `[network.gateway].require_gateway_match`.
    #[arg(long, value_name = "BOOL")]
    pub require_gateway_match: Option<bool>,
    /// Set `[network.offload].tcp_nodelay`.
    #[arg(long, value_name = "BOOL")]
    pub tcp_nodelay: Option<bool>,
    /// Set `[network.offload].socket_keepalive`.
    #[arg(long, value_name = "BOOL")]
    pub socket_keepalive: Option<bool>,
    /// Set `[network.offload].tcp_fast_open`.
    #[arg(long, value_name = "BOOL")]
    pub tcp_fast_open: Option<bool>,
    /// Set `[network.offload].reuse_port`.
    #[arg(long, value_name = "BOOL")]
    pub reuse_port: Option<bool>,
    /// Set `[network.offload].io_uring`.
    #[arg(long, value_name = "BOOL")]
    pub io_uring: Option<bool>,
    /// Set `[network.offload].zerocopy`.
    #[arg(long, value_name = "BOOL")]
    pub zerocopy: Option<bool>,
    /// Set `[network.offload].sendfile`.
    #[arg(long, value_name = "BOOL")]
    pub sendfile: Option<bool>,
    /// Set `[network.offload].checksum_offload`.
    #[arg(long, value_name = "BOOL")]
    pub checksum_offload: Option<bool>,
    /// Set `[network.offload].large_send_offload`.
    #[arg(long, value_name = "BOOL")]
    pub large_send_offload: Option<bool>,
    /// Set `[network.load_balance].strategy`.
    #[arg(long, value_name = "STRATEGY")]
    pub load_balance_strategy: Option<String>,
    /// Set `[network.load_balance].sticky_sessions`.
    #[arg(long, value_name = "BOOL")]
    pub sticky_sessions: Option<bool>,
    /// Set `[network.load_balance].health_check`.
    #[arg(long, value_name = "MODE")]
    pub health_check: Option<String>,
    /// Set `[network.load_balance].fail_after`.
    #[arg(long, value_name = "N")]
    pub load_balance_fail_after: Option<u32>,
    /// Set `[network.load_balance].restore_after`.
    #[arg(long, value_name = "DURATION")]
    pub load_balance_restore_after: Option<String>,
    /// Set `[network.load_balance].rebalance_interval`.
    #[arg(long, value_name = "DURATION")]
    pub rebalance_interval: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall policy`.
#[derive(Args, Debug)]
pub struct FirewallPolicy {
    /// Policy subcommand.
    #[command(subcommand)]
    pub command: FirewallPolicySub,
}

/// Subcommands of `spt firewall policy`.
#[derive(Subcommand, Debug)]
pub enum FirewallPolicySub {
    /// List known policy bindings.
    List(FirewallPolicyList),
    /// Show live registry policy overlay and effective network/firewall fields.
    Show(FirewallPolicyShow),
    /// Set a policy value in HKCU/HKLM.
    Set(FirewallPolicySet),
    /// Remove a policy value from HKCU/HKLM.
    Unset(FirewallPolicyUnset),
}

/// Registry policy scope.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum FirewallPolicyScope {
    /// HKLM machine policy.
    Machine,
    /// HKCU user policy.
    User,
}

/// `spt firewall policy list`.
#[derive(Args, Debug)]
pub struct FirewallPolicyList {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall policy show`.
#[derive(Args, Debug)]
pub struct FirewallPolicyShow {
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall policy set`.
#[derive(Args, Debug)]
pub struct FirewallPolicySet {
    /// Policy key in `Section.Name` or `Section\Name` form.
    #[arg(value_name = "SECTION.NAME")]
    pub key: String,
    /// Policy value. Lists use comma-separated values.
    #[arg(value_name = "VALUE")]
    pub value: String,
    /// Target registry hive.
    #[arg(long, value_enum, default_value_t = FirewallPolicyScope::User)]
    pub scope: FirewallPolicyScope,
    /// Mark the containing machine-policy section enforced.
    #[arg(long)]
    pub enforced: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt firewall policy unset`.
#[derive(Args, Debug)]
pub struct FirewallPolicyUnset {
    /// Policy key in `Section.Name` or `Section\Name` form.
    #[arg(value_name = "SECTION.NAME")]
    pub key: String,
    /// Target registry hive.
    #[arg(long, value_enum, default_value_t = FirewallPolicyScope::User)]
    pub scope: FirewallPolicyScope,
    /// Also clear the section-level `Enforced` sentinel.
    #[arg(long)]
    pub clear_enforced: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}
