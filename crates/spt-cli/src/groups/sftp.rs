//! `spt sftp` — one-shot SFTP file operations and mount planning.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt sftp test --profile edge
  spt sftp list --profile edge /var/log --json
  spt sftp get --profile edge /etc/app/config.toml --out ./config.toml
  spt sftp put --profile edge ./build.tar.gz /tmp/build.tar.gz
  spt sftp mount add --profile edge --name data --remote /srv/data --mount-point /mnt/spt-data
  spt sftp drive add --profile edge --name data --remote /srv/data --letter S:";

/// `spt sftp` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct SftpCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: SftpSub,
}

/// Subcommands of `spt sftp`.
#[derive(Subcommand, Debug)]
pub enum SftpSub {
    /// Connect to the profile and open the SFTP subsystem.
    Test(SftpProfileArgs),
    /// List a remote directory.
    List(SftpPathArgs),
    /// Show metadata for a remote path.
    Stat(SftpPathArgs),
    /// Download a remote file.
    Get(SftpGetArgs),
    /// Upload a local file.
    Put(SftpPutArgs),
    /// Create a remote directory.
    Mkdir(SftpPathArgs),
    /// Remove a remote file.
    Rm(SftpPathArgs),
    /// Remove a remote directory.
    Rmdir(SftpPathArgs),
    /// Rename a remote file or directory.
    Rename(SftpRenameArgs),
    /// Manage SFTP-backed filesystem mount entries.
    Mount(SftpMountCmd),
    /// Manage SFTP-backed Windows drive entries.
    Drive(SftpDriveCmd),
}

/// Common profile selector.
#[derive(Args, Debug)]
pub struct SftpProfileArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// Remote path against a profile.
#[derive(Args, Debug)]
pub struct SftpPathArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Remote path.
    pub path: String,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt sftp get`.
#[derive(Args, Debug)]
pub struct SftpGetArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Remote file path.
    pub remote: String,
    /// Local output path.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
}

/// `spt sftp put`.
#[derive(Args, Debug)]
pub struct SftpPutArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Local input path.
    pub local: PathBuf,
    /// Remote file path.
    pub remote: String,
}

/// `spt sftp rename`.
#[derive(Args, Debug)]
pub struct SftpRenameArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Existing remote path.
    pub old_path: String,
    /// New remote path.
    pub new_path: String,
}

/// SFTP mount cache mode.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SftpCacheMode {
    /// No local caching.
    None,
    /// Cache metadata only.
    Metadata,
    /// Writeback cache. Requires an explicit capability gate.
    Writeback,
}

impl SftpCacheMode {
    /// Stable config spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Metadata => "metadata",
            Self::Writeback => "writeback",
        }
    }
}

/// `spt sftp mount`.
#[derive(Args, Debug)]
pub struct SftpMountCmd {
    /// Mount subcommand.
    #[command(subcommand)]
    pub command: SftpMountSub,
}

/// Subcommands of `spt sftp mount`.
#[derive(Subcommand, Debug)]
pub enum SftpMountSub {
    /// List configured filesystem mounts.
    List(SftpMountListArgs),
    /// Add a filesystem mount entry to the config.
    Add(SftpMountAddArgs),
    /// Remove a filesystem mount entry from the config.
    Remove(SftpMountRefArgs),
    /// Render the platform plan for a configured or proposed mount.
    Plan(SftpMountPlanArgs),
}

/// `spt sftp drive`.
#[derive(Args, Debug)]
pub struct SftpDriveCmd {
    /// Drive subcommand.
    #[command(subcommand)]
    pub command: SftpDriveSub,
}

/// Subcommands of `spt sftp drive`.
#[derive(Subcommand, Debug)]
pub enum SftpDriveSub {
    /// List configured Windows drive mounts.
    List(SftpMountListArgs),
    /// Add a Windows drive mount entry to the config.
    Add(SftpDriveAddArgs),
    /// Remove a Windows drive mount entry from the config.
    Remove(SftpMountRefArgs),
    /// Render the platform plan for a configured or proposed drive mount.
    Plan(SftpDrivePlanArgs),
}

/// `spt sftp mount list`.
#[derive(Args, Debug)]
pub struct SftpMountListArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt sftp mount add`.
#[derive(Args, Debug)]
pub struct SftpMountAddArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Mount name.
    #[arg(long)]
    pub name: String,
    /// Remote SFTP path.
    #[arg(long, value_name = "PATH")]
    pub remote: String,
    /// Local mount point.
    #[arg(long, value_name = "PATH")]
    pub mount_point: String,
    /// Mount read-only.
    #[arg(long)]
    pub read_only: bool,
    /// Cache mode.
    #[arg(long, value_enum, value_name = "MODE")]
    pub cache: Option<SftpCacheMode>,
}

/// `spt sftp drive add`.
#[derive(Args, Debug)]
pub struct SftpDriveAddArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Mount name.
    #[arg(long)]
    pub name: String,
    /// Remote SFTP path.
    #[arg(long, value_name = "PATH")]
    pub remote: String,
    /// Windows drive letter, for example `S` or `S:`.
    #[arg(long, value_name = "LETTER")]
    pub letter: String,
    /// Mount read-only.
    #[arg(long)]
    pub read_only: bool,
    /// Cache mode.
    #[arg(long, value_enum, value_name = "MODE")]
    pub cache: Option<SftpCacheMode>,
}

/// `<profile>/<mount>` shorthand.
#[derive(Args, Debug)]
pub struct SftpMountRefArgs {
    /// `<profile>/<mount>`.
    #[arg(value_name = "PROFILE/MOUNT")]
    pub reference: String,
}

/// `spt sftp mount plan`.
#[derive(Args, Debug)]
pub struct SftpMountPlanArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Existing mount name. If omitted, `--remote` and `--mount-point` are used.
    #[arg(long)]
    pub name: Option<String>,
    /// Proposed remote path.
    #[arg(long, value_name = "PATH")]
    pub remote: Option<String>,
    /// Proposed mount point.
    #[arg(long, value_name = "PATH")]
    pub mount_point: Option<String>,
    /// Proposed cache mode.
    #[arg(long, value_enum, value_name = "MODE")]
    pub cache: Option<SftpCacheMode>,
    /// Proposed read-only mode.
    #[arg(long)]
    pub read_only: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt sftp drive plan`.
#[derive(Args, Debug)]
pub struct SftpDrivePlanArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Existing mount name. If omitted, `--remote` and `--letter` are used.
    #[arg(long)]
    pub name: Option<String>,
    /// Proposed remote path.
    #[arg(long, value_name = "PATH")]
    pub remote: Option<String>,
    /// Proposed Windows drive letter.
    #[arg(long, value_name = "LETTER")]
    pub letter: Option<String>,
    /// Proposed cache mode.
    #[arg(long, value_enum, value_name = "MODE")]
    pub cache: Option<SftpCacheMode>,
    /// Proposed read-only mode.
    #[arg(long)]
    pub read_only: bool,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}
