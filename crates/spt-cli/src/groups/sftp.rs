//! `spt sftp` — one-shot SFTP file operations and mount planning.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt sftp test --profile edge
  spt sftp list --profile edge /var/log --json
  spt sftp get --profile edge /etc/app/config.toml --out ./config.toml
  spt sftp put --profile edge ./build.tar.gz /tmp/build.tar.gz
  spt sftp cat --profile edge /etc/hostname
  spt sftp tail --profile edge /var/log/app.log --bytes 4096
  spt sftp chmod --profile edge --mode 0640 /tmp/build.tar.gz
  spt sftp symlink --profile edge --target /opt/app/current /opt/app/live
  spt sftp readlink --profile edge /opt/app/live
  spt sftp realpath --profile edge ./reports
  spt sftp put-recursive --profile edge ./dist /srv/app --bps 5MiB --checksum sha256
  spt sftp get-recursive --profile edge /srv/app ./mirror --resume
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
    /// Print a remote file (with a size cap).
    Cat(SftpCatArgs),
    /// Print the trailing bytes of a remote file.
    Tail(SftpTailArgs),
    /// Change POSIX permissions on a remote path.
    Chmod(SftpChmodArgs),
    /// Create a remote symbolic link.
    Symlink(SftpSymlinkArgs),
    /// Read the target of a remote symbolic link.
    Readlink(SftpPathArgs),
    /// Canonicalise a remote path.
    Realpath(SftpPathArgs),
    /// Mirror a local directory tree onto the server (recursive `put`).
    PutRecursive(SftpRecursiveArgs),
    /// Mirror a remote directory tree onto the local filesystem (recursive `get`).
    GetRecursive(SftpRecursiveArgs),
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

/// `spt sftp cat`.
#[derive(Args, Debug)]
pub struct SftpCatArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Remote file path.
    pub path: String,
    /// Maximum number of bytes to read; defaults to 4 MiB.
    #[arg(long, value_name = "BYTES", default_value_t = 4 * 1024 * 1024)]
    pub size_cap: u64,
}

/// `spt sftp tail`.
#[derive(Args, Debug)]
pub struct SftpTailArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Remote file path.
    pub path: String,
    /// Number of trailing bytes to print; defaults to 4 KiB.
    #[arg(long, value_name = "BYTES", default_value_t = 4096)]
    pub bytes: u64,
}

/// `spt sftp chmod`.
#[derive(Args, Debug)]
pub struct SftpChmodArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Octal mode, for example `0640`.
    #[arg(long, value_name = "OCTAL")]
    pub mode: String,
    /// Remote path.
    pub path: String,
}

/// `spt sftp symlink`.
#[derive(Args, Debug)]
pub struct SftpSymlinkArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Target path the link should point to.
    #[arg(long)]
    pub target: String,
    /// Link path to create.
    pub linkpath: String,
}

/// Checksum verification modes accepted by recursive transfers.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SftpChecksumMode {
    /// No post-transfer verification.
    None,
    /// SHA-256 each file on both ends.
    Sha256,
}

/// `spt sftp put-recursive` / `spt sftp get-recursive`.
#[derive(Args, Debug)]
pub struct SftpRecursiveArgs {
    /// Profile name.
    #[arg(long)]
    pub profile: String,
    /// Source path. For `put-recursive` this is a local directory; for
    /// `get-recursive` it is a remote directory.
    pub source: String,
    /// Destination path. For `put-recursive` this is a remote directory;
    /// for `get-recursive` it is a local directory.
    pub destination: String,
    /// Resume mode: seek into existing target files instead of truncating.
    #[arg(long)]
    pub resume: bool,
    /// Bandwidth cap, e.g. `5MiB` (parsed via `bytesize`); `0` disables.
    #[arg(long, value_name = "RATE", default_value = "0")]
    pub bps: String,
    /// Post-transfer integrity check.
    #[arg(long, value_enum, value_name = "ALGO", default_value_t = SftpChecksumMode::None)]
    pub checksum: SftpChecksumMode,
    /// Follow symbolic links during the walk (loops are still detected).
    #[arg(long)]
    pub follow_symlinks: bool,
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
