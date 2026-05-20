//! `spt config` — manage configuration files.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt config init --example smtp --path /etc/ssh-perma-tunnel/config.toml
  spt config validate --strict
  spt config render --redacted
  spt config diff --from old.toml --to new.toml
  spt config pull --url https://cfg.example/spt.toml --fingerprint <sha256> --cache";

/// `spt config` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct ConfigCmd {
    /// Subcommand selecting the config operation.
    #[command(subcommand)]
    pub command: ConfigSub,
}

/// Subcommands of `spt config`.
#[derive(Subcommand, Debug)]
pub enum ConfigSub {
    /// Initialize a new config file from a template.
    Init(ConfigInit),
    /// Validate config syntax, schema, and obvious mistakes.
    Validate(ConfigValidate),
    /// Run environment checks against the loaded config.
    Doctor(ConfigDoctor),
    /// Render the canonical (optionally redacted) config.
    Render(ConfigRender),
    /// Diff two config files.
    Diff(ConfigDiff),
    /// Migrate a config between schema versions.
    Migrate(ConfigMigrate),
    /// Reload the running service's config.
    Reload(ConfigReload),
    /// Pull a remote config over HTTPS with pinning.
    Pull(ConfigPull),
    /// Manage remote-config trust pins.
    Trust(ConfigTrust),
    /// Encrypt a plaintext config to a sealed `SPTENC1` envelope.
    Encrypt(ConfigEncrypt),
    /// Decrypt a sealed `SPTENC1` envelope back to plaintext TOML.
    Decrypt(ConfigDecrypt),
    /// Open a sealed config in `$EDITOR`; re-seal on save.
    Edit(ConfigEdit),
    /// Re-seal a sealed config under a new key (key rotation).
    Crypt(ConfigCrypt),
}

/// `spt config crypt`.
#[derive(Args, Debug)]
pub struct ConfigCrypt {
    /// Sub-action.
    #[command(subcommand)]
    pub command: ConfigCryptSub,
}

/// Subcommands of `spt config crypt`.
#[derive(Subcommand, Debug)]
pub enum ConfigCryptSub {
    /// Re-seal a sealed config under a new key.
    Rotate(ConfigCryptRotate),
}

/// `spt config encrypt`.
#[derive(Args, Debug)]
pub struct ConfigEncrypt {
    /// Plaintext config path.
    #[arg(value_name = "IN")]
    pub input: PathBuf,
    /// Output path (default: `<IN>.sealed`).
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Read passphrase from a secret reference (e.g. `secret://env/SPT_PP`).
    #[arg(long, value_name = "REF")]
    pub passphrase_from: Option<String>,
    /// One or more X25519 recipient public keys (base64).
    #[arg(long, value_name = "PUBKEY")]
    pub recipient: Vec<String>,
    /// Use the keychain-resident vault master key.
    #[arg(long)]
    pub use_vault_master: bool,
    /// Vault directory or `vault.spt` file used for `secret://` passphrases
    /// and `--use-vault-master`.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Unlock the vault with a passphrase source instead of the keychain
    /// (`stdin`, `env:NAME`, `file:<path>`, or `file:///path`).
    #[arg(long, value_name = "SOURCE")]
    pub vault_passphrase_from: Option<String>,
    /// Overwrite an existing output file.
    #[arg(long)]
    pub force: bool,
}

/// `spt config decrypt`.
#[derive(Args, Debug)]
pub struct ConfigDecrypt {
    /// Sealed config path.
    #[arg(value_name = "IN")]
    pub input: PathBuf,
    /// Output path. If unset, write the cleartext to stdout.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Read passphrase from a secret reference.
    #[arg(long, value_name = "REF")]
    pub passphrase_from: Option<String>,
    /// Path to an X25519 private-key file (32 raw bytes or base64 line).
    #[arg(long, value_name = "PATH")]
    pub recipient_key: Option<PathBuf>,
    /// Vault directory or `vault.spt` file used for `secret://` passphrases
    /// and vault-master envelopes.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Unlock the vault with a passphrase source instead of the keychain.
    #[arg(long, value_name = "SOURCE")]
    pub vault_passphrase_from: Option<String>,
}

/// `spt config edit`.
#[derive(Args, Debug)]
pub struct ConfigEdit {
    /// Sealed config path.
    #[arg(value_name = "SEALED")]
    pub sealed: PathBuf,
    /// Read passphrase from a secret reference.
    #[arg(long, value_name = "REF")]
    pub passphrase_from: Option<String>,
    /// Vault directory or `vault.spt` file used for `secret://` passphrases
    /// and vault-master envelopes.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Unlock the vault with a passphrase source instead of the keychain.
    #[arg(long, value_name = "SOURCE")]
    pub vault_passphrase_from: Option<String>,
}

/// `spt config crypt rotate`.
#[derive(Args, Debug)]
pub struct ConfigCryptRotate {
    /// Sealed config path.
    #[arg(value_name = "SEALED")]
    pub sealed: PathBuf,
    /// New passphrase, read from a secret reference.
    #[arg(long, value_name = "REF")]
    pub new_passphrase_from: Option<String>,
    /// New X25519 recipient public keys (base64).
    #[arg(long, value_name = "PUBKEY")]
    pub new_recipient: Vec<String>,
    /// Vault directory or `vault.spt` file used for `secret://` passphrases
    /// and vault-master envelopes.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Unlock the vault with a passphrase source instead of the keychain.
    #[arg(long, value_name = "SOURCE")]
    pub vault_passphrase_from: Option<String>,
}

/// Built-in config templates available to `spt config init`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ConfigExample {
    Smtp,
    Jump,
    Reverse,
    Ssh3,
    Dns,
    Observability,
    Mcp,
}

/// `spt config init`.
#[derive(Args, Debug)]
pub struct ConfigInit {
    /// Output path for the generated config.
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Template to seed the config from.
    #[arg(long, value_enum, value_name = "EXAMPLE")]
    pub example: Option<ConfigExample>,
}

/// `spt config validate`.
#[derive(Args, Debug)]
pub struct ConfigValidate {
    /// Reject unknown fields and friendly aliases.
    #[arg(long)]
    pub strict: bool,
}

/// `spt config doctor`.
#[derive(Args, Debug)]
pub struct ConfigDoctor {
    /// Run network checks.
    #[arg(long)]
    pub network: bool,
    /// Run service-manager checks.
    #[arg(long)]
    pub service: bool,
    /// Run secret backend checks.
    #[arg(long)]
    pub secrets: bool,
    /// Run DNS checks.
    #[arg(long)]
    pub dns: bool,
    /// Run observability sink checks.
    #[arg(long)]
    pub observability: bool,
}

/// `spt config render`.
#[derive(Args, Debug)]
pub struct ConfigRender {
    /// Redact secret values.
    #[arg(long)]
    pub redacted: bool,
    /// Render as JSON instead of canonical TOML.
    #[arg(long)]
    pub json: bool,
}

/// `spt config diff`.
#[derive(Args, Debug)]
pub struct ConfigDiff {
    /// Base config.
    #[arg(long, value_name = "PATH")]
    pub from: PathBuf,
    /// Candidate config.
    #[arg(long, value_name = "PATH")]
    pub to: PathBuf,
}

/// `spt config migrate`.
#[derive(Args, Debug)]
pub struct ConfigMigrate {
    /// Source schema version.
    #[arg(long, value_name = "N")]
    pub from_version: u32,
    /// Target schema version.
    #[arg(long, value_name = "N")]
    pub to_version: u32,
}

/// Reload mode for `spt config reload`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum ReloadMode {
    Signal,
    Watch,
    Service,
    None,
}

/// `spt config reload`.
#[derive(Args, Debug)]
pub struct ConfigReload {
    /// Reload mechanism to use.
    #[arg(long, value_enum, value_name = "MODE")]
    pub mode: Option<ReloadMode>,
    /// Wait for reload to complete.
    #[arg(long)]
    pub wait: bool,
}

/// `spt config pull`.
#[derive(Args, Debug)]
pub struct ConfigPull {
    /// HTTPS URL to fetch.
    #[arg(long, value_name = "URL")]
    pub url: String,
    /// SHA-256 fingerprint pin.
    #[arg(long, value_name = "SHA256")]
    pub fingerprint: Option<String>,
    /// Output path.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Update the local atomic cache.
    #[arg(long)]
    pub cache: bool,
}

/// `spt config trust`.
#[derive(Args, Debug)]
pub struct ConfigTrust {
    /// Trust action.
    #[command(subcommand)]
    pub command: ConfigTrustSub,
}

/// Subcommands of `spt config trust`.
#[derive(Subcommand, Debug)]
pub enum ConfigTrustSub {
    /// Add a pinned remote-config URL.
    AddUrl(ConfigTrustAddUrl),
}

/// `spt config trust add-url`.
#[derive(Args, Debug)]
pub struct ConfigTrustAddUrl {
    /// HTTPS URL to trust.
    #[arg(long, value_name = "URL")]
    pub url: String,
    /// SHA-256 fingerprint pin.
    #[arg(long, value_name = "SHA256")]
    pub fingerprint: String,
}
