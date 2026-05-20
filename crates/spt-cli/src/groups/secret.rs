//! `spt secret` — vault and keychain management.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt secret store init --backend keychain
  spt secret set db/password --prompt
  spt secret set db/password --from-env DB_PASSWORD
  spt secret set api/token --from-file ~/.tokens/api
  spt secret rotate db/password
  spt secret remove db/password";

/// `spt secret` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct SecretCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: SecretSub,
}

/// Subcommands of `spt secret`.
#[derive(Subcommand, Debug)]
pub enum SecretSub {
    /// Initialize the secret store.
    Store(SecretStore),
    /// Set a secret.
    Set(SecretSet),
    /// Get a secret (redacted unless `--reveal`).
    Get(SecretGet),
    /// List known secret names.
    List(SecretList),
    /// Rotate a secret.
    Rotate(SecretName),
    /// Remove a secret.
    Remove(SecretName),
    /// Run secret backend health checks.
    Doctor,
}

/// Backend selector for `secret store init`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum SecretBackend {
    Auto,
    Keychain,
    Vault,
}

/// `spt secret store`.
#[derive(Args, Debug)]
pub struct SecretStore {
    /// Store subcommand.
    #[command(subcommand)]
    pub command: SecretStoreSub,
}

/// `spt secret store` subcommands.
#[derive(Subcommand, Debug)]
pub enum SecretStoreSub {
    /// Initialize a secret store.
    Init(SecretStoreInit),
}

/// `spt secret store init`.
#[derive(Args, Debug)]
pub struct SecretStoreInit {
    /// Preferred backend.
    #[arg(long, value_enum, value_name = "BACKEND")]
    pub backend: Option<SecretBackend>,
    /// Vault directory or `vault.spt` file location.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Read the vault passphrase from a value source
    /// (`stdin`, `file:<path>`, `env:<NAME>`).
    #[arg(long, value_name = "SOURCE")]
    pub passphrase_from: Option<String>,
}

/// `spt secret set`.
#[derive(Args, Debug)]
pub struct SecretSet {
    /// Secret name (`namespace/name`).
    pub name: String,
    /// Read from a TTY prompt.
    #[arg(long, group = "secret_source")]
    pub prompt: bool,
    /// Read from an environment variable.
    #[arg(long, value_name = "ENV", group = "secret_source")]
    pub from_env: Option<String>,
    /// Read from a file (mode-checked).
    #[arg(long, value_name = "PATH", group = "secret_source")]
    pub from_file: Option<PathBuf>,
    /// Vault directory or `vault.spt` file when writing to the local vault.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Unlock the vault with a passphrase source (`stdin`, `env:NAME`,
    /// `file:<path>`, or `file:///path`).
    #[arg(long, value_name = "SOURCE")]
    pub passphrase_from: Option<String>,
}

/// `spt secret get`.
#[derive(Args, Debug)]
pub struct SecretGet {
    /// Secret name.
    pub name: String,
    /// Print the plaintext value.
    #[arg(long)]
    pub reveal: bool,
    /// Vault directory or `vault.spt` file when reading from the local vault.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Unlock the vault with a passphrase source.
    #[arg(long, value_name = "SOURCE")]
    pub passphrase_from: Option<String>,
}

/// `spt secret list`.
#[derive(Args, Debug)]
pub struct SecretList {
    /// Restrict to a single namespace.
    #[arg(long, value_name = "NS")]
    pub namespace: Option<String>,
    /// Vault directory or `vault.spt` file location.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Read the vault passphrase from a value source.
    #[arg(long, value_name = "SOURCE")]
    pub passphrase_from: Option<String>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt secret rotate|remove <name>`.
#[derive(Args, Debug)]
pub struct SecretName {
    /// Secret name (`namespace/name` or `secret://...`).
    pub name: String,
    /// New value source for `rotate`
    /// (`stdin`, `file:<path>`, `env:<NAME>`).
    #[arg(long, value_name = "SOURCE")]
    pub new_value_from: Option<String>,
    /// Vault directory or `vault.spt` file location.
    #[arg(long, value_name = "PATH")]
    pub vault_path: Option<PathBuf>,
    /// Read the vault passphrase from a value source.
    #[arg(long, value_name = "SOURCE")]
    pub passphrase_from: Option<String>,
}
