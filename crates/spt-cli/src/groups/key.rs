//! `spt key` — keygen, inspection, and remote install.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

const EXAMPLES: &str = "EXAMPLES:
  spt key generate --type ed25519 --out ~/.ssh/spt_ed25519 --comment spt
  spt key inspect ~/.ssh/spt_ed25519 --fingerprint sha256
  spt key sign-cert --ca-key ca --public-key user.pub --principal alice --out user-cert.pub
  spt key install-public --profile edge --key ~/.ssh/spt_ed25519.pub
  spt key change-passphrase ~/.ssh/spt_ed25519";

/// `spt key` group.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct KeyCmd {
    /// Subcommand.
    #[command(subcommand)]
    pub command: KeySub,
}

/// Subcommands of `spt key`.
#[derive(Subcommand, Debug)]
pub enum KeySub {
    /// Generate a new keypair.
    Generate(KeyGenerate),
    /// Inspect a key file.
    Inspect(KeyInspect),
    /// Print a public key (optionally to a file).
    Public(KeyPublic),
    /// Change the passphrase on a private key.
    ChangePassphrase(KeyPath),
    /// Sign an OpenSSH certificate.
    SignCert(KeySignCert),
    /// Verify an OpenSSH certificate.
    VerifyCert(KeyPath),
    /// Install a public key on a remote host.
    InstallPublic(KeyInstallPublic),
}

/// Key algorithms supported by `spt key generate`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum KeyKind {
    Ed25519,
    EcdsaP256,
    Rsa,
}

/// Fingerprint hash algorithms.
#[derive(Copy, Clone, Debug, Eq, PartialEq, ValueEnum)]
pub enum FingerprintAlgo {
    Sha256,
    Md5,
}

/// `spt key generate`.
#[derive(Args, Debug)]
pub struct KeyGenerate {
    /// Algorithm.
    #[arg(long, value_enum, value_name = "TYPE")]
    pub r#type: KeyKind,
    /// Output path (private key; public is `<path>.pub`).
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
    /// RSA bit length (only meaningful for `--type rsa`).
    #[arg(long, value_name = "N")]
    pub bits: Option<u32>,
    /// Optional comment to embed.
    #[arg(long, value_name = "TEXT")]
    pub comment: Option<String>,
    /// Encrypt the private key at rest with a passphrase.
    #[arg(long)]
    pub encrypt: bool,
}

/// `spt key inspect`.
#[derive(Args, Debug)]
pub struct KeyInspect {
    /// Key file path.
    pub path: PathBuf,
    /// Fingerprint hash to print.
    #[arg(long, value_enum, value_name = "ALGO")]
    pub fingerprint: Option<FingerprintAlgo>,
    /// JSON output.
    #[arg(long)]
    pub json: bool,
}

/// `spt key public`.
#[derive(Args, Debug)]
pub struct KeyPublic {
    /// Private key path.
    pub path: PathBuf,
    /// Output file (otherwise stdout).
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
}

/// Single positional path argument.
#[derive(Args, Debug)]
pub struct KeyPath {
    /// Key or certificate path.
    pub path: PathBuf,
}

/// `spt key sign-cert`.
#[derive(Args, Debug)]
pub struct KeySignCert {
    /// Path to the signing CA private key.
    #[arg(long, value_name = "PATH")]
    pub ca_key: PathBuf,
    /// Public key to sign.
    #[arg(long, value_name = "PATH")]
    pub public_key: PathBuf,
    /// Principal name to embed.
    #[arg(long, value_name = "NAME")]
    pub principal: String,
    /// Output certificate path.
    #[arg(long, value_name = "PATH")]
    pub out: PathBuf,
}

/// `spt key install-public`.
#[derive(Args, Debug)]
pub struct KeyInstallPublic {
    /// Owning profile.
    #[arg(long)]
    pub profile: String,
    /// Public key path.
    #[arg(long, value_name = "PATH")]
    pub key: PathBuf,
    /// Override the remote install command.
    #[arg(long, value_name = "COMMAND")]
    pub remote_command: Option<String>,
}
