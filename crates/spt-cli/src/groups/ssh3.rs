//! `spt ssh3-serve` — run the in-repo SSH3 (QUIC + HTTP/3) server end.
//!
//! This is the responder half of an spt↔spt SSH3 tunnel: it binds a
//! `quinn::Endpoint::server`, accepts QUIC connections, and runs the
//! `Ssh3Server` responder per connection so a peer `spt` (or any client
//! speaking the spt SSH3 framing) can open forwards through it.
//!
//! The framing/auth contract is spt↔spt only; reference-server
//! (francoismichel/ssh3) forward interop is explicitly out of scope.

use clap::Args;

/// Example invocations shown in `--help`.
pub const EXAMPLES: &str = "EXAMPLES:
  spt ssh3-serve --listen 0.0.0.0:443 --cert server.pem --key server.key
  spt ssh3-serve --listen 127.0.0.1:8443 --self-signed
  spt ssh3-serve --cert chain.pem --key key.pem --allow-target db.internal:5432
  spt ssh3-serve --cert chain.pem --key key.pem --fixed-target dns.internal:53 --require-authorization-file /run/credentials/spt.ssh3.authz
  spt ssh3-serve --cert chain.pem --key key.pem --protocol-token ssh3";

/// `spt ssh3-serve` — bind and serve an SSH3 responder endpoint.
#[derive(Args, Debug)]
#[command(after_help = EXAMPLES)]
pub struct Ssh3ServeCmd {
    /// Address and port to bind the QUIC/UDP listener on.
    #[arg(long, value_name = "ADDR:PORT", default_value = "0.0.0.0:443")]
    pub listen: String,

    /// Path to the server's TLS certificate chain (PEM, leaf first).
    /// Required unless `--self-signed` is given.
    #[arg(long, value_name = "PEM")]
    pub cert: Option<std::path::PathBuf>,

    /// Path to the server's TLS private key (PEM: PKCS#8, PKCS#1, or SEC1).
    /// Required unless `--self-signed` is given.
    #[arg(long, value_name = "PEM")]
    pub key: Option<std::path::PathBuf>,

    /// Dev-mode only: generate a self-signed certificate at startup instead of
    /// loading `--cert`/`--key`. Requires the binary to be built with the
    /// `server-selfsigned` feature; otherwise this flag errors. The SHA-256
    /// SPKI pin of the generated cert is logged so a peer can pin it.
    #[arg(long, conflicts_with_all = ["cert", "key"])]
    pub self_signed: bool,

    /// DNS name(s) / IP literal(s) to embed as SANs in the self-signed cert.
    /// Only meaningful with `--self-signed`. Repeat for multiple SANs.
    #[arg(long = "self-signed-san", value_name = "NAME", default_values_t = [String::from("localhost")])]
    pub self_signed_sans: Vec<String>,

    /// The `:protocol` token the server requires on the HTTP/3 Extended-CONNECT
    /// (default `ssh3`). A mismatch is rejected with HTTP 421.
    #[arg(long, value_name = "TOKEN", default_value = "ssh3")]
    pub protocol_token: String,

    /// Allow-list of `host:port` forward targets the server will dial. May be
    /// repeated. When empty, every requested `direct-tcp` open is accepted and
    /// dialed as requested (open relay — use with care).
    #[arg(long = "allow-target", value_name = "HOST:PORT")]
    pub allow_targets: Vec<String>,

    /// Pin every accepted forward to this single `host:port` target regardless
    /// of what the peer requests (overrides `--allow-target`). Useful for a
    /// single-service bastion.
    #[arg(long, value_name = "HOST:PORT", conflicts_with = "allow_targets")]
    pub fixed_target: Option<String>,

    /// Require this bearer/authorization value on the CONNECT request. When
    /// set, a CONNECT whose `Authorization` header does not match is rejected
    /// with HTTP 401. Prefer `--require-authorization-file` for production so
    /// secrets do not appear in process arguments.
    #[arg(
        long,
        value_name = "TOKEN",
        conflicts_with = "require_authorization_file"
    )]
    pub require_authorization: Option<String>,

    /// Read the required CONNECT `Authorization` header value from this file.
    /// Trailing CR/LF is ignored so newline-terminated secret files work.
    #[arg(long, value_name = "PATH")]
    pub require_authorization_file: Option<std::path::PathBuf>,
}
