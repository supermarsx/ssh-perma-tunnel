//! `spt ssh3-serve` operation body — the in-repo SSH3 server end.
//!
//! Builds an ALPN-`h3` rustls server config (from operator-supplied cert+key
//! PEM, or a dev-mode self-signed cert when built with the
//! `ssh3-server-selfsigned` feature) and an [`spt_ssh3::Ssh3ServerAcl`] from the
//! CLI surface, then hands both to [`spt_ssh3::serve`], which owns the
//! `quinn::Endpoint` bind + accept loop and runs [`spt_ssh3::Ssh3Server::run`]
//! per accepted connection.
//!
//! The framing/auth contract is identical to what the client
//! [`spt_ssh3::Ssh3Session`] / [`spt_ssh3::Ssh3Server::run`] already implement
//! (spt↔spt only — reference-server forward interop is out of scope).
//!
//! Graceful shutdown: a Ctrl-C / SIGTERM (via [`crate::signals`]) resolves the
//! shutdown future passed to [`spt_ssh3::serve`], mirroring `spt tunnel run`.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

use std::net::{SocketAddr, ToSocketAddrs};

use spt_cli::groups::ssh3::Ssh3ServeCmd;
use spt_cli::GlobalOpts;
use spt_core::{Error, Result};
use spt_protocol::endpoint::TargetAddr;
use spt_ssh3::Ssh3ServerAcl;

/// Parse a `host:port` string into a [`TargetAddr`].
fn parse_target(s: &str) -> Result<TargetAddr> {
    let (host, port) = s.rsplit_once(':').ok_or_else(|| {
        Error::InvalidArgs(format!("ssh3-serve: target `{s}` must be `host:port`"))
    })?;
    if host.is_empty() {
        return Err(Error::InvalidArgs(format!(
            "ssh3-serve: target `{s}` has an empty host"
        )));
    }
    let port: u16 = port
        .parse()
        .map_err(|e| Error::InvalidArgs(format!("ssh3-serve: target `{s}` bad port: {e}")))?;
    Ok(TargetAddr::new(host.to_string(), port))
}

/// Resolve the `--listen` string to a concrete [`SocketAddr`].
fn parse_listen(s: &str) -> Result<SocketAddr> {
    s.to_socket_addrs()
        .map_err(|e| Error::InvalidArgs(format!("ssh3-serve: --listen `{s}`: {e}")))?
        .next()
        .ok_or_else(|| {
            Error::InvalidArgs(format!("ssh3-serve: --listen `{s}` resolved to nothing"))
        })
}

/// Load the expected CONNECT `Authorization` header from CLI input.
fn required_authorization(args: &Ssh3ServeCmd) -> Result<Option<String>> {
    if let Some(path) = &args.require_authorization_file {
        let mut value = std::fs::read_to_string(path).map_err(|e| {
            Error::InvalidConfig(format!(
                "ssh3-serve: read --require-authorization-file `{}`: {e}",
                path.display()
            ))
        })?;
        while value.ends_with('\r') || value.ends_with('\n') {
            value.pop();
        }
        if value.is_empty() {
            return Err(Error::InvalidConfig(format!(
                "ssh3-serve: --require-authorization-file `{}` is empty",
                path.display()
            )));
        }
        Ok(Some(value))
    } else {
        Ok(args.require_authorization.clone())
    }
}

fn validate_exposure(listen: SocketAddr, args: &Ssh3ServeCmd) -> Result<()> {
    if args.allow_targets.is_empty() && args.fixed_target.is_none() && !args.allow_open_relay {
        return Err(Error::InvalidArgs(
            "ssh3-serve: refusing to start without a target restriction; pass \
             --allow-target, --fixed-target, or the explicit --allow-open-relay escape hatch"
                .into(),
        ));
    }

    if !listen.ip().is_loopback()
        && args.require_authorization.is_none()
        && args.require_authorization_file.is_none()
    {
        return Err(Error::InvalidArgs(
            "ssh3-serve: refusing non-loopback listen without authorization; pass \
             --require-authorization or --require-authorization-file"
                .into(),
        ));
    }

    Ok(())
}

/// Build the [`Ssh3ServerAcl`] from the parsed CLI surface.
fn build_acl(args: &Ssh3ServeCmd) -> Result<Ssh3ServerAcl> {
    let mut acl = if let Some(fixed) = &args.fixed_target {
        let target = parse_target(fixed)?;
        Ssh3ServerAcl::fixed_target(target)
    } else if args.allow_open_relay {
        // Explicit escape hatch: dial whatever the peer requests (open relay).
        Ssh3ServerAcl::new(|open| Some(TargetAddr::new(open.host.clone(), open.port)))
    } else {
        // Allow-list: only resolve opens whose `host:port` is allow-listed.
        let mut allowed = Vec::with_capacity(args.allow_targets.len());
        for t in &args.allow_targets {
            allowed.push(parse_target(t)?);
        }
        Ssh3ServerAcl::new(move |open| {
            allowed
                .iter()
                .find(|t| t.host == open.host && t.port == open.port)
                .cloned()
        })
    };

    acl = acl.with_protocol_token(args.protocol_token.clone());

    let expected_authorization = required_authorization(args)?;
    if let Some(expected) = expected_authorization {
        acl = acl.with_authorize_connect(move |_protocol, authz| authz == Some(expected.as_str()));
    }

    Ok(acl)
}

/// Build the rustls/quinn server config: from operator PEM, or self-signed.
///
/// Returns the opaque `quinn::ServerConfig` (type inferred so this module never
/// names `quinn` directly — the type lives wholly inside `spt-ssh3`).
fn build_server_config(args: &Ssh3ServeCmd) -> Result<spt_ssh3_server_config> {
    if args.self_signed {
        #[cfg(feature = "ssh3-server-selfsigned")]
        {
            let sans = args.self_signed_sans.clone();
            let (cfg, pin) = spt_ssh3::tls::self_signed_server_config(sans)?;
            let pin_hex = hex::encode(pin);
            tracing::warn!(
                spki_sha256 = %pin_hex,
                "ssh3-serve: using a DEV self-signed certificate — NOT for production. \
                 Peers can pin this leaf via the SPKI SHA-256 above."
            );
            return Ok(cfg);
        }
        #[cfg(not(feature = "ssh3-server-selfsigned"))]
        {
            return Err(Error::InvalidArgs(
                "ssh3-serve: --self-signed requires a binary built with the \
                 `ssh3-server-selfsigned` feature (dev-only). Supply --cert and --key instead."
                    .into(),
            ));
        }
    }

    let cert_path = args.cert.as_ref().ok_or_else(|| {
        Error::InvalidArgs("ssh3-serve: --cert is required (or use --self-signed)".into())
    })?;
    let key_path = args.key.as_ref().ok_or_else(|| {
        Error::InvalidArgs("ssh3-serve: --key is required (or use --self-signed)".into())
    })?;
    let cert_pem = std::fs::read(cert_path).map_err(|e| {
        Error::InvalidConfig(format!(
            "ssh3-serve: read --cert `{}`: {e}",
            cert_path.display()
        ))
    })?;
    let key_pem = std::fs::read(key_path).map_err(|e| {
        Error::InvalidConfig(format!(
            "ssh3-serve: read --key `{}`: {e}",
            key_path.display()
        ))
    })?;
    spt_ssh3::tls::build_server_config(&cert_pem, &key_pem)
}

// The concrete server-config type is `quinn::ServerConfig`, re-exported by
// `spt-ssh3` so this module need not depend on `quinn` directly.
use spt_ssh3::tls::ServerTlsConfig as spt_ssh3_server_config;

/// `spt ssh3-serve`.
pub async fn serve(global: &GlobalOpts, args: Ssh3ServeCmd) -> Result<()> {
    let _ = global;
    let listen = parse_listen(&args.listen)?;
    validate_exposure(listen, &args)?;
    let server_cfg = build_server_config(&args)?;
    let acl = build_acl(&args)?;

    // Bridge OS signals to a shutdown future for the accept loop.
    let mut signal_rx = crate::signals::spawn();
    let shutdown = async move {
        loop {
            if signal_rx.changed().await.is_err() {
                break;
            }
            if matches!(*signal_rx.borrow(), Some(crate::signals::Signal::Shutdown)) {
                break;
            }
        }
    };

    spt_ssh3::serve(listen, server_cfg, acl, shutdown).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> Ssh3ServeCmd {
        Ssh3ServeCmd {
            listen: "127.0.0.1:0".into(),
            cert: None,
            key: None,
            self_signed: false,
            self_signed_sans: vec!["localhost".into()],
            protocol_token: "ssh3".into(),
            allow_targets: Vec::new(),
            fixed_target: None,
            allow_open_relay: false,
            require_authorization: None,
            require_authorization_file: None,
        }
    }

    #[test]
    fn parse_target_ok() {
        let t = parse_target("db.internal:5432").unwrap();
        assert_eq!(t.host, "db.internal");
        assert_eq!(t.port, 5432);
    }

    #[test]
    fn parse_target_ipv6() {
        let t = parse_target("[::1]:443").unwrap();
        assert_eq!(t.host, "[::1]");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parse_target_rejects_missing_port() {
        assert!(parse_target("nohost").is_err());
        assert!(parse_target("host:notaport").is_err());
        assert!(parse_target(":5432").is_err());
    }

    #[test]
    fn parse_listen_ok() {
        let a = parse_listen("127.0.0.1:8443").unwrap();
        assert_eq!(a.port(), 8443);
    }

    #[test]
    fn build_acl_fixed_target_pins_every_open() {
        let mut args = base_args();
        args.fixed_target = Some("echo:1".into());
        let acl = build_acl(&args).unwrap();
        let open = spt_ssh3::ChannelOpenPayload {
            host: "anything".into(),
            port: 9999,
        };
        let resolved = (acl.resolve_target)(&open).unwrap();
        assert_eq!(resolved.host, "echo");
        assert_eq!(resolved.port, 1);
    }

    #[test]
    fn build_acl_allow_list_only_resolves_listed() {
        let mut args = base_args();
        args.allow_targets = vec!["db:5432".into()];
        let acl = build_acl(&args).unwrap();
        let ok = spt_ssh3::ChannelOpenPayload {
            host: "db".into(),
            port: 5432,
        };
        let denied = spt_ssh3::ChannelOpenPayload {
            host: "other".into(),
            port: 22,
        };
        assert!((acl.resolve_target)(&ok).is_some());
        assert!((acl.resolve_target)(&denied).is_none());
    }

    #[test]
    fn build_acl_explicit_open_relay_resolves_requested_target() {
        let mut args = base_args();
        args.allow_open_relay = true;
        let acl = build_acl(&args).unwrap();
        let open = spt_ssh3::ChannelOpenPayload {
            host: "any".into(),
            port: 1234,
        };
        let resolved = (acl.resolve_target)(&open).unwrap();
        assert_eq!(resolved.host, "any");
        assert_eq!(resolved.port, 1234);
    }

    #[test]
    fn validate_exposure_requires_target_policy() {
        let args = base_args();
        let err = validate_exposure("127.0.0.1:8443".parse().unwrap(), &args).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)), "got {err:?}");
    }

    #[test]
    fn validate_exposure_requires_auth_for_non_loopback() {
        let mut args = base_args();
        args.allow_targets = vec!["db:5432".into()];
        let err = validate_exposure("0.0.0.0:8443".parse().unwrap(), &args).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)), "got {err:?}");

        args.require_authorization = Some("Bearer ok".into());
        validate_exposure("0.0.0.0:8443".parse().unwrap(), &args).unwrap();
    }

    #[test]
    fn build_acl_protocol_token_applied() {
        let mut args = base_args();
        args.protocol_token = "custom".into();
        let acl = build_acl(&args).unwrap();
        assert_eq!(acl.protocol_token, "custom");
    }

    #[test]
    fn build_acl_require_authorization_checks_header() {
        let mut args = base_args();
        args.require_authorization = Some("Bearer xyz".into());
        let acl = build_acl(&args).unwrap();
        let check = acl.authorize_connect.as_ref().unwrap();
        assert!(check("ssh3", Some("Bearer xyz")));
        assert!(!check("ssh3", Some("Bearer wrong")));
        assert!(!check("ssh3", None));
    }

    #[test]
    fn build_acl_require_authorization_file_checks_header_and_trims_newline() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "spt-ssh3-authz-{}-{}.txt",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(&path, "Bearer from-file\n").unwrap();

        let mut args = base_args();
        args.require_authorization_file = Some(path.clone());
        let acl = build_acl(&args).unwrap();
        let check = acl.authorize_connect.as_ref().unwrap();
        assert!(check("ssh3", Some("Bearer from-file")));
        assert!(!check("ssh3", Some("Bearer from-file\n")));

        std::fs::remove_file(path).unwrap();
    }

    #[cfg(not(feature = "ssh3-server-selfsigned"))]
    #[test]
    fn self_signed_without_feature_errors() {
        let mut args = base_args();
        args.self_signed = true;
        let err = build_server_config(&args).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)), "got {err:?}");
    }

    #[test]
    fn missing_cert_errors() {
        let args = base_args();
        let err = build_server_config(&args).unwrap_err();
        assert!(matches!(err, Error::InvalidArgs(_)), "got {err:?}");
    }
}
