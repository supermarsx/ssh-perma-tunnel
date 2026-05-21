//! meek-http transport (HTTPS-CONNECT through a fronting CDN).
//!
//! ## Stub status
//!
//! The contract surface is shipped; the wire path is gated until Bwire wires
//! `reqwest` (or a hyper-based equivalent) into this crate. The stub validates
//! the SNI / Host: header split (`front_host != sni`) at construction time so
//! configuration errors land at validate-time, not at first connect.

use std::sync::Arc;

use async_trait::async_trait;

use spt_core::Result;

use crate::audit::AuditHook;
use crate::config::ObfsConfig;
use crate::error::ObfsError;
use crate::transport::{AsyncReadWrite, ObfsTransport};

/// meek-http transport handle.
pub struct MeekHttpTransport {
    cfg: ObfsConfig,
    audit: Arc<dyn AuditHook>,
    /// Last simulated HTTP status — used by tests to assert error surfaces.
    pub(crate) simulated_status: u16,
}

impl MeekHttpTransport {
    /// Construct the transport, validating the config.
    pub fn new(cfg: ObfsConfig, audit: Arc<dyn AuditHook>) -> Result<Self> {
        let ObfsConfig::MeekHttp { .. } = cfg else {
            return Err(ObfsError::InvalidConfig(
                "MeekHttpTransport requires ObfsConfig::MeekHttp".into(),
            )
            .into());
        };
        cfg.validate().map_err(spt_core::Error::from)?;
        Ok(Self {
            cfg,
            audit,
            simulated_status: 200,
        })
    }

    /// SNI host used for TLS — `sni` override > URL host. Returns owned
    /// string for convenience.
    #[must_use]
    pub fn sni(&self) -> String {
        match &self.cfg {
            ObfsConfig::MeekHttp { url, sni, .. } => {
                if let Some(s) = sni {
                    return s.clone();
                }
                Self::host_from_url(url).unwrap_or_default()
            }
            _ => unreachable!("checked in new()"),
        }
    }

    /// HTTP Host: header — `front_host` override > URL host.
    #[must_use]
    pub fn host_header(&self) -> String {
        match &self.cfg {
            ObfsConfig::MeekHttp { url, front_host, .. } => {
                if let Some(h) = front_host {
                    return h.clone();
                }
                Self::host_from_url(url).unwrap_or_default()
            }
            _ => unreachable!("checked in new()"),
        }
    }

    /// True when SNI and Host: headers point at different names (the
    /// "domain fronting" mode meek is designed for).
    #[must_use]
    pub fn is_fronted(&self) -> bool {
        self.sni() != self.host_header()
    }

    /// Inject a simulated HTTP status code for the error-surface contract
    /// test. Real implementations replace this with the live response.
    pub fn set_simulated_status(&mut self, code: u16) {
        self.simulated_status = code;
    }

    fn host_from_url(url: &str) -> Option<String> {
        // Tiny URL host extractor — sufficient for the stub. The real path
        // delegates to `url::Url` (already in workspace deps).
        let rest = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))?;
        let host = rest
            .split('/')
            .next()
            .unwrap_or(rest)
            .split(':')
            .next()
            .unwrap_or(rest);
        if host.is_empty() {
            None
        } else {
            Some(host.to_owned())
        }
    }
}

#[async_trait]
impl ObfsTransport for MeekHttpTransport {
    async fn connect(&mut self, target: &str) -> Result<Box<dyn AsyncReadWrite>> {
        self.audit.on_connect(self.name(), target);
        if !(200..300).contains(&self.simulated_status) {
            return Err(ObfsError::Handshake(format!(
                "meek-http front returned HTTP {}",
                self.simulated_status
            ))
            .into());
        }
        tracing::warn!(
            transport = self.name(),
            sni = %self.sni(),
            host = %self.host_header(),
            "meek-http: stub transport — reqwest backend not wired"
        );
        Err(ObfsError::Unsupported {
            transport: "meek-http",
            crate_name: "reqwest",
            detail: "stub transport; HTTPS-CONNECT fronting backend not wired by Bwire yet".into(),
        }
        .into())
    }

    fn name(&self) -> &'static str {
        "meek-http"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::NoopAuditHook;

    fn fronted_cfg() -> ObfsConfig {
        ObfsConfig::MeekHttp {
            url: "https://front.cdn.example/path".into(),
            front_host: Some("hidden.example".into()),
            sni: None,
        }
    }

    #[test]
    fn sni_and_host_differ_under_fronting() {
        let t = MeekHttpTransport::new(fronted_cfg(), Arc::new(NoopAuditHook)).unwrap();
        assert_eq!(t.sni(), "front.cdn.example");
        assert_eq!(t.host_header(), "hidden.example");
        assert!(t.is_fronted());
    }

    #[test]
    fn unfronted_cfg_sni_eq_host() {
        let cfg = ObfsConfig::MeekHttp {
            url: "https://plain.example/p".into(),
            front_host: None,
            sni: None,
        };
        let t = MeekHttpTransport::new(cfg, Arc::new(NoopAuditHook)).unwrap();
        assert_eq!(t.sni(), t.host_header());
        assert!(!t.is_fronted());
    }
}
