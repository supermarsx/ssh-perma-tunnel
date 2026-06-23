//! Client-side DNS resolution policy and a tiny resolver cache.
//!
//! This is the shared home for the `[profiles.connection].dns_resolution` knob
//! (spec §9.11): both transports (`spt-ssh2` and `spt-ssh3`) consume it at their
//! dial sites so the policy can be honored uniformly.
//!
//! Two modes:
//!
//! * [`DnsResolution::PerAttempt`] (default, behaviour-preserving) — every dial
//!   re-resolves the name via the OS resolver. This is exactly what the code did
//!   before this knob existed.
//! * [`DnsResolution::Once`] — the first dial for a `(host, port)` key resolves
//!   the name and *pins* the resulting addresses for the lifetime of the
//!   process; later dials (e.g. reconnects) reuse the pinned addresses instead
//!   of re-resolving. Useful when the upstream DNS is flaky or the operator
//!   wants a stable address across reconnects.
//!
//! The cache is process-wide, tiny, thread-safe, and dependency-free (a
//! `Mutex<HashMap>` over std's [`ToSocketAddrs`]). IP literals resolve trivially
//! and are cached just the same.

use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Mutex;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

/// Client-side DNS resolution policy.
///
/// Maps to `[profiles.connection].dns_resolution` (`per_attempt` | `once`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsResolution {
    /// Re-resolve the name on every dial (default; behaviour-preserving).
    #[default]
    PerAttempt,
    /// Resolve the name once per `(host, port)` and pin it across reconnects.
    Once,
}

impl DnsResolution {
    /// Parse the schema string form (`per_attempt` | `once`). Returns `None`
    /// for any unrecognized value so callers can surface a config error.
    #[must_use]
    pub fn from_config_str(s: &str) -> Option<Self> {
        match s {
            "per_attempt" => Some(Self::PerAttempt),
            "once" => Some(Self::Once),
            _ => None,
        }
    }

    /// The schema string form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerAttempt => "per_attempt",
            Self::Once => "once",
        }
    }
}

/// Pinned-address map keyed by `(host, port)`.
type PinMap = HashMap<(String, u16), Vec<SocketAddr>>;

/// Process-wide pinned-address cache for [`DnsResolution::Once`].
fn pin_cache() -> &'static Mutex<PinMap> {
    static CACHE: OnceLock<Mutex<PinMap>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(PinMap::new()))
}

/// Resolve `host:port` to socket addresses, honoring the supplied policy.
///
/// * [`DnsResolution::PerAttempt`] always delegates to the OS resolver (no
///   caching), reproducing the pre-knob behaviour exactly.
/// * [`DnsResolution::Once`] resolves on the first call for a given
///   `(host, port)` key and returns the *pinned* addresses on every later call,
///   even if upstream DNS later changes or fails.
///
/// The returned vector is never empty on `Ok` (an empty resolution is mapped to
/// an [`io::ErrorKind::NotFound`] error, matching `TcpStream::connect`'s
/// behaviour on an unresolvable name).
///
/// # Errors
///
/// Returns the underlying resolver [`io::Error`] when the name cannot be
/// resolved (only on a cache miss for `Once`, or always for `PerAttempt`).
pub fn resolve(host: &str, port: u16, policy: DnsResolution) -> io::Result<Vec<SocketAddr>> {
    match policy {
        DnsResolution::PerAttempt => resolve_fresh(host, port),
        DnsResolution::Once => {
            let key = (host.to_owned(), port);
            // Fast path: already pinned.
            if let Ok(cache) = pin_cache().lock() {
                if let Some(addrs) = cache.get(&key) {
                    return Ok(addrs.clone());
                }
            }
            // Cache miss: resolve fresh, then pin (last writer wins; a
            // concurrent resolver for the same key just overwrites with an
            // equivalent set).
            let addrs = resolve_fresh(host, port)?;
            if let Ok(mut cache) = pin_cache().lock() {
                cache.insert(key, addrs.clone());
            }
            Ok(addrs)
        }
    }
}

/// Resolve via the OS resolver with no caching.
fn resolve_fresh(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs()?.collect();
    if addrs.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no addresses resolved for `{host}:{port}`"),
        ));
    }
    Ok(addrs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_per_attempt() {
        assert_eq!(DnsResolution::default(), DnsResolution::PerAttempt);
    }

    #[test]
    fn from_config_str_known_values() {
        assert_eq!(
            DnsResolution::from_config_str("per_attempt"),
            Some(DnsResolution::PerAttempt)
        );
        assert_eq!(
            DnsResolution::from_config_str("once"),
            Some(DnsResolution::Once)
        );
    }

    #[test]
    fn from_config_str_rejects_unknown() {
        assert_eq!(DnsResolution::from_config_str("forever"), None);
        assert_eq!(DnsResolution::from_config_str(""), None);
        assert_eq!(DnsResolution::from_config_str("PerAttempt"), None);
    }

    #[test]
    fn round_trip_serde() {
        for p in [DnsResolution::PerAttempt, DnsResolution::Once] {
            let s = serde_json::to_string(&p).unwrap();
            let de: DnsResolution = serde_json::from_str(&s).unwrap();
            assert_eq!(p, de);
        }
        // wire form is snake_case.
        assert_eq!(
            serde_json::to_string(&DnsResolution::PerAttempt).unwrap(),
            "\"per_attempt\""
        );
        assert_eq!(
            serde_json::to_string(&DnsResolution::Once).unwrap(),
            "\"once\""
        );
    }

    #[test]
    fn per_attempt_resolves_localhost() {
        let addrs = resolve("localhost", 80, DnsResolution::PerAttempt).unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 80));
    }

    #[test]
    fn once_resolves_and_pins_stable_addrs() {
        // Use a distinct port so this test's key cannot collide with the
        // per-attempt test (the cache is process-wide).
        let first = resolve("localhost", 7001, DnsResolution::Once).unwrap();
        let second = resolve("localhost", 7001, DnsResolution::Once).unwrap();
        assert!(!first.is_empty());
        // Pinned: the second call returns exactly what the first did, in order.
        assert_eq!(first, second);
    }

    #[test]
    fn per_attempt_does_not_consult_pin_cache() {
        // An IP literal always resolves to itself; per-attempt must produce it
        // fresh regardless of any pinned entry under a different policy.
        let a = resolve("127.0.0.1", 7002, DnsResolution::PerAttempt).unwrap();
        assert_eq!(a, vec![SocketAddr::from(([127, 0, 0, 1], 7002))]);
        // A second per-attempt call re-resolves (no pinning side effects).
        let b = resolve("127.0.0.1", 7002, DnsResolution::PerAttempt).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn once_pins_ip_literal() {
        let a = resolve("127.0.0.1", 7003, DnsResolution::Once).unwrap();
        let b = resolve("127.0.0.1", 7003, DnsResolution::Once).unwrap();
        assert_eq!(a, vec![SocketAddr::from(([127, 0, 0, 1], 7003))]);
        assert_eq!(a, b);
    }

    #[test]
    fn unresolvable_name_errors_per_attempt() {
        let err = resolve("no.such.host.invalid.", 80, DnsResolution::PerAttempt).unwrap_err();
        // Either resolver failure or empty-set NotFound — both are errors.
        let _ = err;
    }
}
