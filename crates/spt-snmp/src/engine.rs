//! SNMP engine identity, boots/time tracking, and time-window enforcement.
//!
//! Per RFC 3411 §5 the authoritative engine ID is an opaque OCTET STRING that
//! uniquely identifies an SNMP engine. RFC 3411 §5.1 defines a structured
//! 12-byte form starting with the IANA private-enterprise number.

use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result, UsmError};

/// Engine ID byte string. Always non-empty.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EngineId(Vec<u8>);

impl EngineId {
    /// Constructs an `EngineId` from raw bytes.
    pub fn new<T: Into<Vec<u8>>>(bytes: T) -> Result<Self> {
        let v = bytes.into();
        if v.is_empty() || v.len() > 32 {
            return Err(Error::Config(format!(
                "engine id must be 1..=32 bytes (got {})",
                v.len()
            )));
        }
        Ok(Self(v))
    }

    /// Returns the engine id bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for EngineId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// SNMPv3 time-window threshold (RFC 3414 §3.2 — 150 seconds).
pub const TIME_WINDOW_SECS: u32 = 150;

/// Generates a fresh structured engine id per RFC 3411 §5.1 format 5
/// (administratively-unique 4-octet random suffix).
///
/// Layout: `[0x80 | (PEN >> 24)] [PEN bytes 1..4] [format = 5] [4 random bytes]`
///
/// # Examples
/// ```
/// use spt_snmp::generate_engine_id;
/// let id = generate_engine_id(99_999);
/// assert_eq!(id.as_bytes().len(), 9);
/// // Top bit of first byte is set per RFC 3411.
/// assert_eq!(id.as_bytes()[0] & 0x80, 0x80);
/// ```
#[must_use]
pub fn generate_engine_id(private_enterprise_number: u32) -> EngineId {
    let pen = private_enterprise_number & 0x7FFF_FFFF; // top bit reserved
    let mut buf = Vec::with_capacity(9);
    let pen_bytes = pen.to_be_bytes();
    buf.push(pen_bytes[0] | 0x80);
    buf.extend_from_slice(&pen_bytes[1..]);
    buf.push(5); // format: 4 random octets
    let mut rnd = [0u8; 4];
    rand::Rng::fill(&mut rand::thread_rng(), &mut rnd);
    buf.extend_from_slice(&rnd);
    EngineId(buf)
}

/// Tracks engine boots/time per RFC 3414 §2.2.2.
///
/// `engine_boots` is incremented every time the SNMP engine starts.
/// `engine_time` is the number of seconds since the engine last booted,
/// monotonically increasing while running.
#[derive(Debug)]
pub struct EngineClock {
    boots: AtomicU32,
    started_at: Instant,
    /// The wall-clock baseline at engine start (used purely for diagnostics).
    started_unix: u64,
}

impl EngineClock {
    /// Creates a new clock with the given initial boot count.
    ///
    /// In a long-lived agent the boot counter MUST be persisted between
    /// restarts; this crate exposes it as a value the embedder can read on
    /// shutdown via [`EngineClock::boots`] and pass back here on restart.
    #[must_use]
    pub fn new(boots: u32) -> Self {
        Self {
            boots: AtomicU32::new(boots),
            started_at: Instant::now(),
            started_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }

    /// Returns the current `engine_boots` value.
    #[must_use]
    pub fn boots(&self) -> u32 {
        self.boots.load(Ordering::Relaxed)
    }

    /// Returns the current `engine_time` (seconds since boot).
    #[must_use]
    pub fn time(&self) -> u32 {
        let elapsed = self.started_at.elapsed().as_secs();
        // Saturate at u32::MAX; per RFC 3414 the engine should reboot before
        // this happens (≈ 136 years) but we never overflow.
        u32::try_from(elapsed).unwrap_or(u32::MAX)
    }

    /// Wall-clock seconds at engine start (for diagnostics).
    #[must_use]
    pub fn started_unix(&self) -> u64 {
        self.started_unix
    }

    /// Increments `engine_boots`. Should be called once at startup before
    /// processing any messages, then never again for the engine's lifetime.
    pub fn bump_boots(&self) {
        self.boots.fetch_add(1, Ordering::Relaxed);
    }

    /// Validates `peer_boots`/`peer_time` against the local clock per
    /// RFC 3414 §3.2 step 7.
    ///
    /// Returns `Ok(())` if within the 150-second window; otherwise
    /// `UsmError::NotInTimeWindow`.
    pub fn check_time_window(&self, peer_boots: u32, peer_time: u32) -> Result<()> {
        let local_boots = self.boots();
        let local_time = self.time();
        if peer_boots != local_boots {
            return Err(Error::Usm(UsmError::NotInTimeWindow));
        }
        let diff = local_time.abs_diff(peer_time);
        if diff > TIME_WINDOW_SECS {
            return Err(Error::Usm(UsmError::NotInTimeWindow));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_id_validation() {
        assert!(EngineId::new(vec![]).is_err());
        assert!(EngineId::new(vec![0u8; 33]).is_err());
        let id = EngineId::new(vec![1, 2, 3]).unwrap();
        assert_eq!(id.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn structured_engine_id_format() {
        let id = generate_engine_id(99_999);
        let b = id.as_bytes();
        assert_eq!(b.len(), 9);
        assert_eq!(b[0] & 0x80, 0x80);
        assert_eq!(b[4], 5); // format byte
                             // PEN encoded in low 31 bits of bytes 0..4.
        let pen_bytes = [b[0] & 0x7F, b[1], b[2], b[3]];
        let pen = u32::from_be_bytes(pen_bytes);
        assert_eq!(pen, 99_999);
    }

    #[test]
    fn time_window_enforced() {
        let clock = EngineClock::new(1);
        assert!(clock.check_time_window(1, clock.time()).is_ok());
        // Within 150s — pass
        assert!(clock
            .check_time_window(1, clock.time().saturating_add(10))
            .is_ok());
        // Out of window — fail
        assert!(clock
            .check_time_window(1, clock.time().saturating_add(200))
            .is_err());
        // Wrong boots — fail
        assert!(clock.check_time_window(2, clock.time()).is_err());
    }

    #[test]
    fn boots_bump() {
        let clock = EngineClock::new(0);
        assert_eq!(clock.boots(), 0);
        clock.bump_boots();
        assert_eq!(clock.boots(), 1);
    }
}
