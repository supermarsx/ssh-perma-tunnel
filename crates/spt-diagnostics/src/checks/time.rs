//! System time + clock-drift checks.
//!
//! * `time.utc_now`   — records the current UTC timestamp as evidence so a
//!   bundle can be cross-referenced with logs. Always `Pass`.
//! * `time.sanity`    — a hermetic, offline sanity check: the wall clock must
//!   be after a hardcoded build-era floor (2024-01-01) and not absurdly far in
//!   the future. Catches an unset / battery-dead RTC without any network.
//! * `time.ntp_drift` — E8-F8: previously a permanent `Skipped` stub. Now a
//!   real SNTP (RFC 4330) drift probe against a configurable server. It is
//!   **opt-in** (`probe_ntp = false` by default) so `cargo test` and offline
//!   CI never touch the network; when enabled it degrades gracefully — an
//!   unreachable server yields `Skipped` (clearly labelled experimental /
//!   offline), never `Fail`, so the check can never flake a healthy host.

use async_trait::async_trait;
use std::time::Duration;

use crate::check::{Check, Severity, Status};
use crate::framework::{Diagnostic, DiagnosticContext};

/// Drift over this threshold is reported as a `Warn`.
const DRIFT_WARN_THRESHOLD: Duration = Duration::from_secs(2);
/// SNTP round-trip budget.
const NTP_BUDGET: Duration = Duration::from_secs(3);
/// NTP epoch (1900-01-01) to Unix epoch (1970-01-01) offset, in seconds.
const NTP_UNIX_OFFSET: u64 = 2_208_988_800;

/// System time / clock-drift diagnostic.
#[derive(Debug)]
pub struct TimeDiagnostic {
    /// When true, perform a live SNTP query against [`Self::ntp_server`].
    /// Defaults to **false** so the diagnostic stays hermetic and offline-safe;
    /// the dispatcher opts in (e.g. behind `--probe`) when a network check is
    /// wanted.
    pub probe_ntp: bool,
    /// SNTP server (`host:port`). Defaults to `pool.ntp.org:123`.
    pub ntp_server: String,
}

impl Default for TimeDiagnostic {
    fn default() -> Self {
        Self {
            probe_ntp: false,
            ntp_server: "pool.ntp.org:123".to_string(),
        }
    }
}

#[async_trait]
impl Diagnostic for TimeDiagnostic {
    fn group(&self) -> &'static str {
        "time"
    }
    async fn run(&self, _ctx: &DiagnosticContext) -> Vec<Check> {
        let now = chrono::Utc::now();
        let mut out = vec![Check::new("time.utc_now", Severity::Info, Status::Pass)
            .with_evidence(format!("utc = {}", now.to_rfc3339()))];

        // Hermetic sanity floor/ceiling: an unset RTC usually reports 1970 or a
        // far-future date. Build-era floor catches the common "dead battery"
        // case without any network access.
        let year = now.format("%Y").to_string();
        let yr: i32 = year.parse().unwrap_or(0);
        if yr < 2024 {
            out.push(
                Check::new("time.sanity", Severity::High, Status::Fail)
                    .with_evidence(format!("system clock reports {yr}, before the 2024 build floor"))
                    .with_remediation("the RTC is likely unset; sync time (NTP) and check the battery"),
            );
        } else if yr > 2100 {
            out.push(
                Check::new("time.sanity", Severity::High, Status::Fail)
                    .with_evidence(format!("system clock reports {yr}, implausibly far in the future"))
                    .with_remediation("correct the system clock; sync time via NTP"),
            );
        } else {
            out.push(
                Check::new("time.sanity", Severity::Info, Status::Pass)
                    .with_evidence(format!("wall-clock year {yr} is within plausible range")),
            );
        }

        out.push(self.ntp_drift_check().await);
        out
    }
}

impl TimeDiagnostic {
    async fn ntp_drift_check(&self) -> Check {
        if !self.probe_ntp {
            return Check::new("time.ntp_drift", Severity::Low, Status::Skipped)
                .with_evidence(
                    "SNTP drift probe disabled (experimental; enable with the live probe flag)",
                )
                .with_remediation("run `chronyc tracking` / `w32tm /query /status` for local drift");
        }

        match query_sntp(&self.ntp_server, NTP_BUDGET).await {
            Ok(drift) => {
                let abs_ms = drift.num_milliseconds().unsigned_abs();
                let secs = abs_ms as f64 / 1000.0;
                if abs_ms <= DRIFT_WARN_THRESHOLD.as_millis() as u64 {
                    Check::new("time.ntp_drift", Severity::Info, Status::Pass).with_evidence(
                        format!("clock within {secs:.3}s of `{}`", self.ntp_server),
                    )
                } else {
                    Check::new("time.ntp_drift", Severity::Medium, Status::Warn)
                        .with_evidence(format!(
                            "clock drifts {secs:.3}s from `{}`",
                            self.ntp_server
                        ))
                        .with_remediation("enable/repair time synchronisation (NTP/chrony/w32time)")
                }
            }
            // Offline / unreachable / malformed: degrade to Skipped, never Fail,
            // so an air-gapped host running diagnostics is not penalised.
            Err(e) => Check::new("time.ntp_drift", Severity::Low, Status::Skipped)
                .with_evidence(format!("SNTP probe of `{}` unavailable: {e}", self.ntp_server))
                .with_remediation("network may be offline; verify local time sync manually"),
        }
    }
}

/// Minimal SNTP (RFC 4330) client. Sends a mode-3 (client) request and reads
/// the server's transmit timestamp, returning the signed offset
/// `server_time - local_time`. Best-effort and connectionless; any IO or
/// parse error propagates as `Err` for the caller to map to `Skipped`.
async fn query_sntp(server: &str, budget: Duration) -> Result<chrono::Duration, String> {
    use tokio::net::{lookup_host, UdpSocket};
    use tokio::time::timeout;

    let mut addrs = timeout(budget, lookup_host(server))
        .await
        .map_err(|_| "dns timeout".to_string())?
        .map_err(|e| format!("dns: {e}"))?;
    let target = addrs
        .next()
        .ok_or_else(|| "no addresses resolved".to_string())?;

    let bind = if target.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind)
        .await
        .map_err(|e| format!("bind: {e}"))?;
    sock.connect(target)
        .await
        .map_err(|e| format!("connect: {e}"))?;

    // RFC 4330: 48-byte packet, first byte LI=0, VN=4, Mode=3 (0b00_100_011).
    let mut req = [0u8; 48];
    req[0] = 0x23;
    let sent_at = chrono::Utc::now();
    timeout(budget, sock.send(&req))
        .await
        .map_err(|_| "send timeout".to_string())?
        .map_err(|e| format!("send: {e}"))?;

    let mut resp = [0u8; 48];
    let n = timeout(budget, sock.recv(&mut resp))
        .await
        .map_err(|_| "recv timeout".to_string())?
        .map_err(|e| format!("recv: {e}"))?;
    let recv_at = chrono::Utc::now();
    if n < 48 {
        return Err(format!("short response ({n} bytes)"));
    }

    // Transmit Timestamp is bytes 40..48: 32-bit seconds + 32-bit fraction,
    // both big-endian, in the NTP (1900) epoch.
    let secs = u32::from_be_bytes([resp[40], resp[41], resp[42], resp[43]]);
    let frac = u32::from_be_bytes([resp[44], resp[45], resp[46], resp[47]]);
    if secs == 0 {
        return Err("server returned a zero transmit timestamp".to_string());
    }
    let unix_secs = i64::from(secs) - NTP_UNIX_OFFSET as i64;
    let nanos = ((u64::from(frac) * 1_000_000_000) >> 32) as u32;
    let server_time = chrono::DateTime::from_timestamp(unix_secs, nanos)
        .ok_or_else(|| "server timestamp out of range".to_string())?;

    // Compare the server transmit time to the local clock at the midpoint of
    // our send/recv window to net out (roughly) the round-trip latency.
    let midpoint = sent_at + (recv_at - sent_at) / 2;
    Ok(server_time - midpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn time_check_emits_now_sanity_and_drift() {
        let r = TimeDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].id, "time.utc_now");
        assert_eq!(r[0].status, Status::Pass);
    }

    #[tokio::test]
    async fn sanity_passes_on_real_clock() {
        // CI runs in the present, so the sanity floor must Pass.
        let r = TimeDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        let sanity = r.iter().find(|c| c.id == "time.sanity").unwrap();
        assert_eq!(sanity.status, Status::Pass, "{sanity:?}");
    }

    // E8-F8: with the probe disabled (the default), the drift check is a
    // clearly-labelled experimental Skipped — never Fail, hermetic.
    #[tokio::test]
    async fn ntp_drift_skipped_and_labelled_when_probe_disabled() {
        let r = TimeDiagnostic::default()
            .run(&DiagnosticContext::default())
            .await;
        let drift = r.iter().find(|c| c.id == "time.ntp_drift").unwrap();
        assert_eq!(drift.status, Status::Skipped);
        let ev = drift.evidence.join(" ");
        assert!(ev.contains("experimental") || ev.contains("disabled"), "{ev}");
    }

    // E8-F8: when enabled but the server is unreachable (RFC 5737 TEST-NET-1,
    // guaranteed non-routable), the drift check degrades to Skipped, not Fail
    // — offline hosts must not flake.
    #[tokio::test]
    async fn ntp_drift_offline_degrades_to_skipped() {
        let d = TimeDiagnostic {
            probe_ntp: true,
            // 192.0.2.0/24 is reserved for documentation and is unroutable.
            ntp_server: "192.0.2.1:123".to_string(),
        };
        let r = d.run(&DiagnosticContext::default()).await;
        let drift = r.iter().find(|c| c.id == "time.ntp_drift").unwrap();
        assert_ne!(drift.status, Status::Fail, "{drift:?}");
        assert!(matches!(
            drift.status,
            Status::Skipped | Status::Warn | Status::Pass
        ));
    }

    #[test]
    fn group_is_time() {
        assert_eq!(TimeDiagnostic::default().group(), "time");
    }
}
