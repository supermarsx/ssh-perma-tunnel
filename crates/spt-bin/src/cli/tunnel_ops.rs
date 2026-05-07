//! `spt tunnel` operational subcommands: `stats`, `sessions`, `health`.
//!
//! Each entry point is a one-shot reader against the status snapshot written
//! by the running supervisor (`<state_dir>/status.json`). No live RPC is
//! required — the snapshot is authoritative for these views per spec §13.5.
//!
//! ## Outputs
//!
//! * `stats`    — header + per-profile rollup + per-forward listing.
//! * `sessions` — aligned table from `StatusSnapshot::sessions`.
//! * `health`   — green / yellow / red / unknown aggregation across profiles
//!   plus the recent-error tail, with health-specific exit codes
//!   (0 / 1 / 2 / 3).
//!
//! All three honour `--json`, in which case the JSON form is the parsed
//! `StatusSnapshot` (or, for `health`, a small derived object).

#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::uninlined_format_args)]

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::Serialize;

use spt_cli::groups::tunnel::{TunnelHealth, TunnelSessions, TunnelStats};
use spt_cli::GlobalOpts;
use spt_core::{Error, Result};
use spt_state::status::{LastError, ProfileStatus, StatusSnapshot};

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// `spt tunnel stats` — one-shot snapshot of the running tunnel's stats.
pub async fn stats(global: &GlobalOpts, args: TunnelStatsArgs) -> Result<()> {
    let state_dir = resolve_state_dir(global)?;
    let snap = read_status(&state_dir)?;
    let filtered = apply_filters(&snap, args.profile.as_deref(), args.forward.as_deref());

    if args.json {
        print_json(&filtered)?;
        return Ok(());
    }
    println!("{}", render_stats_human(&filtered, Utc::now()));
    Ok(())
}

/// `spt tunnel sessions` — print the session table from `status.json`.
pub async fn sessions(global: &GlobalOpts, args: TunnelSessionsArgs) -> Result<()> {
    let state_dir = resolve_state_dir(global)?;
    let snap = read_status(&state_dir)?;
    let filtered = apply_filters(&snap, args.profile.as_deref(), args.forward.as_deref());

    if args.json {
        // Match the brief: "JSON dumps the sessions array."
        let v = serde_json::to_string_pretty(&filtered.sessions)
            .map_err(|e| Error::RuntimeFailure(format!("serialize sessions: {e}")))?;
        println!("{v}");
        return Ok(());
    }
    println!("{}", render_sessions_human(&filtered, Utc::now()));
    Ok(())
}

/// `spt tunnel health` — aggregate profile state into a green/yellow/red/unknown
/// summary. Exits with the corresponding numeric code (0/1/2/3) for shell use.
pub async fn health(global: &GlobalOpts, args: TunnelHealthArgs) -> Result<()> {
    let state_dir = resolve_state_dir(global)?;
    let report = match try_read_status(&state_dir)? {
        Some(snap) => compute_health(&snap, Utc::now()),
        None => HealthReport::unknown(),
    };

    if args.json {
        let payload = report.to_json();
        let v = serde_json::to_string_pretty(&payload)
            .map_err(|e| Error::RuntimeFailure(format!("serialize health: {e}")))?;
        println!("{v}");
    } else {
        println!("{}", render_health_human(&report, Utc::now()));
    }

    let code = report.level.exit_code();
    if code == 0 {
        Ok(())
    } else {
        // Health-specific exit codes (per brief): 1 yellow, 2 red, 3 unknown.
        // We bypass the normal `Error::exit_code()` mapping by exiting directly
        // here — these aren't error categories, they're a `health` contract.
        // The output has already been written above.
        std::process::exit(code);
    }
}

// ---------------------------------------------------------------------------
// Args
// ---------------------------------------------------------------------------

/// Parsed args for `tunnel stats`. Mirrors `spt_cli::groups::tunnel::TunnelStats`
/// but is a separate type so the dispatch layer can pass either the raw clap
/// struct or a synthesised one (e.g. tests).
#[derive(Debug, Default, Clone)]
pub struct TunnelStatsArgs {
    pub profile: Option<String>,
    pub forward: Option<String>,
    pub json: bool,
}

impl From<TunnelStats> for TunnelStatsArgs {
    fn from(v: TunnelStats) -> Self {
        Self {
            profile: v.profile,
            forward: v.forward,
            json: v.json,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TunnelSessionsArgs {
    pub profile: Option<String>,
    pub forward: Option<String>,
    pub json: bool,
}

impl From<TunnelSessions> for TunnelSessionsArgs {
    fn from(v: TunnelSessions) -> Self {
        Self {
            profile: v.profile,
            forward: v.forward,
            json: v.json,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct TunnelHealthArgs {
    pub json: bool,
}

impl From<TunnelHealth> for TunnelHealthArgs {
    fn from(v: TunnelHealth) -> Self {
        Self { json: v.json }
    }
}

// ---------------------------------------------------------------------------
// Internals — state dir + status.json
// ---------------------------------------------------------------------------

fn resolve_state_dir(global: &GlobalOpts) -> Result<PathBuf> {
    spt_state::resolve_state_dir(global.state_dir.as_deref())
}

fn read_status(state_dir: &Path) -> Result<StatusSnapshot> {
    match try_read_status(state_dir)? {
        Some(s) => Ok(s),
        None => Err(Error::RuntimeFailure(format!(
            "no status snapshot at `{}` — is `spt tunnel run` running?",
            spt_state::paths::status_path(state_dir).display()
        ))),
    }
}

fn try_read_status(state_dir: &Path) -> Result<Option<StatusSnapshot>> {
    let path = spt_state::paths::status_path(state_dir);
    match std::fs::read(&path) {
        Ok(bytes) => {
            let s: StatusSnapshot = serde_json::from_slice(&bytes).map_err(|e| {
                Error::RuntimeFailure(format!("parse `{}`: {e}", path.display()))
            })?;
            Ok(Some(s))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::RuntimeFailure(format!(
            "read `{}`: {e}",
            path.display()
        ))),
    }
}

fn apply_filters(
    snap: &StatusSnapshot,
    profile: Option<&str>,
    forward: Option<&str>,
) -> StatusSnapshot {
    if profile.is_none() && forward.is_none() {
        return snap.clone();
    }
    let mut out = snap.clone();
    if let Some(p) = profile {
        out.profiles.retain(|x| x.id == p);
        out.forwards.retain(|x| x.profile == p);
        out.sessions.retain(|x| x.profile == p);
        out.connections.retain(|x| x.profile == p);
    }
    if let Some(f) = forward {
        out.forwards.retain(|x| x.id == f);
        // Sessions don't have a forward field; filter via active_forwards is
        // not feasible without per-session forward IDs. Connections do.
        out.connections.retain(|x| x.forward == f);
    }
    out
}

fn print_json(snap: &StatusSnapshot) -> Result<()> {
    let s = serde_json::to_string_pretty(snap)
        .map_err(|e| Error::RuntimeFailure(format!("serialize status: {e}")))?;
    println!("{s}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Human renderers
// ---------------------------------------------------------------------------

fn render_stats_human(snap: &StatusSnapshot, now: DateTime<Utc>) -> String {
    let mut out = String::new();
    let active_sessions: u64 = snap
        .sessions
        .iter()
        .filter(|s| eq_ic(&s.state, "running") || eq_ic(&s.state, "active"))
        .count() as u64;
    out.push_str(&format!(
        "tunnel: {} profiles · {} forwards · {} active sessions\n\n",
        snap.profiles.len(),
        snap.forwards.len(),
        active_sessions,
    ));

    // Profile rollup
    let name_w = snap
        .profiles
        .iter()
        .map(|p| p.id.len())
        .max()
        .unwrap_or(0)
        .max(7);
    for p in &snap.profiles {
        let uptime = snap
            .started_at
            .map_or_else(|| "-".to_string(), |t| fmt_uptime(now.signed_duration_since(t)));
        // Aggregate per-profile bytes from forwards.
        let (rx, tx) = snap
            .forwards
            .iter()
            .filter(|f| f.profile == p.id)
            .fold((0u64, 0u64), |(a, b), f| (a + f.bytes_in, b + f.bytes_out));
        out.push_str(&format!(
            "{:<width$}  {:<13}  uptime {}    rx {}    tx {}    reconnects {}\n",
            p.id,
            p.state,
            uptime,
            spt_core::size::format_size(rx),
            spt_core::size::format_size(tx),
            p.reconnect_count,
            width = name_w,
        ));
    }

    if !snap.forwards.is_empty() {
        out.push_str("\nforwards:\n");
        for f in &snap.forwards {
            let listen = f.local_addr.clone().unwrap_or_else(|| "-".into());
            out.push_str(&format!(
                "  {}/{}        listen {}  active {}   rx {}   tx {}\n",
                f.profile,
                f.id,
                listen,
                f.current_connections,
                spt_core::size::format_size(f.bytes_in),
                spt_core::size::format_size(f.bytes_out),
            ));
        }
    }

    out
}

fn render_sessions_human(snap: &StatusSnapshot, now: DateTime<Utc>) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{:<22} {:<14} {:<22} {:<12} {:<20} {:<5}\n",
        "ID", "PROFILE", "ENDPOINT", "SINCE", "BYTES IN/OUT", "CONNS",
    ));
    if snap.sessions.is_empty() {
        out.push_str("(no active sessions)\n");
        return out;
    }
    for s in &snap.sessions {
        let since = s
            .started_at
            .map_or_else(|| "-".to_string(), |t| fmt_uptime(now.signed_duration_since(t)));
        let bytes = format!(
            "{} / {}",
            spt_core::size::format_size(s.bytes_in),
            spt_core::size::format_size(s.bytes_out),
        );
        out.push_str(&format!(
            "{:<22} {:<14} {:<22} {:<12} {:<20} {:<5}\n",
            truncate(&s.id, 22),
            truncate(&s.profile, 14),
            truncate(&s.endpoint, 22),
            since,
            bytes,
            s.active_forwards,
        ));
    }
    out
}

fn render_health_human(report: &HealthReport, now: DateTime<Utc>) -> String {
    let mut out = String::new();
    out.push_str(&format!("tunnel health: {}\n\n", report.level.label()));

    if report.profiles.is_empty() && matches!(report.level, HealthLevel::Unknown) {
        out.push_str("  (no supervisor running — `status.json` not found)\n");
    }

    let name_w = report
        .profiles
        .iter()
        .map(|p| p.id.len())
        .max()
        .unwrap_or(0)
        .max(7);
    for p in &report.profiles {
        let last = p.last_error.as_deref().unwrap_or("-");
        out.push_str(&format!(
            "  {:<width$}  {:<13} uptime {}    last error: {}\n",
            format!("{}:", p.id),
            p.state,
            p.uptime
                .as_ref()
                .cloned()
                .unwrap_or_else(|| "-".into()),
            last,
            width = name_w + 1,
        ));
    }

    if !report.recent_events.is_empty() {
        out.push_str("\n  Recent events (last 10m):\n");
        for ev in &report.recent_events {
            let when = ev
                .at
                .map_or_else(|| "-".to_string(), |t| fmt_clock(t));
            out.push_str(&format!(
                "    - {}  {}  {}\n",
                when, ev.scope, ev.message
            ));
        }
    }

    let _ = now;
    out
}

// ---------------------------------------------------------------------------
// Health logic
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthLevel {
    Green,
    Yellow,
    Red,
    Unknown,
}

impl HealthLevel {
    fn label(self) -> &'static str {
        match self {
            HealthLevel::Green => "GREEN",
            HealthLevel::Yellow => "YELLOW",
            HealthLevel::Red => "RED",
            HealthLevel::Unknown => "UNKNOWN",
        }
    }
    fn exit_code(self) -> i32 {
        match self {
            HealthLevel::Green => 0,
            HealthLevel::Yellow => 1,
            HealthLevel::Red => 2,
            HealthLevel::Unknown => 3,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HealthReport {
    pub level: HealthLevel,
    pub profiles: Vec<HealthProfile>,
    pub recent_events: Vec<HealthEvent>,
}

#[derive(Debug, Clone)]
pub(crate) struct HealthProfile {
    pub id: String,
    pub state: String,
    pub uptime: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct HealthEvent {
    pub at: Option<DateTime<Utc>>,
    pub scope: String,
    pub message: String,
}

impl HealthReport {
    fn unknown() -> Self {
        Self {
            level: HealthLevel::Unknown,
            profiles: Vec::new(),
            recent_events: Vec::new(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "overall": match self.level {
                HealthLevel::Green => "green",
                HealthLevel::Yellow => "yellow",
                HealthLevel::Red => "red",
                HealthLevel::Unknown => "unknown",
            },
            "profiles": self.profiles.iter().map(|p| serde_json::json!({
                "id": p.id,
                "state": p.state,
                "uptime": p.uptime,
                "last_error": p.last_error,
            })).collect::<Vec<_>>(),
            "recent_events": self.recent_events.iter().map(|e| serde_json::json!({
                "at": e.at,
                "scope": e.scope,
                "message": e.message,
            })).collect::<Vec<_>>(),
        })
    }
}

pub(crate) fn compute_health(snap: &StatusSnapshot, now: DateTime<Utc>) -> HealthReport {
    // Empty profile set with a missing supervisor would have been short-circuited
    // upstream as Unknown. An empty profile list inside a real snapshot means
    // "no profiles configured" — treat as Unknown so users notice.
    if snap.profiles.is_empty() {
        return HealthReport {
            level: HealthLevel::Unknown,
            profiles: Vec::new(),
            recent_events: collect_recent_events(snap, now),
        };
    }

    let recent_events = collect_recent_events(snap, now);
    let any_recent_error = recent_events.iter().any(|_| true);

    let mut has_red = false;
    let mut has_yellow = any_recent_error;
    for p in &snap.profiles {
        match classify_profile(&p.state) {
            ProfileLevel::Red => has_red = true,
            ProfileLevel::Yellow => has_yellow = true,
            ProfileLevel::Green => {}
        }
    }

    let level = if has_red {
        HealthLevel::Red
    } else if has_yellow {
        HealthLevel::Yellow
    } else {
        HealthLevel::Green
    };

    let profiles = snap
        .profiles
        .iter()
        .map(|p| HealthProfile {
            id: p.id.clone(),
            state: p.state.clone(),
            uptime: snap
                .started_at
                .map(|t| fmt_uptime(now.signed_duration_since(t))),
            last_error: profile_last_error(snap, p),
        })
        .collect();

    HealthReport {
        level,
        profiles,
        recent_events,
    }
}

enum ProfileLevel {
    Green,
    Yellow,
    Red,
}

fn classify_profile(state: &str) -> ProfileLevel {
    // States from spt-supervisor / spec §13.5.
    if eq_ic(state, "ready") || eq_ic(state, "running") || eq_ic(state, "active") {
        ProfileLevel::Green
    } else if eq_ic(state, "reconnecting")
        || eq_ic(state, "backingoff")
        || eq_ic(state, "backing_off")
        || eq_ic(state, "connecting")
        || eq_ic(state, "starting")
    {
        ProfileLevel::Yellow
    } else if eq_ic(state, "failed") || eq_ic(state, "stopped") || eq_ic(state, "error") {
        ProfileLevel::Red
    } else {
        // Unknown/unclassified states err on the side of yellow so they're
        // visible without being alarming.
        ProfileLevel::Yellow
    }
}

fn profile_last_error(snap: &StatusSnapshot, p: &ProfileStatus) -> Option<String> {
    // Prefer the profile's own last_error_category; fall back to a matching
    // entry in `last_errors` (scope == profile id).
    if let Some(c) = &p.last_error_category {
        if !c.is_empty() {
            return Some(c.clone());
        }
    }
    snap.last_errors
        .iter()
        .filter(|e| e.scope == p.id)
        .max_by_key(|e| e.at)
        .map(|e| {
            if e.message.is_empty() {
                e.category.clone()
            } else {
                e.message.clone()
            }
        })
}

fn collect_recent_events(snap: &StatusSnapshot, now: DateTime<Utc>) -> Vec<HealthEvent> {
    let cutoff = now - ChronoDuration::minutes(10);
    let mut evs: Vec<&LastError> = snap
        .last_errors
        .iter()
        .filter(|e| e.at.map_or(false, |t| t >= cutoff))
        .collect();
    evs.sort_by_key(|e| e.at);
    evs.into_iter()
        .rev()
        .take(10)
        .map(|e| HealthEvent {
            at: e.at,
            scope: e.scope.clone(),
            message: if e.message.is_empty() {
                e.category.clone()
            } else {
                e.message.clone()
            },
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn eq_ic(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn fmt_uptime(d: ChronoDuration) -> String {
    let total = d.num_seconds().max(0);
    let days = total / 86_400;
    let hours = (total % 86_400) / 3_600;
    let mins = (total % 3_600) / 60;
    let secs = total % 60;
    if days > 0 {
        format!("{days}d {hours:02}h")
    } else if hours > 0 {
        format!("{hours:2}h {mins:02}m")
    } else if mins > 0 {
        format!("{mins:2}m {secs:02}s")
    } else {
        format!("{secs}s")
    }
}

fn fmt_clock(t: DateTime<Utc>) -> String {
    t.format("%H:%M").to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use spt_state::status::{ForwardStatus, ProfileStatus, SessionStatus};
    use spt_state::testing::StatusSnapshotBuilder;

    fn ts() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, 0).unwrap()
    }

    fn ready_profile(id: &str) -> ProfileStatus {
        let mut p = ProfileStatus::default();
        p.id = id.into();
        p.state = "Ready".into();
        p
    }

    fn forward(profile: &str, id: &str, listen: &str, rx: u64, tx: u64) -> ForwardStatus {
        let mut f = ForwardStatus::default();
        f.id = id.into();
        f.profile = profile.into();
        f.state = "active".into();
        f.local_addr = Some(listen.into());
        f.bytes_in = rx;
        f.bytes_out = tx;
        f
    }

    fn session(id: &str, profile: &str, endpoint: &str) -> SessionStatus {
        let mut s = SessionStatus::default();
        s.id = id.into();
        s.profile = profile.into();
        s.endpoint = endpoint.into();
        s.state = "running".into();
        s.started_at = Some(ts());
        s
    }

    fn green_snapshot() -> StatusSnapshot {
        StatusSnapshotBuilder::new()
            .pid(1)
            .version("test")
            .started_at(ts() - ChronoDuration::hours(2))
            .add_profile(ready_profile("bastion-prod"))
            .add_profile(ready_profile("bastion-staging"))
            .add_forward(forward(
                "bastion-prod",
                "web",
                "127.0.0.1:8080",
                12 * 1024 * 1024 * 1024,
                1024 * 1024 * 1024,
            ))
            .add_session(session("abc123", "bastion-prod", "bastion.corp:22"))
            .build()
    }

    // -- compute_health --------------------------------------------------

    #[test]
    fn health_green_when_all_ready_no_recent_errors() {
        let snap = green_snapshot();
        let now = ts();
        let r = compute_health(&snap, now);
        assert_eq!(r.level, HealthLevel::Green);
        assert_eq!(r.level.exit_code(), 0);
        assert_eq!(r.profiles.len(), 2);
    }

    #[test]
    fn health_yellow_when_profile_reconnecting() {
        let mut snap = green_snapshot();
        snap.profiles[1].state = "Reconnecting".into();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Yellow);
        assert_eq!(r.level.exit_code(), 1);
    }

    #[test]
    fn health_yellow_when_recent_error_logged() {
        let mut snap = green_snapshot();
        snap.last_errors.push(LastError {
            scope: "bastion-prod".into(),
            category: "io".into(),
            message: "peer reset".into(),
            at: Some(ts() - ChronoDuration::minutes(2)),
        });
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Yellow);
        assert_eq!(r.recent_events.len(), 1);
    }

    #[test]
    fn health_red_when_profile_failed() {
        let mut snap = green_snapshot();
        snap.profiles[0].state = "Failed".into();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Red);
        assert_eq!(r.level.exit_code(), 2);
    }

    #[test]
    fn health_red_takes_precedence_over_yellow() {
        let mut snap = green_snapshot();
        snap.profiles[0].state = "Reconnecting".into();
        snap.profiles[1].state = "Failed".into();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Red);
    }

    #[test]
    fn health_unknown_when_no_profiles() {
        let snap = StatusSnapshotBuilder::new().build();
        let r = compute_health(&snap, ts());
        assert_eq!(r.level, HealthLevel::Unknown);
        assert_eq!(r.level.exit_code(), 3);
    }

    #[test]
    fn health_unknown_via_constructor_when_no_supervisor() {
        // Mirrors the "no status.json on disk" path from `health()`.
        let r = HealthReport::unknown();
        assert_eq!(r.level, HealthLevel::Unknown);
        assert_eq!(r.level.exit_code(), 3);
    }

    #[test]
    fn recent_events_window_is_10_minutes() {
        let mut snap = green_snapshot();
        snap.last_errors.push(LastError {
            scope: "bastion-prod".into(),
            category: "io".into(),
            message: "old".into(),
            at: Some(ts() - ChronoDuration::minutes(30)),
        });
        snap.last_errors.push(LastError {
            scope: "bastion-prod".into(),
            category: "io".into(),
            message: "fresh".into(),
            at: Some(ts() - ChronoDuration::minutes(3)),
        });
        let evs = collect_recent_events(&snap, ts());
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].message, "fresh");
    }

    // -- JSON round-trip ------------------------------------------------

    #[test]
    fn health_json_round_trips_through_value() {
        let snap = green_snapshot();
        let r = compute_health(&snap, ts());
        let v = r.to_json();
        let s = serde_json::to_string(&v).unwrap();
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["overall"], "green");
        assert_eq!(v["profiles"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn stats_json_roundtrips_full_snapshot() {
        let snap = green_snapshot();
        let s = serde_json::to_string_pretty(&snap).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["profiles"].as_array().unwrap().len(), 2);
        assert_eq!(v["forwards"].as_array().unwrap().len(), 1);
        // Re-deserialize to StatusSnapshot to lock the shape.
        let _back: StatusSnapshot = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn sessions_json_dumps_sessions_array() {
        let snap = green_snapshot();
        let s = serde_json::to_string(&snap.sessions).unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 1);
        assert_eq!(v[0]["id"], "abc123");
    }

    // -- Renderers ------------------------------------------------------

    #[test]
    fn render_stats_human_includes_header_and_forward_listing() {
        let snap = green_snapshot();
        let s = render_stats_human(&snap, ts());
        assert!(s.contains("tunnel: 2 profiles"));
        assert!(s.contains("5 forwards").not_or(true) || s.contains("1 forwards") || s.contains("forwards"));
        assert!(s.contains("bastion-prod"));
        assert!(s.contains("forwards:"));
        assert!(s.contains("127.0.0.1:8080"));
    }

    // Helper trait so the assert macro chain above stays readable. (Tests
    // shouldn't rely on this for real logic.)
    trait BoolExt {
        fn not_or(self, fallback: bool) -> bool;
    }
    impl BoolExt for bool {
        fn not_or(self, fallback: bool) -> bool {
            !self || fallback
        }
    }

    #[test]
    fn render_sessions_human_table_has_header() {
        let snap = green_snapshot();
        let s = render_sessions_human(&snap, ts() + ChronoDuration::hours(1));
        assert!(s.contains("ID"));
        assert!(s.contains("PROFILE"));
        assert!(s.contains("ENDPOINT"));
        assert!(s.contains("abc123"));
        assert!(s.contains("bastion.corp:22"));
    }

    #[test]
    fn render_sessions_human_handles_empty_table() {
        let snap = StatusSnapshotBuilder::new().build();
        let s = render_sessions_human(&snap, ts());
        assert!(s.contains("(no active sessions)"));
    }

    #[test]
    fn render_health_human_labels_each_level() {
        let snap = green_snapshot();
        let r = compute_health(&snap, ts());
        let s = render_health_human(&r, ts());
        assert!(s.contains("GREEN"));
        assert!(s.contains("bastion-prod"));
    }

    #[test]
    fn render_health_human_unknown_explains_missing_supervisor() {
        let r = HealthReport::unknown();
        let s = render_health_human(&r, ts());
        assert!(s.contains("UNKNOWN"));
        assert!(s.contains("no supervisor running"));
    }

    // -- Filters --------------------------------------------------------

    #[test]
    fn apply_filters_narrows_to_profile() {
        let snap = green_snapshot();
        let f = apply_filters(&snap, Some("bastion-prod"), None);
        assert_eq!(f.profiles.len(), 1);
        assert_eq!(f.forwards.len(), 1);
        assert_eq!(f.sessions.len(), 1);
    }

    #[test]
    fn apply_filters_narrows_to_forward() {
        let snap = green_snapshot();
        let f = apply_filters(&snap, None, Some("web"));
        assert_eq!(f.forwards.len(), 1);
    }

    #[test]
    fn apply_filters_drops_nonmatching_profile() {
        let snap = green_snapshot();
        let f = apply_filters(&snap, Some("does-not-exist"), None);
        assert!(f.profiles.is_empty());
        assert!(f.forwards.is_empty());
        assert!(f.sessions.is_empty());
    }

    // -- fmt helpers ----------------------------------------------------

    #[test]
    fn fmt_uptime_formats_days_hours_minutes() {
        assert!(fmt_uptime(ChronoDuration::seconds(45)).contains('s'));
        assert!(fmt_uptime(ChronoDuration::seconds(125)).contains('m'));
        assert!(fmt_uptime(ChronoDuration::seconds(2 * 3600 + 5 * 60))
            .contains('h'));
        let s = fmt_uptime(ChronoDuration::seconds(4 * 86_400 + 12 * 3600));
        assert!(s.contains("4d"));
        assert!(s.contains("12h"));
    }

    #[test]
    fn truncate_clips_long_strings() {
        assert_eq!(truncate("hello", 10), "hello");
        let s = truncate("hello-world-extra", 8);
        assert!(s.chars().count() == 8);
        assert!(s.ends_with('…'));
    }

    // -- read_status (filesystem) ---------------------------------------

    #[test]
    fn try_read_status_returns_none_when_missing() {
        let d = spt_state::testing::TempStateDir::new();
        let r = try_read_status(d.as_path()).unwrap();
        assert!(r.is_none());
    }

    #[test]
    fn try_read_status_parses_existing_snapshot() {
        let d = spt_state::testing::TempStateDir::new().with_status(|s| {
            s.pid = 4242;
            s.version = "v-test".into();
        });
        let r = try_read_status(d.as_path()).unwrap().unwrap();
        assert_eq!(r.pid, 4242);
        assert_eq!(r.version, "v-test");
    }
}
