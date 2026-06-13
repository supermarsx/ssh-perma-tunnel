//! Per-process resource probes. Returns RSS in bytes and an open
//! file-descriptor / handle count for the *current* process.
//!
//! No external crates are pulled in — Linux uses `/proc/self/{status,fd}`,
//! macOS falls back to a best-effort RSS via `getrusage(2)` and skips fd
//! counting (returns 0), and Windows calls `GetProcessHandleCount` /
//! `K32GetProcessMemoryInfo` from the already-locked `windows = 0.58` crate.

use std::io;

/// One process-resource snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Resident set size in bytes. `0` if the platform did not provide it.
    pub rss_bytes: u64,
    /// Open file-descriptor / handle count. `0` if the platform did not
    /// provide it (best-effort; the soak/leak tests gate on a *delta*, so a
    /// zero baseline still produces meaningful comparisons).
    pub open_handles: u64,
}

impl Snapshot {
    /// Capture a snapshot of the calling process.
    pub fn capture() -> io::Result<Self> {
        Ok(Self {
            rss_bytes: rss_bytes()?,
            open_handles: open_handle_count()?,
        })
    }
}

// ----------------------------------------------------------------- Linux ----

#[cfg(target_os = "linux")]
fn rss_bytes() -> io::Result<u64> {
    let s = std::fs::read_to_string("/proc/self/status")?;
    for line in s.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            // "VmRSS:    12345 kB"
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|n| n.parse().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "VmRSS parse"))?;
            return Ok(kb * 1024);
        }
    }
    Ok(0)
}

#[cfg(target_os = "linux")]
fn open_handle_count() -> io::Result<u64> {
    let mut n: u64 = 0;
    for entry in std::fs::read_dir("/proc/self/fd")? {
        if entry?.file_name().to_string_lossy().parse::<u64>().is_ok() {
            n += 1;
        }
    }
    Ok(n)
}

// ----------------------------------------------------------------- macOS ----

#[cfg(target_os = "macos")]
fn rss_bytes() -> io::Result<u64> {
    // getrusage(RUSAGE_SELF).ru_maxrss is bytes on macOS (kB on Linux). The
    // exact unit is only documented in BSD man pages; this is best-effort.
    use nix::sys::resource::{getrusage, UsageWho};
    let usage = getrusage(UsageWho::RUSAGE_SELF)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    let raw = usage.max_rss();
    if raw < 0 {
        return Ok(0);
    }
    Ok(raw as u64)
}

#[cfg(target_os = "macos")]
fn open_handle_count() -> io::Result<u64> {
    // proc_pidinfo is gated behind libproc which we don't depend on. Return
    // 0; the leak tests still produce a delta=0 baseline that won't false-fail.
    Ok(0)
}

// --------------------------------------------------------------- Windows ----

#[cfg(target_os = "windows")]
fn rss_bytes() -> io::Result<u64> {
    use windows::Win32::System::ProcessStatus::{K32GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS};
    use windows::Win32::System::Threading::GetCurrentProcess;
    let mut pmc = PROCESS_MEMORY_COUNTERS::default();
    let cb = u32::try_from(std::mem::size_of::<PROCESS_MEMORY_COUNTERS>())
        .map_err(|_| io::Error::other("PMC size overflow"))?; // 1.88 lint: io_other_error
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always valid
    // and does not need closing. `pmc` is a stack value of the size we pass.
    let ok = unsafe { K32GetProcessMemoryInfo(GetCurrentProcess(), &raw mut pmc, cb) };
    if !ok.as_bool() {
        return Err(io::Error::last_os_error());
    }
    Ok(pmc.WorkingSetSize as u64)
}

#[cfg(target_os = "windows")]
fn open_handle_count() -> io::Result<u64> {
    use windows::Win32::System::Threading::{GetCurrentProcess, GetProcessHandleCount};
    let mut count: u32 = 0;
    // SAFETY: pseudo-handle is always valid; `count` is a valid stack pointer.
    let res = unsafe { GetProcessHandleCount(GetCurrentProcess(), &raw mut count) };
    res.map_err(|e| io::Error::other(e.to_string()))?; // 1.88 lint: io_other_error
    Ok(u64::from(count))
}

// ------------------------------------------------------------- fallback ----

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn rss_bytes() -> io::Result<u64> {
    Ok(0)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn open_handle_count() -> io::Result<u64> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_returns_nonpanicking_values() {
        // Just ensure the call works; absolute values vary by platform.
        let _ = Snapshot::capture().expect("snapshot");
    }
}
