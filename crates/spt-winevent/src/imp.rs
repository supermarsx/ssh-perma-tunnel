//! Windows-only implementation of Event Log source registration and write.
//!
//! ## t8-D2 unsafe audit
//!
//! This module originally held 9 `unsafe` blocks, all wrapping FFI:
//!
//! 1. **2 buffer-encoding casts** (`Vec<u16>` → `&[u8]` and `&u32` → `&[u8]`)
//!    used to feed `RegSetValueExW`'s `Some(&[u8])` argument. Replaced with
//!    safe [`zerocopy::IntoBytes`] calls — `u16::slice_as_bytes(&v)` and
//!    `value.as_bytes()`. The `IntoBytes` impl on `u16`/`u32` is sound by
//!    construction (POD primitives).
//! 2. **7 pure FFI calls** to `RegCreateKeyExW`, `RegSetValueExW`,
//!    `RegCloseKey`, `RegDeleteTreeW`, `RegisterEventSourceW`, `ReportEventW`,
//!    `DeregisterEventSource`. Each carries an inline `// SAFETY:` comment
//!    documenting (a) the lifetime/validity of the pointers, (b) the
//!    nullability/return-code contract, and (c) why a Rust-level invariant
//!    cannot be violated by the call.
//!
//! Net result: 9 → 7 unsafe blocks, all documented for
//! `clippy::undocumented_unsafe_blocks -D warnings`.

use std::path::Path;

use spt_core::error::{Error, Result};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{ERROR_SUCCESS, HANDLE, WIN32_ERROR};
use windows::Win32::System::EventLog::{
    DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
    EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE, REPORT_EVENT_TYPE,
};
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE,
    KEY_WRITE, REG_DWORD, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use zerocopy::IntoBytes;

use crate::{EventLogBackend, Level};

const SUBKEY_PREFIX: &str = r"SYSTEM\CurrentControlSet\Services\EventLog";

/// Real Win32 backend that calls `RegCreateKeyExW`, `RegisterEventSourceW`,
/// `ReportEventW`, etc.
///
/// Default backend on Windows targets. Holds no state.
pub(crate) struct WindowsEventLogBackend;

impl EventLogBackend for WindowsEventLogBackend {
    fn register_source(&self, name: &str, channel: &str, message_dll: Option<&Path>) -> Result<()> {
        register_source(name, channel, message_dll)
    }

    fn unregister_source(&self, name: &str, channel: &str) -> Result<()> {
        unregister_source(name, channel)
    }

    fn report_event(&self, name: &str, level: Level, event_id: u32, message: &str) -> Result<()> {
        report_event(name, level, event_id, message)
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn err_from(code: WIN32_ERROR, ctx: &str) -> Error {
    Error::WindowsEventLogFailed(format!("{ctx}: win32 error {}", code.0))
}

pub(crate) fn register_source(name: &str, channel: &str, message_dll: Option<&Path>) -> Result<()> {
    let path = format!("{SUBKEY_PREFIX}\\{channel}\\{name}");
    let path_w = wide(&path);
    let mut hkey = HKEY::default();

    // SAFETY: `path_w` is a NUL-terminated UTF-16 buffer owned by this stack
    // frame and outlives the FFI call. `&mut hkey` is a unique mutable pointer
    // into local storage. `RegCreateKeyExW` will only write through `hkey` and
    // the optional disposition arg (we pass `None` for the latter). The return
    // value is checked against `ERROR_SUCCESS` immediately below — on failure
    // the `HKEY` is not used. No Rust aliasing or initialisation invariant can
    // be violated by this call.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &raw mut hkey, // 1.88 lint: implicit raw-pointer borrow
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(err_from(rc, "RegCreateKeyExW"));
    }

    let result: Result<()> = (|| {
        if let Some(p) = message_dll {
            let dll = wide(&p.display().to_string());
            // t8-D2 zerocopy replacement (was: `unsafe { slice::from_raw_parts(
            // dll.as_ptr().cast::<u8>(), dll.len() * size_of::<u16>()) }`).
            // `<[u16] as IntoBytes>::as_bytes` is safe by construction: `u16`
            // is a POD primitive with no padding and no invalid bit patterns,
            // and the returned `&[u8]` borrow is bounded by `dll`'s lifetime.
            let bytes = dll.as_slice().as_bytes();
            let name_w = wide("EventMessageFile");
            // SAFETY: `hkey` was just successfully opened via
            // `RegCreateKeyExW`. `name_w` is NUL-terminated UTF-16 owned by
            // this stack frame. `bytes` is a `&[u8]` view onto `dll` (also
            // owned here) — `RegSetValueExW` copies into the registry
            // synchronously, so no dangling-pointer hazard exists on return.
            let rc =
                unsafe { RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_SZ, Some(bytes)) };
            if rc != ERROR_SUCCESS {
                return Err(err_from(rc, "RegSetValueExW(EventMessageFile)"));
            }
        }
        // TypesSupported = info | warning | error
        let supported: u32 = 0x07;
        let name_w = wide("TypesSupported");
        // t8-D2 zerocopy replacement (was: `unsafe { slice::from_raw_parts(
        // addr_of!(supported).cast::<u8>(), size_of::<u32>()) }`).
        // `u32: IntoBytes` is sound; the borrow is local to this scope.
        let supported_bytes = supported.as_bytes();
        // SAFETY: same invariants as the `EventMessageFile` write above —
        // `hkey` is live, `name_w` is a NUL-terminated UTF-16 buffer in scope,
        // and the byte payload is copied synchronously into the registry.
        let rc = unsafe {
            RegSetValueExW(
                hkey,
                PCWSTR(name_w.as_ptr()),
                0,
                REG_DWORD,
                Some(supported_bytes),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(err_from(rc, "RegSetValueExW(TypesSupported)"));
        }
        Ok(())
    })();

    // SAFETY: `hkey` was opened by `RegCreateKeyExW` above and is owned by
    // this stack frame. No further use occurs after the close, so the
    // double-free / use-after-close hazards are precluded. Discard the return
    // value — close failure is not actionable here (the registry value was
    // either set or surfaced as an error in `result`).
    unsafe {
        let _ = RegCloseKey(hkey);
    }
    result
}

pub(crate) fn unregister_source(name: &str, channel: &str) -> Result<()> {
    let path = format!("{SUBKEY_PREFIX}\\{channel}\\{name}");
    let path_w = wide(&path);
    // SAFETY: `path_w` is a NUL-terminated UTF-16 buffer owned by this stack
    // frame and outlives the FFI call. `HKEY_LOCAL_MACHINE` is a Win32-defined
    // predefined-key constant, always valid. The return code is checked
    // against `ERROR_SUCCESS`.
    let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr())) };
    if rc != ERROR_SUCCESS {
        return Err(err_from(rc, "RegDeleteTreeW"));
    }
    Ok(())
}

pub(crate) fn report_event(name: &str, level: Level, event_id: u32, message: &str) -> Result<()> {
    let name_w = wide(name);
    // SAFETY: `name_w` is a NUL-terminated UTF-16 buffer owned by this stack
    // frame; `PCWSTR::null()` passes the local-machine sentinel for the UNC
    // server-name argument. `RegisterEventSourceW` either returns a valid
    // event-source handle or an error; we check the result + `is_invalid()`
    // below before any further FFI use.
    let handle = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(name_w.as_ptr())) }
        .map_err(|e| Error::WindowsEventLogFailed(format!("RegisterEventSourceW: {e}")))?;

    if handle.is_invalid() {
        return Err(Error::WindowsEventLogFailed(
            "RegisterEventSourceW returned invalid handle".into(),
        ));
    }

    let etype: REPORT_EVENT_TYPE = match level {
        Level::Info => EVENTLOG_INFORMATION_TYPE,
        Level::Warning => EVENTLOG_WARNING_TYPE,
        Level::Error => EVENTLOG_ERROR_TYPE,
    };

    let mut msg_w = wide(message);
    let strings = [PCWSTR(msg_w.as_mut_ptr())];

    // SAFETY: `handle` was just opened by `RegisterEventSourceW` and is live
    // for the duration of this scope (closed by `DeregisterEventSource`
    // below). `msg_w` is a NUL-terminated UTF-16 buffer owned by this stack
    // frame; `strings` is a stack array of `PCWSTR` references into `msg_w`.
    // `ReportEventW` reads its argument buffer synchronously, so the
    // pointers remain valid for the entire call.
    let r = unsafe {
        ReportEventW(
            HANDLE(handle.0),
            etype,
            0,
            event_id,
            None,
            0,
            Some(&strings),
            None,
        )
    };
    // SAFETY: `handle` is the live event-source handle from `RegisterEventSourceW`
    // above. No further use of `handle` occurs after this close.
    let _ = unsafe { DeregisterEventSource(handle) };
    r.map_err(|e| Error::WindowsEventLogFailed(format!("ReportEventW: {e}")))
}

#[cfg(test)]
mod tests {
    // Live registry / event log tests require admin and stable channel
    // configuration; gated under `--ignored` so they don't run in default CI.
    use super::*;

    #[test]
    #[ignore = "writes to HKLM; requires admin"]
    fn live_register_unregister() {
        register_source("spt-test-source", "Application", None).unwrap();
        unregister_source("spt-test-source", "Application").unwrap();
    }

    #[test]
    #[ignore = "requires Application source registered; admin"]
    fn live_report_info() {
        report_event("spt-test-source", Level::Info, 1, "hello from spt test").unwrap();
    }
}
