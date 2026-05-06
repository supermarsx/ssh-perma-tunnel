//! Windows-only implementation of Event Log source registration and write.

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

use crate::Level;

const SUBKEY_PREFIX: &str = r"SYSTEM\CurrentControlSet\Services\EventLog";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn err_from(code: WIN32_ERROR, ctx: &str) -> Error {
    Error::WindowsEventLogFailed(format!("{ctx}: win32 error {}", code.0))
}

pub(crate) fn register_source(
    name: &str,
    channel: &str,
    message_dll: Option<&Path>,
) -> Result<()> {
    let path = format!("{SUBKEY_PREFIX}\\{channel}\\{name}");
    let path_w = wide(&path);
    let mut hkey = HKEY::default();

    // SAFETY: pointers passed in are valid for the duration of the call.
    let rc = unsafe {
        RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            PCWSTR(path_w.as_ptr()),
            0,
            PCWSTR::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(err_from(rc, "RegCreateKeyExW"));
    }

    let result: Result<()> = (|| {
        if let Some(p) = message_dll {
            let dll = wide(&p.display().to_string());
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    dll.as_ptr().cast::<u8>(),
                    dll.len() * std::mem::size_of::<u16>(),
                )
            };
            let name_w = wide("EventMessageFile");
            let rc = unsafe {
                RegSetValueExW(hkey, PCWSTR(name_w.as_ptr()), 0, REG_SZ, Some(bytes))
            };
            if rc != ERROR_SUCCESS {
                return Err(err_from(rc, "RegSetValueExW(EventMessageFile)"));
            }
        }
        // TypesSupported = info | warning | error
        let supported: u32 = 0x07;
        let name_w = wide("TypesSupported");
        let rc = unsafe {
            RegSetValueExW(
                hkey,
                PCWSTR(name_w.as_ptr()),
                0,
                REG_DWORD,
                Some(std::slice::from_raw_parts(
                    std::ptr::addr_of!(supported).cast::<u8>(),
                    std::mem::size_of::<u32>(),
                )),
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(err_from(rc, "RegSetValueExW(TypesSupported)"));
        }
        Ok(())
    })();

    unsafe {
        let _ = RegCloseKey(hkey);
    }
    result
}

pub(crate) fn unregister_source(name: &str, channel: &str) -> Result<()> {
    let path = format!("{SUBKEY_PREFIX}\\{channel}\\{name}");
    let path_w = wide(&path);
    let rc = unsafe { RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(path_w.as_ptr())) };
    if rc != ERROR_SUCCESS {
        return Err(err_from(rc, "RegDeleteTreeW"));
    }
    Ok(())
}

pub(crate) fn report_event(name: &str, level: Level, event_id: u32, message: &str) -> Result<()> {
    let name_w = wide(name);
    // SAFETY: name_w is valid wide-NUL-terminated; result is checked.
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
