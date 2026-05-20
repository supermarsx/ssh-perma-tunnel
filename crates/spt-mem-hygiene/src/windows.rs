//! Windows-specific hardening primitives.
//!
//! * `SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX)` —
//!   suppress the "abort/retry/ignore" and Windows Error Reporting fault
//!   dialogs that can hang a service or expose register state in
//!   screenshots.
//!
//! * `SetProcessMitigationPolicy(ProcessExtensionPointDisablePolicy)` —
//!   block legacy `AppInit` DLL injection.
//! * `SetProcessMitigationPolicy(ProcessDynamicCodePolicy)` — block
//!   ad-hoc RWX page creation (`VirtualProtect(PAGE_EXECUTE_*)`).
//!
//! * `AdjustTokenPrivileges` — drop `SeDebugPrivilege` from the process
//!   token. Without this privilege a process cannot open arbitrary other
//!   processes for cross-process memory read, even if a future bug grants
//!   it administrative context.
//!
//! ### Note on bindings
//!
//! `windows-rs 0.58` does not expose
//! `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY` /
//! `PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY` directly. Both
//! structures are simple bitfields whose first DWORD carries a single bit
//! we care about, so we pass a `u32` buffer with the correct bit set and
//! the correct length to `SetProcessMitigationPolicy`. The other reserved
//! bits remain zero.
//!
//! All FFI calls are wrapped in tight `unsafe` blocks with `// SAFETY:`
//! justifications. Failures of any one call are reported via
//! [`HardeningResult`] but never panic.

use crate::{HardeningReport, HardeningResult};
use tracing::warn;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES,
    SE_PRIVILEGE_REMOVED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcessToken, ProcessDynamicCodePolicy,
    ProcessExtensionPointDisablePolicy, SetProcessMitigationPolicy,
};

use windows::Win32::System::Diagnostics::Debug::{
    SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX, THREAD_ERROR_MODE,
};

pub(crate) fn harden_into(report: &mut HardeningReport) {
    report.push(set_error_mode());
    report.push(disable_extension_points());
    report.push(disable_dynamic_code());
    report.push(drop_se_debug_privilege());
}

fn set_error_mode() -> HardeningResult {
    let mode: THREAD_ERROR_MODE = SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX;
    // SAFETY: `SetErrorMode` is a stateless Win32 API that takes a bitmask
    // by value and returns the previous mask. No memory is dereferenced.
    let _prev = unsafe { SetErrorMode(mode) };
    HardeningResult::ok("set_error_mode")
}

fn disable_extension_points() -> HardeningResult {
    // PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY is a single DWORD
    // bitfield. Bit 0 = DisableExtensionPoints. Remaining bits reserved.
    let policy: u32 = 0x0000_0001;
    // SAFETY: We pass a pointer to a stack-local u32 whose lifetime
    // outlives the call, and the matching size (4). The kernel reads the
    // buffer for `dwlength` bytes and does not retain the pointer.
    let r = unsafe {
        SetProcessMitigationPolicy(
            ProcessExtensionPointDisablePolicy,
            std::ptr::addr_of!(policy).cast::<core::ffi::c_void>(),
            std::mem::size_of::<u32>(),
        )
    };
    match r {
        Ok(()) => HardeningResult::ok("mitigation.extension_point_disable"),
        Err(e) => {
            warn!(error = %e, "SetProcessMitigationPolicy(ExtensionPointDisable) failed");
            HardeningResult::err(
                "mitigation.extension_point_disable",
                short_winerr(&e),
            )
        }
    }
}

fn disable_dynamic_code() -> HardeningResult {
    // PROCESS_MITIGATION_DYNAMIC_CODE_POLICY:
    //   bit 0 = ProhibitDynamicCode
    //   bit 1 = AllowThreadOptOut
    //   bit 2 = AllowRemoteDowngrade
    // We set only bit 0.
    let policy: u32 = 0x0000_0001;
    // SAFETY: pointer to a stack-local u32, matching size; kernel reads
    // and does not retain.
    let r = unsafe {
        SetProcessMitigationPolicy(
            ProcessDynamicCodePolicy,
            std::ptr::addr_of!(policy).cast::<core::ffi::c_void>(),
            std::mem::size_of::<u32>(),
        )
    };
    match r {
        Ok(()) => HardeningResult::ok("mitigation.dynamic_code"),
        Err(e) => {
            warn!(error = %e, "SetProcessMitigationPolicy(DynamicCode) failed");
            HardeningResult::err("mitigation.dynamic_code", short_winerr(&e))
        }
    }
}

fn drop_se_debug_privilege() -> HardeningResult {
    const ERROR_NOT_ALL_ASSIGNED: u32 = 1300;
    let mut token: HANDLE = HANDLE::default();
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle. `OpenProcessToken`
    // writes the handle into `token` on success; `token` is owned local
    // storage with lifetime spanning the call.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            std::ptr::addr_of_mut!(token),
        )
    };
    if opened.is_err() {
        // SAFETY: GetLastError is a stateless thread-local read.
        let code = unsafe { GetLastError().0 } as i32;
        let e = std::io::Error::from_raw_os_error(code);
        warn!(error = %e, "OpenProcessToken failed");
        return HardeningResult::err("token.drop_se_debug_privilege", short_io(&e));
    }

    let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    let mut luid = LUID::default();
    // SAFETY: `priv_name` is NUL-terminated UTF-16, owned for the call;
    // `luid` is a valid out-parameter on our stack.
    let look = unsafe {
        LookupPrivilegeValueW(
            PCWSTR::null(),
            PCWSTR::from_raw(priv_name.as_ptr()),
            std::ptr::addr_of_mut!(luid),
        )
    };
    if look.is_err() {
        // SAFETY: `token` opened above; close exactly once.
        let _ = unsafe { CloseHandle(token) };
        return HardeningResult::skipped(
            "token.drop_se_debug_privilege",
            "SeDebugPrivilege not found on this system",
        );
    }

    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_REMOVED,
        }],
    };
    // SAFETY: valid token handle and valid TOKEN_PRIVILEGES; the previous-
    // state output parameters are explicitly `None`.
    let adj = unsafe {
        AdjustTokenPrivileges(
            token,
            false,
            Some(std::ptr::addr_of_mut!(tp)),
            0,
            None,
            None,
        )
    };
    let outcome = match adj {
        Ok(()) => {
            // AdjustTokenPrivileges returns Ok even when not every entry
            // was adjusted; ERROR_NOT_ALL_ASSIGNED means the privilege was
            // not held — which is exactly the state we want.
            // SAFETY: GetLastError is a stateless thread-local read.
            let last = unsafe { GetLastError().0 };
            if last == 0 || last == ERROR_NOT_ALL_ASSIGNED {
                HardeningResult::ok("token.drop_se_debug_privilege")
            } else {
                let e = std::io::Error::from_raw_os_error(last as i32);
                HardeningResult::err("token.drop_se_debug_privilege", short_io(&e))
            }
        }
        Err(e) => {
            warn!(error = %e, "AdjustTokenPrivileges failed");
            HardeningResult::err("token.drop_se_debug_privilege", short_winerr(&e))
        }
    };
    // SAFETY: token was successfully opened above; safe to close exactly once.
    let _ = unsafe { CloseHandle(token) };
    outcome
}

fn short_winerr(e: &windows::core::Error) -> String {
    let s = e.message();
    if s.is_empty() {
        format!("hresult 0x{:08x}", e.code().0 as u32)
    } else {
        s
    }
}

fn short_io(e: &std::io::Error) -> String {
    let s = e.to_string();
    if let Some(idx) = s.rfind(" (os error") {
        s[..idx].to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_error_mode_is_ok() {
        let r = set_error_mode();
        assert_eq!(r.name, "set_error_mode");
        assert!(r.status.is_ok());
    }

    #[test]
    fn drop_se_debug_does_not_panic() {
        let r = drop_se_debug_privilege();
        assert_eq!(r.name, "token.drop_se_debug_privilege");
        assert!(
            !r.status.is_err(),
            "dropping SeDebugPrivilege should not hard-error in user mode: {:?}",
            r.status
        );
    }

    #[test]
    fn dynamic_code_does_not_panic() {
        let r = disable_dynamic_code();
        assert_eq!(r.name, "mitigation.dynamic_code");
        // On older Windows builds this can fail with INVALID_PARAMETER —
        // we just assert it doesn't panic. Status is consulted to ensure
        // the field is initialised.
        let _ = r.status;
    }

    #[test]
    fn extension_points_does_not_panic() {
        let r = disable_extension_points();
        assert_eq!(r.name, "mitigation.extension_point_disable");
        let _ = r.status;
    }

    /// After `harden()` the process token must NOT contain `SeDebugPrivilege`
    /// in an enabled state.
    #[test]
    fn se_debug_privilege_is_removed_after_harden() {
        use windows::Win32::Security::{
            GetTokenInformation, TokenPrivileges, TOKEN_PRIVILEGES,
        };
        const SE_PRIVILEGE_ENABLED: u32 = 0x2;

        let _ = crate::harden();

        let mut token: HANDLE = HANDLE::default();
        // SAFETY: pseudo-handle; out-parameter on our stack.
        let ok = unsafe {
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                std::ptr::addr_of_mut!(token),
            )
        };
        if ok.is_err() {
            return;
        }

        let mut needed: u32 = 0;
        // SAFETY: with a null buffer GetTokenInformation only writes `needed`.
        let _ = unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                None,
                0,
                std::ptr::addr_of_mut!(needed),
            )
        };
        if needed == 0 {
            // SAFETY: token opened above; close exactly once.
            let _ = unsafe { CloseHandle(token) };
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        // SAFETY: buf has `needed` bytes; we pass that length explicitly.
        let r = unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                Some(buf.as_mut_ptr().cast()),
                needed,
                std::ptr::addr_of_mut!(needed),
            )
        };
        // SAFETY: token opened above; close exactly once.
        let _ = unsafe { CloseHandle(token) };
        if r.is_err() {
            return;
        }

        // SAFETY: kernel wrote a valid TOKEN_PRIVILEGES into buf.
        let tp: &TOKEN_PRIVILEGES = unsafe { &*buf.as_ptr().cast() };
        let count = tp.PrivilegeCount as usize;
        // SAFETY: kernel guarantees Privileges[0..count] is initialised.
        let arr = unsafe {
            std::slice::from_raw_parts(tp.Privileges.as_ptr(), count)
        };

        let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        let mut want = LUID::default();
        // SAFETY: NUL-terminated UTF-16; out-LUID is valid.
        let look = unsafe {
            LookupPrivilegeValueW(
                PCWSTR::null(),
                PCWSTR::from_raw(priv_name.as_ptr()),
                std::ptr::addr_of_mut!(want),
            )
        };
        if look.is_err() {
            return;
        }

        for la in arr {
            if la.Luid.LowPart == want.LowPart && la.Luid.HighPart == want.HighPart {
                let attrs = la.Attributes.0;
                assert_eq!(
                    attrs & SE_PRIVILEGE_ENABLED,
                    0,
                    "SeDebugPrivilege must not be enabled after harden()"
                );
            }
        }
    }
}
