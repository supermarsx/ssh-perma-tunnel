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
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_REMOVED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
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
    // SAFETY: `SetErrorMode` (kernel32.dll; MSDN: SetErrorMode) takes a
    // `UINT` bitmask by value and returns the previous mask. No pointer
    // arguments, no caller-allocated buffers, no aliasing concerns. The
    // mode is a process-wide attribute; calling it from any thread is
    // safe — the documented thread-safety caveat is only about
    // observation ordering, not soundness. Cannot fail (the previous
    // mask is always valid).
    let _prev = unsafe { SetErrorMode(mode) };
    HardeningResult::ok("set_error_mode")
}

fn disable_extension_points() -> HardeningResult {
    // PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY is a single DWORD
    // bitfield. Bit 0 = DisableExtensionPoints. Remaining bits reserved.
    let policy: u32 = 0x0000_0001;
    // SAFETY: `SetProcessMitigationPolicy` (kernel32.dll; MSDN:
    // SetProcessMitigationPolicy) reads `dwlength` bytes from `lpBuffer`
    // and interprets them as the policy struct selected by the first
    // parameter. Per MSDN, the
    // `PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY` struct is a
    // single DWORD bitfield whose bit 0 == DisableExtensionPoints — so a
    // `u32` (4 bytes) with bit 0 set is an exact bit-compatible payload.
    // `policy` is on our stack and outlives the call; we pass its
    // address via `addr_of!` (avoiding any &T -> *const T provenance
    // surprises). The kernel does not retain the pointer. No aliasing
    // (no other reference exists), no thread-safety concerns (process-
    // wide, atomic).
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
            HardeningResult::err("mitigation.extension_point_disable", short_winerr(&e))
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
    // SAFETY: `SetProcessMitigationPolicy` (MSDN: same). Per MSDN the
    // `PROCESS_MITIGATION_DYNAMIC_CODE_POLICY` struct is a DWORD bitfield
    // with bit 0 = ProhibitDynamicCode; a `u32` with bit 0 set is the
    // exact bit-compatible payload. `policy` lives on the stack for the
    // duration of the call; `addr_of!` yields a valid `*const u32`; the
    // kernel reads `size_of::<u32>()` bytes and does not retain the
    // pointer. Process-wide, no aliasing, no thread-safety hazards.
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
    // SAFETY: `OpenProcessToken` (advapi32.dll; MSDN: OpenProcessToken).
    // `GetCurrentProcess()` returns the (-1) pseudo-handle which is
    // always valid and need not be closed. The third parameter is an
    // out-param: the function writes a new HANDLE into `*token`. `token`
    // is a properly-aligned stack local of type `HANDLE` whose storage
    // outlives the call. We use `addr_of_mut!` to obtain `*mut HANDLE`
    // without forming an intermediate `&mut`. On success the handle is
    // owned by us and must be closed exactly once via `CloseHandle` —
    // we do so on every exit path below.
    let opened = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            std::ptr::addr_of_mut!(token),
        )
    };
    if opened.is_err() {
        // SAFETY: `GetLastError` (MSDN: GetLastError) reads thread-local
        // storage maintained by the OS for the calling thread. No
        // pointers, no parameters, cannot fail. The value is stale-safe
        // because we read it immediately after the failed call above
        // with no intervening Win32 API.
        let code = unsafe { GetLastError().0 } as i32;
        let e = std::io::Error::from_raw_os_error(code);
        warn!(error = %e, "OpenProcessToken failed");
        return HardeningResult::err("token.drop_se_debug_privilege", short_io(&e));
    }

    let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
    let mut luid = LUID::default();
    // SAFETY: `LookupPrivilegeValueW` (advapi32.dll; MSDN:
    // LookupPrivilegeValueW). `lpSystemName = NULL` requests the local
    // system. `lpName` must be a NUL-terminated wide string; `priv_name`
    // is owned by this stack frame, contains the explicit `\0`
    // terminator, and outlives the call — its `.as_ptr()` is a valid
    // `*const u16`. `lpLuid` is an out-parameter; `&mut luid` (taken via
    // `addr_of_mut!`) is a properly-aligned stack location owned by us.
    // The kernel writes a LUID on success and does not retain any
    // pointer.
    let look = unsafe {
        LookupPrivilegeValueW(
            PCWSTR::null(),
            PCWSTR::from_raw(priv_name.as_ptr()),
            std::ptr::addr_of_mut!(luid),
        )
    };
    if look.is_err() {
        // SAFETY: `CloseHandle` (MSDN: CloseHandle). `token` was
        // successfully returned by `OpenProcessToken` above and has not
        // been closed on any other path; we close it exactly once here
        // before early-returning. After this call `token` must not be
        // used.
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
    // SAFETY: `AdjustTokenPrivileges` (advapi32.dll; MSDN:
    // AdjustTokenPrivileges). `token` is a live handle opened above with
    // `TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY`. `DisableAllPrivileges =
    // false`. `NewState` is `&mut tp`, a properly-initialised
    // `TOKEN_PRIVILEGES` with `PrivilegeCount = 1` and a single
    // `LUID_AND_ATTRIBUTES` whose `Luid` was populated by the
    // immediately-preceding `LookupPrivilegeValueW`; the kernel reads
    // exactly `PrivilegeCount` entries. `BufferLength = 0` and
    // `PreviousState = None` since we do not care about the previous
    // state; per MSDN passing 0/NULL together is valid. `ReturnLength`
    // may then be `None` as well. The kernel does not retain any of our
    // pointers.
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
            // SAFETY: `GetLastError` reads thread-local OS storage; no
            // arguments, no pointers, cannot fail. Read immediately
            // after the call above with no intervening Win32 API, so
            // the value is the one set by `AdjustTokenPrivileges`.
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
    // SAFETY: `CloseHandle` (MSDN: CloseHandle). `token` was returned
    // by `OpenProcessToken` above and reaches this line only via paths
    // that did not previously close it. We close it exactly once here.
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
        use windows::Win32::Security::{GetTokenInformation, TokenPrivileges, TOKEN_PRIVILEGES};
        const SE_PRIVILEGE_ENABLED: u32 = 0x2;

        let _ = crate::harden();

        let mut token: HANDLE = HANDLE::default();
        // SAFETY: `OpenProcessToken` with `GetCurrentProcess()` pseudo-
        // handle (always valid, never closed by us) and `TOKEN_QUERY`
        // access. Third argument is `*mut HANDLE` taken via
        // `addr_of_mut!` from a stack-local that outlives the call;
        // kernel writes the new HANDLE there on success. If success we
        // own it and close it exactly once below.
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
        // SAFETY: `GetTokenInformation` (MSDN). Probe call: `TokenInformation
        // = None`, `TokenInformationLength = 0`. Per MSDN this is the
        // documented size-probe form which sets ERROR_INSUFFICIENT_BUFFER
        // and writes the required byte count into `ReturnLength`. The
        // out-pointer `&mut needed` is a properly-aligned stack u32
        // owned by us. The kernel does not retain any pointer.
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
            // SAFETY: `CloseHandle` on a token returned by
            // `OpenProcessToken` above; closed exactly once on this
            // early-return path.
            let _ = unsafe { CloseHandle(token) };
            return;
        }

        let mut buf = vec![0u8; needed as usize];
        // SAFETY: `GetTokenInformation` second invocation. `buf` is a
        // Vec<u8> of length exactly `needed`; `as_mut_ptr()` yields a
        // valid `*mut u8` whose write-region is `needed` bytes and
        // outlives the call. We cast to `*mut c_void` to match the FFI
        // signature, and pass `needed` for both the buffer length and
        // the ReturnLength out-pointer (kernel will overwrite the
        // latter). No aliasing: `buf` is uniquely owned by this frame.
        let r = unsafe {
            GetTokenInformation(
                token,
                TokenPrivileges,
                Some(buf.as_mut_ptr().cast()),
                needed,
                std::ptr::addr_of_mut!(needed),
            )
        };
        // SAFETY: `CloseHandle` on a token returned by
        // `OpenProcessToken`; closed exactly once at this point. The
        // function does not use `token` again after this line.
        let _ = unsafe { CloseHandle(token) };
        if r.is_err() {
            return;
        }

        // SAFETY: The preceding successful `GetTokenInformation(
        // TokenPrivileges, …)` call wrote a valid `TOKEN_PRIVILEGES`
        // header at `buf.as_ptr()`. `buf` is at least `size_of::<
        // TOKEN_PRIVILEGES>()` bytes (the kernel reported `needed` and
        // we allocated `needed`). `buf` is owned and not mutated for
        // the lifetime of `tp`, so the borrow is exclusive enough for a
        // shared reference. Alignment: `Vec<u8>::as_ptr()` returns an
        // 8-byte-aligned pointer in practice; `TOKEN_PRIVILEGES` is
        // 4-byte-aligned (DWORDs only), so the cast is alignment-safe
        // on all Windows targets.
        let tp: &TOKEN_PRIVILEGES = unsafe { &*buf.as_ptr().cast() };
        let count = tp.PrivilegeCount as usize;
        // SAFETY: Per MSDN, on success `GetTokenInformation` writes
        // exactly `PrivilegeCount` `LUID_AND_ATTRIBUTES` entries after
        // the header. `buf` is sized to `needed` which includes those
        // entries, so the slice covers initialised memory owned by us
        // and not aliased elsewhere. The lifetime is bound by `buf`.
        let arr = unsafe { std::slice::from_raw_parts(tp.Privileges.as_ptr(), count) };

        let priv_name: Vec<u16> = "SeDebugPrivilege\0".encode_utf16().collect();
        let mut want = LUID::default();
        // SAFETY: `LookupPrivilegeValueW`. `lpSystemName = NULL` -> local
        // system. `priv_name` is owned by this stack frame and contains
        // an explicit `\0` terminator, so `priv_name.as_ptr()` is a
        // valid NUL-terminated `*const u16`. `&mut want` (via
        // `addr_of_mut!`) is a stack-local `LUID` out-parameter the
        // kernel writes on success.
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
