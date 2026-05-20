//! Packaging-security smoke tests.
//!
//! These are deliberately minimal: each one is a one-shot
//! `parser-on-disk-file` check. They are not gated behind
//! workspace-locked cargo because the host crate (tests-rs) ships its
//! own `[workspace]` table.
//!
//! Three checks:
//!
//! 1. `seccomp_json_parses` — always runnable (pure `serde_json`).
//! 2. `apparmor_profile_parses` — Linux + `apparmor_parser` on PATH; skip otherwise.
//! 3. `selinux_te_compiles`    — Linux + `checkmodule` on PATH; skip otherwise.

use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::Command;

fn artifact_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR == packaging/security/tests-rs/
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop(); // -> packaging/security/
    p
}

#[test]
fn seccomp_json_parses() {
    let path = artifact_dir().join("seccomp").join("spt.json");
    let bytes = std::fs::read(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

    // Structural sanity: required OCI-runtime-style top-level keys.
    let obj = v.as_object().expect("top-level object");
    assert_eq!(
        obj.get("defaultAction").and_then(|x| x.as_str()),
        Some("SCMP_ACT_ERRNO"),
        "defaultAction must be SCMP_ACT_ERRNO"
    );
    let syscalls = obj
        .get("syscalls")
        .and_then(|x| x.as_array())
        .expect("syscalls array");
    assert!(!syscalls.is_empty(), "syscalls must be non-empty");

    // Allow-list must cover the core hot-path names.
    let mut all_allowed = Vec::<String>::new();
    let mut all_denied = Vec::<String>::new();
    for entry in syscalls {
        let action = entry["action"].as_str().unwrap_or("");
        let names = entry["names"].as_array().cloned().unwrap_or_default();
        let bucket = match action {
            "SCMP_ACT_ALLOW" => &mut all_allowed,
            "SCMP_ACT_ERRNO" | "SCMP_ACT_KILL_PROCESS" | "SCMP_ACT_KILL" => &mut all_denied,
            other => panic!("unexpected action: {other}"),
        };
        for n in names {
            bucket.push(n.as_str().unwrap_or("").to_string());
        }
    }
    for must_allow in [
        "read", "write", "openat", "close", "mmap", "munmap", "futex",
        "epoll_create1", "epoll_ctl", "epoll_wait", "socket", "connect",
        "accept4", "sendto", "recvfrom", "bind", "listen", "memfd_secret",
        "memfd_create", "mlock", "munlock", "getrandom",
    ] {
        assert!(
            all_allowed.iter().any(|s| s == must_allow),
            "allow-list missing required syscall: {must_allow}"
        );
    }
    for must_deny in [
        "ptrace", "process_vm_readv", "process_vm_writev", "kcmp",
        "pivot_root", "mount", "umount2", "swapon", "reboot",
        "init_module", "finit_module", "delete_module", "kexec_load",
        "perf_event_open",
    ] {
        assert!(
            all_denied.iter().any(|s| s == must_deny),
            "deny-list missing required syscall: {must_deny}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn apparmor_profile_parses() {
    let parser = which("apparmor_parser");
    let Some(parser) = parser else {
        eprintln!("skip: apparmor_parser not on PATH");
        return;
    };
    let profile = artifact_dir().join("apparmor").join("spt");
    // -p == parse-only, print profile name + bail (no kernel load).
    let out = Command::new(&parser)
        .arg("-p")
        .arg(&profile)
        .output()
        .unwrap_or_else(|e| panic!("spawn {parser:?}: {e}"));
    assert!(
        out.status.success(),
        "apparmor_parser -p failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn apparmor_profile_parses() {
    eprintln!("skip: AppArmor is Linux-only");
}

#[cfg(target_os = "linux")]
#[test]
fn selinux_te_compiles() {
    let checkmodule = which("checkmodule");
    let Some(checkmodule) = checkmodule else {
        eprintln!("skip: checkmodule not on PATH");
        return;
    };
    let selinux_dir = artifact_dir().join("selinux");
    let te = selinux_dir.join("spt.te");
    // Build into a tmp file so the working tree is not perturbed.
    let tmp_mod = std::env::temp_dir().join(format!("spt-selinux-{}.mod", std::process::id()));
    let out = Command::new(&checkmodule)
        .arg("-M")
        .arg("-m")
        .arg("-o")
        .arg(&tmp_mod)
        .arg(&te)
        .output()
        .unwrap_or_else(|e| panic!("spawn {checkmodule:?}: {e}"));
    let _ = std::fs::remove_file(&tmp_mod);
    assert!(
        out.status.success(),
        "checkmodule failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn selinux_te_compiles() {
    eprintln!("skip: SELinux is Linux-only");
}

/// Cross-platform `which` (stdlib-only — avoids adding a dep).
#[cfg(target_os = "linux")]
fn which(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
