# SFTP

`spt-sftp` provides an SFTP client over an established `russh` channel
(`SftpClient::from_russh`), plus a cross-platform **SFTP-as-filesystem mount**
surface (`spt sftp mount` / `spt sftp umount`). This page documents the mount
backends, their lifecycle behaviour, and the platform-support matrix.

## Platform support matrix

| OS      | Backend                                       | Status        | Caveats                                                                                                              |
|---------|-----------------------------------------------|---------------|----------------------------------------------------------------------------------------------------------------------|
| Linux   | `fuser 0.15` (`mount-fuse` feature)           | Production    | Requires `/dev/fuse` readable by the runtime user; needs `fusermount` (libfuse) on `$PATH`, or root.                 |
| Windows | `winfsp 0.10` (`mount-winfsp` feature)        | Production    | WinFsp runtime must be installed (Chocolatey: `choco install winfsp`). Without the feature, falls back to launcher.  |
| macOS   | `sshfs` shell-out + macFUSE                   | **Deprecated**| macFUSE upstream is unstable; FSKit-based replacement is post-1.0. SSH connection is **not shared** with spt sessions.|
| Other   | n/a                                           | Unsupported   | Returns `ExitCode::UnsupportedPlatform` (10).                                                                        |

## macOS: the macFUSE / FSKit gap

macOS is permanently second-class for SFTP mounts in `spt`, and we are
explicit about why:

1. **macFUSE is operator-deprecated upstream.** Apple's privileged-helper
   requirements have grown increasingly hostile to third-party kernel
   extensions. Each macOS major release tightens the screw further. The
   macFUSE project ships, but with diminishing platform support.
2. **FSKit (the modern Apple API) is Swift-only.** Bridging an idiomatic
   `russh`/`tokio` stack to a Swift framework is out of scope for this
   milestone (see plan §"Out of scope" in `.orchestration/plans/t7.md`).
   An FSKit-backed mount is post-1.0.
3. **The shell-out backend opens its own SSH connection.** `sshfs(1)`
   establishes its own SSH channel under the hood; `spt-sftp` cannot share
   the in-process `Arc<SftpClient>` with it. This is a known limitation —
   audit events still fire and lifecycle is still managed by `spt`, but the
   actual bytes flow over a separate SSH session that does not benefit
   from `spt`'s connection pooling, keep-alive, or multi-hop forwarding.

### macOS mount lifecycle

* `mount` — `MacOsSshfsMounter::new(...)` (exposed as `SshfsMounter`)
  probes for the `sshfs` binary on `$PATH` and macFUSE under
  `/Library/Filesystems/macfuse.fs`. If both are absent the diagnostic is
  cached and surfaced on the first `mount()` call as
  `SftpError::UnsupportedPlatform`, which maps to
  `ExitCode::UnsupportedPlatform` (exit 10).
* `mount` (continued) — On success, spawns
  `sshfs REMOTE:remote_root local_mountpoint -o opts ...`, captures the
  `Child` for lifecycle management, and tees `sshfs` stderr to
  `tracing::debug!` (target `spt_sftp::mount::macos`). The last 3 lines of
  stderr are retained as a ring buffer and surfaced if the child exits
  non-zero.
* `umount` — Calls `Child::kill()` (best-effort, swallows
  already-exited errors), then runs `umount(8)` against the mountpoint.
  Both are idempotent — a second `umount` against the same handle is a
  no-op.

### Operator install guidance

```sh
# macFUSE (kernel extension; requires reboot + system extension approval).
brew install --cask macfuse

# sshfs binary. The upstream osxfuse/sshfs repo is unmaintained; the
# `gromgit/fuse/sshfs-mac` tap is the most actively maintained fork.
brew install gromgit/fuse/sshfs-mac
```

If macFUSE is installed but `sshfs` is not, the diagnostic explicitly
points at the brew tap. If `sshfs` is on `$PATH` but macFUSE is not (an
unusual but possible state), the macFUSE-installation diagnostic links
to the macFUSE project page.

### Live testing

Live macOS mount tests are gated behind `SPT_SSHFS_LIVE=1`:

```sh
SPT_SSHFS_LIVE=1 cargo test -p spt-sftp \
    --features testing \
    -- --ignored sshfs_live
```

This requires macFUSE installed, `sshfs` on `$PATH`, and a reachable
SSH server fixture. CI does not run these tests — they are an operator
acceptance gate.

## Linux: `fuser` session loop

The Linux backend uses `fuser 0.15` over an `Arc<SftpClient>`. FUSE
callbacks run on a dedicated `std::thread`; the backend captures a
`tokio::runtime::Handle` at mount time and bridges sync kernel callbacks
into the async `SftpClient` via `Handle::block_on`. See
`crates/spt-sftp/src/mount/linux_fuse.rs` for the SFTP↔FUSE error
translation table.

Live FUSE tests run with `SPT_FUSE_LIVE=1` on a Linux runner with
`/dev/fuse` accessible and `libfuse-dev` installed.

## Windows: WinFsp

The Windows backend uses the `winfsp 0.10` Rust binding. Without the
`mount-winfsp` cargo feature the build falls back to a launcher shell-out
that surfaces a clean `UnsupportedPlatform` diagnostic if the WinFsp
launcher isn't present.

Install WinFsp via Chocolatey (`choco install winfsp`) on CI runners or
operator hosts. The Windows backend behaves identically to Linux from
the `SftpMounter` trait's perspective — handle lifecycle, audit hooks,
and error categorisation are uniform.

## Audit events

Every backend emits `MountEvent::{MountAttempt, MountSucceeded,
MountFailed, UmountAttempt, UmountSucceeded}` through the optional
`MountOpts::audit_hook`. The hook is invoked synchronously inside the
mounter and must be `Send + Sync`. `t7-B1` wires this through the
workspace audit pipeline; the SFTP crate itself stays oblivious to where
the events land so it remains testable in isolation.

## Exit codes

| Condition                                                | Exit code | `CoreError` variant         |
|----------------------------------------------------------|-----------|-----------------------------|
| Mount succeeded                                          | 0         | —                           |
| Validation failed (empty mountpoint, non-absolute, etc.) | 1         | `RuntimeFailure`            |
| Backend missing (no macFUSE, no `/dev/fuse`, no WinFsp)  | 10        | `UnsupportedPlatform`       |
| Permission denied                                        | 13        | `PermissionDenied`          |
| Other runtime failure (sshfs spawn error, kernel error)  | 1         | `RuntimeFailure`            |

See `crates/spt-sftp/src/error.rs` and `crates/spt-core/src/lib.rs` for
the structured mapping.
