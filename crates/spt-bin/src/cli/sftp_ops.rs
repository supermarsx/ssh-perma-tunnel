//! `spt sftp` operation bodies.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

use std::io::Write as _;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::Serialize;
use serde_json::json;
use spt_cli::{groups, GlobalOpts};
use spt_config::mutate::{Document, SftpMountMutation};
use spt_config::schema::{Config, Profile, SftpMount};
use spt_core::{Error, Result};
use spt_sftp::{
    get_recursive as do_get_recursive, put_recursive as do_put_recursive, ChecksumMode,
    RecursiveOptions,
};
use spt_ssh2::{SftpDirEntry, SftpMetadata};
use spt_supervisor::{MountKey, MountRegistry};

/// Process-global supervisor-side mount registry (t7-B2). Holds the
/// live `Box<dyn SftpMounter>` returned by [`mount_start`] so that
/// [`mount_stop`] can tear the mount down without re-opening an SSH
/// session. The registry is initialised lazily on first access and
/// shared across every CLI subcommand invocation in the same process.
fn mount_registry() -> &'static MountRegistry {
    static REGISTRY: OnceLock<MountRegistry> = OnceLock::new();
    REGISTRY.get_or_init(MountRegistry::new)
}

/// Resolve the profile name to use for a mount-related operation.
/// `mount_start` and `mount_stop` MUST use the same resolution rule so
/// that the [`MountKey`] computed by `mount_stop` matches what
/// `mount_start` registered. Falling back to `"default"` (as the
/// pre-B2 `mount_stop` did) is a registry-miss footgun.
fn resolve_mount_profile(global: &GlobalOpts, arg_profile: Option<&str>) -> Result<String> {
    arg_profile
        .map(ToOwned::to_owned)
        .or_else(|| global.profile.clone())
        .ok_or_else(|| {
            Error::InvalidArgs(
                "no profile supplied (pass --profile or set --profile globally)".into(),
            )
        })
}

type SftpProfileArgs = groups::sftp::SftpProfileArgs;
type SftpPathArgs = groups::sftp::SftpPathArgs;
type SftpGetArgs = groups::sftp::SftpGetArgs;
type SftpPutArgs = groups::sftp::SftpPutArgs;
type SftpRenameArgs = groups::sftp::SftpRenameArgs;
type SftpCatArgs = groups::sftp::SftpCatArgs;
type SftpTailArgs = groups::sftp::SftpTailArgs;
type SftpChmodArgs = groups::sftp::SftpChmodArgs;
type SftpSymlinkArgs = groups::sftp::SftpSymlinkArgs;
type SftpRecursiveArgs = groups::sftp::SftpRecursiveArgs;
type SftpMountListArgs = groups::sftp::SftpMountListArgs;
type SftpMountAddArgs = groups::sftp::SftpMountAddArgs;
type SftpDriveAddArgs = groups::sftp::SftpDriveAddArgs;
type SftpMountRefArgs = groups::sftp::SftpMountRefArgs;
type SftpMountPlanArgs = groups::sftp::SftpMountPlanArgs;
type SftpDrivePlanArgs = groups::sftp::SftpDrivePlanArgs;
type SftpMountStartArgs = groups::sftp::SftpMountStartArgs;
type SftpMountStopArgs = groups::sftp::SftpMountStopArgs;
type SftpCacheMode = groups::sftp::SftpCacheMode;

#[derive(Debug, Serialize)]
struct SftpMetadataView {
    size: Option<u64>,
    permissions: Option<String>,
    modified_unix: Option<u32>,
    kind: &'static str,
}

#[derive(Debug, Serialize)]
struct SftpEntryView {
    name: String,
    metadata: SftpMetadataView,
}

#[derive(Debug, Serialize)]
struct MountView {
    profile: String,
    name: String,
    remote_path: String,
    mount_point: Option<String>,
    drive_letter: Option<String>,
    read_only: bool,
    cache: String,
    enabled: bool,
    required: bool,
}

#[derive(Debug, Serialize)]
struct CapabilityCheck {
    name: &'static str,
    required: bool,
    ok: bool,
}

#[derive(Debug, Serialize)]
struct RecursiveReportView {
    profile: String,
    source: String,
    destination: String,
    files: u64,
    directories: u64,
    symlinks: u64,
    bytes: u64,
}

#[derive(Debug, Serialize)]
struct MountPlanView {
    profile: String,
    name: String,
    remote_path: String,
    local_target: String,
    target_kind: &'static str,
    platform: &'static str,
    helper: &'static str,
    read_only: bool,
    cache: String,
    allow_other: bool,
    capability_checks: Vec<CapabilityCheck>,
    runnable_by_spt: bool,
    note: &'static str,
}

pub async fn test(global: &GlobalOpts, args: SftpProfileArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    client.close().await?;
    if wants_json(global, args.json) {
        print_json(&json!({ "ok": true, "profile": args.profile }))?;
    } else {
        println!("ok: opened SFTP subsystem for profile `{}`", args.profile);
    }
    Ok(())
}

pub async fn list(global: &GlobalOpts, args: SftpPathArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    let entries = client.read_dir(args.path.clone()).await?;
    let _ = client.close().await;
    let views: Vec<SftpEntryView> = entries.into_iter().map(entry_view).collect();
    if wants_json(global, args.json) {
        print_json(&views)?;
    } else if views.is_empty() {
        println!("(empty)");
    } else {
        for entry in views {
            println!(
                "{}\t{}\t{}",
                entry.metadata.kind,
                entry
                    .metadata
                    .size
                    .map_or_else(|| "-".to_owned(), |size| size.to_string()),
                entry.name
            );
        }
    }
    Ok(())
}

pub async fn stat(global: &GlobalOpts, args: SftpPathArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    let metadata = client.metadata(args.path.clone()).await?;
    let _ = client.close().await;
    let view = metadata_view(&metadata);
    if wants_json(global, args.json) {
        print_json(&view)?;
    } else {
        println!("path: {}", args.path);
        println!("kind: {}", view.kind);
        println!(
            "size: {}",
            view.size
                .map_or_else(|| "-".to_owned(), |size| size.to_string())
        );
        println!(
            "permissions: {}",
            view.permissions.unwrap_or_else(|| "-".to_owned())
        );
    }
    Ok(())
}

pub async fn get(global: &GlobalOpts, args: SftpGetArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    let data = client.read_file(args.remote.clone()).await?;
    let _ = client.close().await;
    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                Error::RuntimeFailure(format!("create `{}`: {e}", parent.display()))
            })?;
        }
    }
    tokio::fs::write(&args.out, data)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("write `{}`: {e}", args.out.display())))?;
    println!("wrote {}", args.out.display());
    Ok(())
}

pub async fn put(global: &GlobalOpts, args: SftpPutArgs) -> Result<()> {
    let data = tokio::fs::read(&args.local)
        .await
        .map_err(|e| Error::RuntimeFailure(format!("read `{}`: {e}", args.local.display())))?;
    let client = open_client(global, &args.profile).await?;
    client.write_file(args.remote.clone(), &data).await?;
    let _ = client.close().await;
    println!("uploaded {} to {}", args.local.display(), args.remote);
    Ok(())
}

pub async fn mkdir(global: &GlobalOpts, args: SftpPathArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    client.create_dir(args.path.clone()).await?;
    let _ = client.close().await;
    println!("created {}", args.path);
    Ok(())
}

pub async fn rm(global: &GlobalOpts, args: SftpPathArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    client.remove_file(args.path.clone()).await?;
    let _ = client.close().await;
    println!("removed {}", args.path);
    Ok(())
}

pub async fn rmdir(global: &GlobalOpts, args: SftpPathArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    client.remove_dir(args.path.clone()).await?;
    let _ = client.close().await;
    println!("removed directory {}", args.path);
    Ok(())
}

pub async fn rename(global: &GlobalOpts, args: SftpRenameArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    client
        .rename(args.old_path.clone(), args.new_path.clone())
        .await?;
    let _ = client.close().await;
    println!("renamed {} to {}", args.old_path, args.new_path);
    Ok(())
}

pub async fn cat(global: &GlobalOpts, args: SftpCatArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    let data = client.cat(args.path.clone(), args.size_cap).await?;
    let _ = client.close().await;
    if global.json {
        print_json(&json!({
            "profile": args.profile,
            "path": args.path,
            "bytes": data.len(),
            "text": String::from_utf8_lossy(&data),
        }))?;
    } else {
        std::io::stdout()
            .write_all(&data)
            .map_err(|e| Error::RuntimeFailure(format!("write stdout: {e}")))?;
    }
    Ok(())
}

pub async fn tail(global: &GlobalOpts, args: SftpTailArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    let data = client.tail(args.path.clone(), args.bytes).await?;
    let _ = client.close().await;
    if global.json {
        print_json(&json!({
            "profile": args.profile,
            "path": args.path,
            "bytes": data.len(),
            "text": String::from_utf8_lossy(&data),
        }))?;
    } else {
        std::io::stdout()
            .write_all(&data)
            .map_err(|e| Error::RuntimeFailure(format!("write stdout: {e}")))?;
    }
    Ok(())
}

pub async fn chmod(global: &GlobalOpts, args: SftpChmodArgs) -> Result<()> {
    let mode = parse_octal_mode(&args.mode)?;
    let client = open_client(global, &args.profile).await?;
    client.chmod(args.path.clone(), mode).await?;
    let _ = client.close().await;
    if global.json {
        print_json(
            &json!({ "profile": args.profile, "path": args.path, "mode": format!("{mode:o}") }),
        )?;
    } else {
        println!("chmod {:o} {}", mode, args.path);
    }
    Ok(())
}

pub async fn symlink(global: &GlobalOpts, args: SftpSymlinkArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    client
        .symlink(args.target.clone(), args.linkpath.clone())
        .await?;
    let _ = client.close().await;
    if global.json {
        print_json(
            &json!({ "profile": args.profile, "target": args.target, "linkpath": args.linkpath }),
        )?;
    } else {
        println!("linked {} -> {}", args.linkpath, args.target);
    }
    Ok(())
}

pub async fn readlink(global: &GlobalOpts, args: SftpPathArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    let target = client.readlink(args.path.clone()).await?;
    let _ = client.close().await;
    if wants_json(global, args.json) {
        print_json(&json!({ "profile": args.profile, "path": args.path, "target": target }))?;
    } else {
        println!("{}", target.display());
    }
    Ok(())
}

pub async fn realpath(global: &GlobalOpts, args: SftpPathArgs) -> Result<()> {
    let client = open_client(global, &args.profile).await?;
    let path = client.realpath(args.path.clone()).await?;
    let _ = client.close().await;
    if wants_json(global, args.json) {
        print_json(&json!({ "profile": args.profile, "path": args.path, "realpath": path }))?;
    } else {
        println!("{}", path.display());
    }
    Ok(())
}

pub async fn put_recursive(global: &GlobalOpts, args: SftpRecursiveArgs) -> Result<()> {
    let opts = recursive_options(&args)?;
    let client = open_client(global, &args.profile).await?;
    let report = do_put_recursive(
        &client,
        &PathBuf::from(&args.source),
        &args.destination,
        &opts,
    )
    .await?;
    let _ = client.close().await;
    emit_recursive_report(global, &args, report)
}

pub async fn get_recursive(global: &GlobalOpts, args: SftpRecursiveArgs) -> Result<()> {
    let opts = recursive_options(&args)?;
    let client = open_client(global, &args.profile).await?;
    let report = do_get_recursive(
        &client,
        &args.source,
        &PathBuf::from(&args.destination),
        &opts,
    )
    .await?;
    let _ = client.close().await;
    emit_recursive_report(global, &args, report)
}

fn parse_octal_mode(raw: &str) -> Result<u32> {
    let trimmed = raw.trim();
    let digits = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
        .unwrap_or(trimmed);
    if digits.is_empty() || !digits.chars().all(|c| matches!(c, '0'..='7')) {
        return Err(Error::InvalidArgs(format!(
            "invalid chmod mode `{raw}`; expected an octal value such as 0640"
        )));
    }
    u32::from_str_radix(digits, 8)
        .map_err(|e| Error::InvalidArgs(format!("invalid chmod mode `{raw}`: {e}")))
}

fn recursive_options(args: &SftpRecursiveArgs) -> Result<RecursiveOptions> {
    Ok(RecursiveOptions {
        resume: args.resume,
        bps: parse_rate(&args.bps)?,
        checksum: match args.checksum {
            groups::sftp::SftpChecksumMode::None => ChecksumMode::None,
            groups::sftp::SftpChecksumMode::Sha256 => ChecksumMode::Sha256,
        },
        follow_symlinks: args.follow_symlinks,
    })
}

fn parse_rate(raw: &str) -> Result<u64> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(Error::InvalidArgs("empty --bps value".into()));
    }
    let split_at = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, suffix) = s.split_at(split_at);
    if num.is_empty() {
        return Err(Error::InvalidArgs(format!("invalid --bps value `{raw}`")));
    }
    let value: u64 = num
        .parse()
        .map_err(|e| Error::InvalidArgs(format!("invalid --bps value `{raw}`: {e}")))?;
    let multiplier = match suffix.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "m" | "mb" => 1_000_000,
        "g" | "gb" => 1_000_000_000,
        "kib" => 1024,
        "mib" => 1024 * 1024,
        "gib" => 1024 * 1024 * 1024,
        other => {
            return Err(Error::InvalidArgs(format!(
                "invalid --bps suffix `{other}`; use B, KB, MB, GB, KiB, MiB, or GiB"
            )));
        }
    };
    value
        .checked_mul(multiplier)
        .ok_or_else(|| Error::InvalidArgs(format!("--bps value `{raw}` overflows u64")))
}

fn emit_recursive_report(
    global: &GlobalOpts,
    args: &SftpRecursiveArgs,
    report: spt_sftp::RecursiveReport,
) -> Result<()> {
    let view = RecursiveReportView {
        profile: args.profile.clone(),
        source: args.source.clone(),
        destination: args.destination.clone(),
        files: report.files,
        directories: report.directories,
        symlinks: report.symlinks,
        bytes: report.bytes,
    };
    if global.json {
        print_json(&view)?;
    } else {
        println!(
            "transferred {} files, {} directories, {} symlinks, {} bytes",
            view.files, view.directories, view.symlinks, view.bytes
        );
    }
    Ok(())
}

pub async fn mount_list(global: &GlobalOpts, args: SftpMountListArgs) -> Result<()> {
    emit_mount_list(global, args.profile.as_deref(), args.json, MountKind::Mount)
}

pub async fn drive_list(global: &GlobalOpts, args: SftpMountListArgs) -> Result<()> {
    emit_mount_list(global, args.profile.as_deref(), args.json, MountKind::Drive)
}

pub async fn mount_add(global: &GlobalOpts, args: SftpMountAddArgs) -> Result<()> {
    add_mount_entry(
        global,
        SftpMountMutation {
            profile: &args.profile,
            name: &args.name,
            remote_path: &args.remote,
            mount_point: Some(&args.mount_point),
            drive_letter: None,
            read_only: args.read_only,
            cache: args.cache.map(SftpCacheMode::as_str),
        },
    )
}

pub async fn drive_add(global: &GlobalOpts, args: SftpDriveAddArgs) -> Result<()> {
    add_mount_entry(
        global,
        SftpMountMutation {
            profile: &args.profile,
            name: &args.name,
            remote_path: &args.remote,
            mount_point: None,
            drive_letter: Some(&args.letter),
            read_only: args.read_only,
            cache: args.cache.map(SftpCacheMode::as_str),
        },
    )
}

pub async fn mount_remove(global: &GlobalOpts, args: SftpMountRefArgs) -> Result<()> {
    remove_mount_entry(global, &args.reference)
}

pub async fn drive_remove(global: &GlobalOpts, args: SftpMountRefArgs) -> Result<()> {
    remove_mount_entry(global, &args.reference)
}

pub async fn mount_plan(global: &GlobalOpts, args: SftpMountPlanArgs) -> Result<()> {
    let (cfg, profile, mount) = resolve_mount_plan(
        global,
        &args.profile,
        args.name.as_deref(),
        args.remote.as_deref(),
        args.mount_point.as_deref(),
        None,
        args.read_only,
        args.cache,
    )?;
    let plan = build_plan(&cfg, profile, &mount, MountKind::Mount)?;
    emit_plan(global, args.json, &plan)
}

/// Start an SFTP-backed filesystem mount.
///
/// Picks the platform-correct backend via
/// [`spt_sftp::mounter_for_current_os`], wires an audit hook that emits
/// `tracing` events (t6-Bwire wires this through to the workspace audit
/// subsystem), and surfaces backend errors directly. On platforms without
/// a live driver (Linux without `mount-fuse`, Windows without WinFsp,
/// macOS without `sshfs`) the command exits with
/// [`spt_core::ExitCode::UnsupportedPlatform`].
pub async fn mount_start(global: &GlobalOpts, args: SftpMountStartArgs) -> Result<()> {
    use std::sync::Arc;

    use spt_sftp::mount::{AuditHook, MountEvent, MountOpts};

    let profile_name = resolve_mount_profile(global, args.profile.as_deref())?;

    // Resolve the mountpoint and remote root: explicit CLI args win,
    // then fall back to the first matching mount entry in the profile.
    // `allow_other` is config-only (there is no CLI flag); it defaults to
    // false, which reproduces the pre-wire behaviour.
    let resolved = resolve_mount_targets(global, &profile_name, &args)?;
    let (local, remote) = (resolved.local, resolved.remote);

    let client = open_client(global, &profile_name).await?;
    let sftp = Arc::new(client);
    let mut mounter = spt_sftp::mounter_for_current_os(sftp).map_err(Error::from)?;

    let hook: AuditHook = Arc::new(|event: &MountEvent| match event {
        MountEvent::MountAttempt {
            target, backend, ..
        } => {
            tracing::info!(?target, backend, "sftp.mount.attempt");
        }
        MountEvent::MountSucceeded { target, backend } => {
            tracing::info!(?target, backend, "sftp.mount.succeeded");
        }
        MountEvent::MountFailed { target, reason } => {
            tracing::warn!(?target, %reason, "sftp.mount.failed");
        }
        MountEvent::UmountAttempt { target } => {
            tracing::info!(?target, "sftp.umount.attempt");
        }
        MountEvent::UmountSucceeded { target } => {
            tracing::info!(?target, "sftp.umount.succeeded");
        }
    });

    let mut opts = MountOpts::new(&local, &remote);
    opts.readonly = args.read_only;
    opts.allow_other = resolved.allow_other;
    opts.volume_name = args.volume.clone();
    opts.audit_hook = Some(hook);

    let handle = mounter.mount(opts).map_err(Error::from)?;
    let backend = handle.backend();
    let helper_pid = handle.helper_pid;

    // t7-B2: keep the live mounter in the supervisor-side registry so a
    // subsequent `mount stop` can tear it down in place instead of
    // opening a fresh SSH session and synthesising a handle.
    let key = MountKey::new(profile_name.clone(), local.clone());
    mount_registry()
        .register(key, mounter, handle.clone())
        .map_err(|e| Error::RuntimeFailure(format!("register live mount: {e}")))?;

    if wants_json(global, args.json) {
        print_json(&json!({
            "profile": profile_name,
            "mountpoint": local,
            "remote": remote,
            "backend": backend,
            "helper_pid": helper_pid,
        }))?;
    } else {
        println!(
            "mounted {} -> {} via {}",
            local.display(),
            remote.display(),
            backend
        );
    }
    Ok(())
}

/// Tear down an SFTP-backed filesystem mount.
///
/// Preferred path (t7-B2): the supervisor-side [`MountRegistry`] holds
/// the live `Box<dyn SftpMounter>` returned by [`mount_start`], so we
/// look the mount up by `(profile, mountpoint)` and tear it down in
/// place. This avoids re-opening an SSH session purely to call `umount`
/// and keeps the audit trail attached to the original session.
///
/// Fallback path: if no live registry entry exists (the mount was
/// created out-of-band, e.g. by a previous process invocation, or by a
/// manual `sshfs` call), we open a fresh mounter and call `umount` by
/// path — the legacy pre-B2 behaviour. A deprecation warning is logged
/// in this case so operators can spot stale state.
///
/// On successful umount, fires `audit.sftp.umount` through the workspace
/// audit sink (t7-B1, Bwire follow-up #3) with `mountpoint` /
/// `reason = "operator_request"` fields. The audit event is *not* fired
/// when the umount itself fails — the operator sees the error directly.
pub async fn mount_stop(global: &GlobalOpts, args: SftpMountStopArgs) -> Result<()> {
    use std::sync::Arc;

    use spt_sftp::mount::MountHandle;

    // Resolve the profile name using the same rule as `mount_start` so
    // the MountKey we look up matches what was registered.
    let profile_name = resolve_mount_profile(global, None).ok();

    if let Some(name) = profile_name.as_deref() {
        let key = MountKey::new(name, args.path.clone());
        if mount_registry().contains(&key) {
            let handle = mount_registry()
                .tear_down(&key)
                .map_err(|e| Error::RuntimeFailure(format!("tear down live mount: {e}")))?;
            crate::audit::emit_sftp_umount(&args.path, "operator_request");
            if wants_json(global, args.json) {
                print_json(&json!({
                    "umounted": args.path,
                    "backend": handle.backend(),
                    "source": "registry",
                }))?;
            } else {
                println!(
                    "umounted {} via {} (registry)",
                    args.path.display(),
                    handle.backend()
                );
            }
            return Ok(());
        }
    }

    // Fallback: legacy path for mounts not present in the supervisor
    // registry. Emit a tracing warning so operators can correlate this
    // with stale state or out-of-band mounts (e.g. a previous process
    // crashed without tearing down).
    tracing::warn!(
        path = %args.path.display(),
        profile = ?profile_name,
        "sftp.umount.fallback: no registry entry; opening fresh mounter (deprecated path)",
    );

    let name = profile_name.ok_or_else(|| {
        Error::InvalidArgs("umount without a live registry entry needs --profile".into())
    })?;
    let client = open_client(global, &name).await.map_err(|e| {
        Error::InvalidArgs(format!(
            "umount without a live SFTP session needs --profile (open `{name}`: {e})",
        ))
    })?;
    let sftp = Arc::new(client);
    let mut mounter = spt_sftp::mounter_for_current_os(sftp).map_err(Error::from)?;

    let backend = if cfg!(target_os = "linux") {
        "linux-fuse"
    } else if cfg!(target_os = "macos") {
        "macos-sshfs"
    } else if cfg!(windows) {
        "windows-winfsp"
    } else {
        "unsupported"
    };

    let handle = MountHandle::new(args.path.clone(), backend);
    mounter.umount(handle).map_err(Error::from)?;
    // t7-B1: only emit the audit event after the umount call has
    // completed successfully so the trail reflects realised state, not
    // intent.
    crate::audit::emit_sftp_umount(&args.path, "operator_request");
    if wants_json(global, args.json) {
        print_json(&json!({
            "umounted": args.path,
            "backend": backend,
            "source": "fallback",
        }))?;
    } else {
        println!("umounted {}", args.path.display());
    }
    Ok(())
}

/// Resolved mount targets plus the config-derived `allow_other` flag.
///
/// `allow_other` is config-only (`sftp_mounts[].allow_other`); there is
/// no CLI flag. When both `--local` and `--remote` are passed explicitly
/// we skip the config load entirely, so `allow_other` defaults to false —
/// the pre-wire behaviour.
struct ResolvedMountTargets {
    local: PathBuf,
    remote: PathBuf,
    allow_other: bool,
}

fn resolve_mount_targets(
    global: &GlobalOpts,
    profile_name: &str,
    args: &SftpMountStartArgs,
) -> Result<ResolvedMountTargets> {
    if let (Some(local), Some(remote)) = (args.local.clone(), args.remote.clone()) {
        return Ok(ResolvedMountTargets {
            local,
            remote,
            allow_other: false,
        });
    }
    let path = require_config_path(global)?;
    let (cfg, _warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let profile = find_profile(&cfg, profile_name)?;
    let mount = profile
        .sftp_mounts
        .iter()
        .find(|m| m.mount_point.is_some())
        .ok_or_else(|| {
            Error::InvalidArgs(format!(
                "profile `{profile_name}` has no SFTP mount entry; pass --local and --remote"
            ))
        })?;
    let local = args
        .local
        .clone()
        .or_else(|| mount.mount_point.clone().map(PathBuf::from))
        .ok_or_else(|| Error::InvalidArgs("mount entry is missing mount_point".into()))?;
    let remote = args
        .remote
        .clone()
        .unwrap_or_else(|| PathBuf::from(&mount.remote_path));
    Ok(ResolvedMountTargets {
        local,
        remote,
        allow_other: mount.allow_other.unwrap_or(false),
    })
}

pub async fn drive_plan(global: &GlobalOpts, args: SftpDrivePlanArgs) -> Result<()> {
    let (cfg, profile, mount) = resolve_mount_plan(
        global,
        &args.profile,
        args.name.as_deref(),
        args.remote.as_deref(),
        None,
        args.letter.as_deref(),
        args.read_only,
        args.cache,
    )?;
    let plan = build_plan(&cfg, profile, &mount, MountKind::Drive)?;
    emit_plan(global, args.json, &plan)
}

async fn open_client(global: &GlobalOpts, profile_name: &str) -> Result<spt_ssh2::SftpClient> {
    let path = require_config_path(global)?;
    let (cfg, _warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let profile = find_profile(&cfg, profile_name)?;
    let state_dir = resolve_state_dir(global, &cfg)?;
    let resolver = crate::secrets_bridge::build_resolver(cfg.secrets.as_ref(), &state_dir)?;
    let bundle = crate::profile_factory::build_sftp(profile, &resolver, &cfg)?;
    let endpoint = bundle.endpoints.first().ok_or_else(|| {
        Error::InvalidConfig(format!("profile `{profile_name}` has no SSH2 endpoint"))
    })?;
    bundle.protocol.connect_sftp(endpoint, &bundle.auth).await
}

fn emit_mount_list(
    global: &GlobalOpts,
    profile_filter: Option<&str>,
    json_output: bool,
    kind: MountKind,
) -> Result<()> {
    let path = require_config_path(global)?;
    let (cfg, _warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let mut rows = Vec::new();
    for profile in &cfg.profiles {
        if profile_filter.is_some_and(|wanted| wanted != profile.name) {
            continue;
        }
        for mount in &profile.sftp_mounts {
            if kind.matches(mount) {
                rows.push(mount_view(&profile.name, mount));
            }
        }
    }
    if wants_json(global, json_output) {
        print_json(&rows)?;
    } else if rows.is_empty() {
        println!("(no SFTP {} entries)", kind.label());
    } else {
        for row in rows {
            let local = row
                .mount_point
                .as_ref()
                .or(row.drive_letter.as_ref())
                .cloned()
                .unwrap_or_else(|| "-".to_owned());
            println!(
                "{}\t{}\t{}\t{}",
                row.profile, row.name, row.remote_path, local
            );
        }
    }
    Ok(())
}

fn add_mount_entry(global: &GlobalOpts, spec: SftpMountMutation<'_>) -> Result<()> {
    let path = require_config_path(global)?;
    let mut doc = Document::read(&path)?;
    doc.add_sftp_mount(spec)?;
    if !global.dry_run {
        doc.write_atomic(&path)?;
    }
    println!("added SFTP mount `{}/{}`", spec.profile, spec.name);
    Ok(())
}

fn remove_mount_entry(global: &GlobalOpts, reference: &str) -> Result<()> {
    let (profile, mount) = parse_ref(reference)?;
    let path = require_config_path(global)?;
    let mut doc = Document::read(&path)?;
    if !doc.remove_sftp_mount(profile, mount)? {
        return Err(Error::InvalidArgs(format!(
            "no SFTP mount `{mount}` in profile `{profile}`"
        )));
    }
    if !global.dry_run {
        doc.write_atomic(&path)?;
    }
    println!("removed SFTP mount `{profile}/{mount}`");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn resolve_mount_plan(
    global: &GlobalOpts,
    profile_name: &str,
    mount_name: Option<&str>,
    remote_path: Option<&str>,
    mount_point: Option<&str>,
    drive_letter: Option<&str>,
    read_only: bool,
    cache: Option<SftpCacheMode>,
) -> Result<(Config, String, SftpMount)> {
    let path = require_config_path(global)?;
    let (cfg, _warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    let profile = find_profile(&cfg, profile_name)?;
    let profile_name = profile.name.clone();
    let mount = if let Some(mount_name) = mount_name {
        profile
            .sftp_mounts
            .iter()
            .find(|mount| mount.name == mount_name)
            .cloned()
            .ok_or_else(|| {
                Error::InvalidArgs(format!(
                    "no SFTP mount `{mount_name}` in profile `{profile_name}`"
                ))
            })?
    } else {
        SftpMount {
            name: "proposed".to_owned(),
            enabled: Some(true),
            remote_path: remote_path
                .ok_or_else(|| Error::InvalidArgs("--remote is required without --name".into()))?
                .to_owned(),
            mount_point: mount_point.map(ToOwned::to_owned),
            drive_letter: drive_letter.map(ToOwned::to_owned),
            read_only: Some(read_only),
            cache: cache.map(|value| value.as_str().to_owned()),
            allow_other: None,
            required: None,
        }
    };
    Ok((cfg, profile_name, mount))
}

fn build_plan(
    cfg: &Config,
    profile: String,
    mount: &SftpMount,
    kind: MountKind,
) -> Result<MountPlanView> {
    let local_target = match kind {
        MountKind::Mount => mount
            .mount_point
            .clone()
            .ok_or_else(|| Error::InvalidArgs("mount plan requires mount_point".into()))?,
        MountKind::Drive => mount
            .drive_letter
            .clone()
            .ok_or_else(|| Error::InvalidArgs("drive plan requires drive_letter".into()))?,
    };
    let cache = mount.cache.clone().unwrap_or_else(|| "none".to_owned());
    let caps = cfg.capabilities.as_ref();
    let mut checks = vec![
        capability_check("capabilities.allow_sftp", caps.and_then(|c| c.allow_sftp)),
        capability_check(
            "capabilities.allow_filesystem_mounts",
            caps.and_then(|c| c.allow_filesystem_mounts),
        ),
    ];
    if matches!(kind, MountKind::Drive) {
        checks.push(capability_check(
            "capabilities.allow_windows_drive_mounts",
            caps.and_then(|c| c.allow_windows_drive_mounts),
        ));
    }
    if cache == "writeback" {
        checks.push(capability_check(
            "capabilities.allow_writeback_cache",
            caps.and_then(|c| c.allow_writeback_cache),
        ));
    }
    Ok(MountPlanView {
        profile,
        name: mount.name.clone(),
        remote_path: mount.remote_path.clone(),
        local_target,
        target_kind: kind.label(),
        platform: platform_name(),
        helper: helper_name(kind),
        read_only: mount.read_only.unwrap_or(false),
        cache,
        allow_other: mount.allow_other.unwrap_or(false),
        capability_checks: checks,
        runnable_by_spt: false,
        note: "spt stores and validates the mount plan; OS filesystem mounting still requires a platform helper/driver.",
    })
}

fn emit_plan(global: &GlobalOpts, json_output: bool, plan: &MountPlanView) -> Result<()> {
    if wants_json(global, json_output) {
        print_json(plan)?;
    } else {
        println!("profile: {}", plan.profile);
        println!("name: {}", plan.name);
        println!("remote: {}", plan.remote_path);
        println!("local: {}", plan.local_target);
        println!("platform: {}", plan.platform);
        println!("helper: {}", plan.helper);
        println!("cache: {}", plan.cache);
        println!("allow_other: {}", plan.allow_other);
        for check in &plan.capability_checks {
            println!(
                "{}: {}",
                check.name,
                if check.ok { "ok" } else { "missing" }
            );
        }
        println!("note: {}", plan.note);
    }
    Ok(())
}

fn load_config(global: &GlobalOpts) -> Result<Config> {
    let path = require_config_path(global)?;
    let (cfg, _warnings) = spt_config::load(&path, false)
        .map_err(|e| Error::InvalidConfig(format!("load `{}`: {e}", path.display())))?;
    Ok(cfg)
}

fn find_profile<'a>(cfg: &'a Config, name: &str) -> Result<&'a Profile> {
    cfg.profiles
        .iter()
        .find(|profile| profile.name == name)
        .ok_or_else(|| Error::InvalidArgs(format!("no profile `{name}`")))
}

fn require_config_path(global: &GlobalOpts) -> Result<PathBuf> {
    global.config.clone().ok_or_else(|| {
        Error::InvalidArgs("no config path supplied (pass --config or set $SPT_CONFIG)".into())
    })
}

fn resolve_state_dir(global: &GlobalOpts, cfg: &Config) -> Result<PathBuf> {
    let explicit = global.state_dir.clone().or_else(|| {
        cfg.runtime
            .as_ref()
            .and_then(|runtime| runtime.state_dir.clone())
            .map(PathBuf::from)
    });
    spt_state::resolve_state_dir(explicit.as_deref())
}

fn parse_ref(reference: &str) -> Result<(&str, &str)> {
    reference.split_once('/').ok_or_else(|| {
        Error::InvalidArgs(format!("expected `<profile>/<mount>`, got `{reference}`"))
    })
}

fn wants_json(global: &GlobalOpts, local: bool) -> bool {
    global.json || local
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    let body = serde_json::to_string_pretty(value)
        .map_err(|e| Error::RuntimeFailure(format!("json render: {e}")))?;
    println!("{body}");
    Ok(())
}

fn entry_view(entry: SftpDirEntry) -> SftpEntryView {
    SftpEntryView {
        name: entry.file_name,
        metadata: metadata_view(&entry.metadata),
    }
}

fn metadata_view(metadata: &SftpMetadata) -> SftpMetadataView {
    let kind = if metadata.is_dir {
        "directory"
    } else if metadata.is_symlink {
        "symlink"
    } else if metadata.is_file {
        "file"
    } else {
        "unknown"
    };
    SftpMetadataView {
        size: metadata.size,
        permissions: metadata
            .permissions
            .map(|permissions| format!("{permissions:o}")),
        modified_unix: metadata.modified_unix,
        kind,
    }
}

fn mount_view(profile: &str, mount: &SftpMount) -> MountView {
    MountView {
        profile: profile.to_owned(),
        name: mount.name.clone(),
        remote_path: mount.remote_path.clone(),
        mount_point: mount.mount_point.clone(),
        drive_letter: mount.drive_letter.clone(),
        read_only: mount.read_only.unwrap_or(false),
        cache: mount.cache.clone().unwrap_or_else(|| "none".to_owned()),
        enabled: mount.enabled.unwrap_or(true),
        required: mount.required.unwrap_or(false),
    }
}

fn capability_check(name: &'static str, value: Option<bool>) -> CapabilityCheck {
    CapabilityCheck {
        name,
        required: true,
        ok: matches!(value, Some(true)),
    }
}

#[derive(Copy, Clone)]
enum MountKind {
    Mount,
    Drive,
}

impl MountKind {
    fn label(self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Drive => "drive",
        }
    }

    fn matches(self, mount: &SftpMount) -> bool {
        match self {
            Self::Mount => mount.mount_point.is_some(),
            Self::Drive => mount.drive_letter.is_some(),
        }
    }
}

fn platform_name() -> &'static str {
    if cfg!(windows) {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(unix) {
        "unix"
    } else {
        "unknown"
    }
}

fn helper_name(kind: MountKind) -> &'static str {
    match (platform_name(), kind) {
        ("windows", MountKind::Drive) => "WinFsp/SSHFS-Win-compatible helper",
        ("windows", MountKind::Mount) => "WinFsp-compatible directory mount helper",
        ("macos", _) => "macFUSE/SSHFS-compatible helper",
        ("unix", _) => "FUSE3/SSHFS-compatible helper",
        _ => "platform helper required",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn config_text() -> &'static str {
        r#"
version = 1

[capabilities]
ssh2_backend = "russh"
allow_sftp = true
allow_filesystem_mounts = true
allow_windows_drive_mounts = true

[[profiles]]
name = "edge"
protocol = "ssh2"
host = "localhost"
user = "alice"

[[profiles.sftp_mounts]]
name = "data"
remote_path = "/srv/data"
mount_point = "/mnt/data"
cache = "metadata"

[[profiles.sftp_mounts]]
name = "drive"
remote_path = "/srv/data"
drive_letter = "S:"
"#
    }

    fn allow_other_config_text() -> &'static str {
        r#"
version = 1

[capabilities]
ssh2_backend = "russh"
allow_sftp = true
allow_filesystem_mounts = true

[[profiles]]
name = "edge"
protocol = "ssh2"
host = "localhost"
user = "alice"

[[profiles.sftp_mounts]]
name = "data"
remote_path = "/srv/data"
mount_point = "/mnt/data"

[[profiles.sftp_mounts]]
name = "shared"
remote_path = "/srv/shared"
mount_point = "/mnt/shared"
allow_other = true
"#
    }

    fn global_with_config(path: &Path) -> GlobalOpts {
        GlobalOpts {
            config: Some(path.to_path_buf()),
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
            portable: false,
            profile: None,
            output: spt_cli::OutputFormat::Human,
            json: false,
            log_level: spt_cli::LogLevel::Info,
            color: spt_cli::ColorMode::Auto,
            quiet: false,
            verbose: 0,
            no_color: false,
            dry_run: false,
        }
    }

    #[test]
    fn mount_view_filters_by_kind() {
        let (cfg, _) = spt_config::load_str(config_text(), false).unwrap();
        let profile = find_profile(&cfg, "edge").unwrap();
        let mounts: Vec<_> = profile
            .sftp_mounts
            .iter()
            .filter(|mount| MountKind::Mount.matches(mount))
            .collect();
        let drives: Vec<_> = profile
            .sftp_mounts
            .iter()
            .filter(|mount| MountKind::Drive.matches(mount))
            .collect();
        assert_eq!(mounts.len(), 1);
        assert_eq!(drives.len(), 1);
    }

    #[test]
    fn mount_plan_reports_capability_checks() {
        let (cfg, _) = spt_config::load_str(config_text(), false).unwrap();
        let profile = find_profile(&cfg, "edge").unwrap();
        let plan = build_plan(
            &cfg,
            profile.name.clone(),
            &profile.sftp_mounts[0],
            MountKind::Mount,
        )
        .unwrap();
        assert_eq!(plan.remote_path, "/srv/data");
        assert!(plan.capability_checks.iter().all(|check| check.ok));
        assert!(!plan.runnable_by_spt);
    }

    #[test]
    fn resolve_mount_plan_threads_allow_other() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("spt.toml");
        std::fs::write(&path, allow_other_config_text()).unwrap();
        let global = global_with_config(&path);

        // Mount configured with `allow_other = true` carries the option
        // through resolve_mount_plan and into the built plan.
        let (cfg, profile, mount) = resolve_mount_plan(
            &global,
            "edge",
            Some("shared"),
            None,
            None,
            None,
            false,
            None,
        )
        .unwrap();
        assert_eq!(mount.allow_other, Some(true));
        let plan = build_plan(&cfg, profile, &mount, MountKind::Mount).unwrap();
        assert!(plan.allow_other);

        // A mount without the flag defaults to false (pre-wire behaviour).
        let (cfg, profile, mount) =
            resolve_mount_plan(&global, "edge", Some("data"), None, None, None, false, None)
                .unwrap();
        assert_eq!(mount.allow_other, None);
        let plan = build_plan(&cfg, profile, &mount, MountKind::Mount).unwrap();
        assert!(!plan.allow_other);
    }

    #[test]
    fn add_and_remove_mount_entry_round_trips_config() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("spt.toml");
        std::fs::write(
            &path,
            r#"
version = 1
[[profiles]]
name = "edge"
protocol = "ssh2"
host = "localhost"
"#,
        )
        .unwrap();
        let global = global_with_config(&path);
        add_mount_entry(
            &global,
            SftpMountMutation {
                profile: "edge",
                name: "data",
                remote_path: "/srv/data",
                mount_point: Some("/mnt/data"),
                drive_letter: None,
                read_only: true,
                cache: Some(SftpCacheMode::Metadata.as_str()),
            },
        )
        .unwrap();
        let cfg = load_config(&global).unwrap();
        assert_eq!(cfg.profiles[0].sftp_mounts.len(), 1);
        remove_mount_entry(&global, "edge/data").unwrap();
        let cfg = load_config(&global).unwrap();
        assert!(cfg.profiles[0].sftp_mounts.is_empty());
    }
}
