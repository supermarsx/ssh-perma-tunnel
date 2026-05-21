//! `spt sftp` operation bodies.

#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_name_repetitions)]

use std::path::PathBuf;

use serde::Serialize;
use serde_json::json;
use spt_cli::{groups, GlobalOpts};
use spt_config::mutate::{Document, SftpMountMutation};
use spt_config::schema::{Config, Profile, SftpMount};
use spt_core::{Error, Result};
use spt_ssh2::{SftpDirEntry, SftpMetadata};

type SftpProfileArgs = groups::sftp::SftpProfileArgs;
type SftpPathArgs = groups::sftp::SftpPathArgs;
type SftpGetArgs = groups::sftp::SftpGetArgs;
type SftpPutArgs = groups::sftp::SftpPutArgs;
type SftpRenameArgs = groups::sftp::SftpRenameArgs;
type SftpMountListArgs = groups::sftp::SftpMountListArgs;
type SftpMountAddArgs = groups::sftp::SftpMountAddArgs;
type SftpDriveAddArgs = groups::sftp::SftpDriveAddArgs;
type SftpMountRefArgs = groups::sftp::SftpMountRefArgs;
type SftpMountPlanArgs = groups::sftp::SftpMountPlanArgs;
type SftpDrivePlanArgs = groups::sftp::SftpDrivePlanArgs;
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

    fn global_with_config(path: &Path) -> GlobalOpts {
        GlobalOpts {
            config: Some(path.to_path_buf()),
            config_dir: None,
            config_url: None,
            config_fingerprint: None,
            state_dir: None,
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
