# Embedded auto-updater

`spt` ships with an embedded auto-updater that can poll a configured release
source, verify the artifact, and atomically replace the running binary. It is
**off by default** — a fresh config with no `[updater]` block produces zero
update activity. The operator opts in explicitly.

This document covers:

- [Threat model & defaults](#threat-model--defaults)
- [Config schema](#config-schema)
- [Modes of operation](#modes-of-operation)
- [Release sources](#release-sources)
- [Schedule grammar](#schedule-grammar)
- [Verification](#verification)
- [Maintenance window](#maintenance-window)
- [Install lifecycle](#install-lifecycle)
- [CLI surface](#cli-surface)
- [Threading model](#threading-model)
- [Audit + telemetry](#audit--telemetry)
- [Operations playbook](#operations-playbook)

## Threat model & defaults

The updater operates under three load-bearing defaults:

1. **`enabled = false`** — the supervisor never spawns the polling thread.
2. **`mode = "off"`** — even if the thread is spawned, it does nothing.
3. **`verify.require_minisign = true`** — when the thread *does* install,
   it refuses to install an artifact that doesn't carry a valid minisign
   signature against the operator-supplied public key.

The combination produces "no autonomous action without explicit operator
opt-in, and even then, no install without a verified signature." Manual
`spt update *` commands work regardless of `enabled` — disabling the
master switch only prevents the background thread.

## Config schema

The full `[updater]` block, with every default shown:

```toml
[updater]
enabled  = false              # master switch; off → no background thread
mode     = "off"              # off | check | warn | auto
schedule = "0 6 * * *"        # 5-field cron expression (UTC by default)
# interval = "24h"            # alternative; mutually exclusive with schedule
source   = "github"           # github | url | static

# --- github source (default) ---
github_repo    = "supermarsx/ssh-perma-tunnel"
github_channel = "stable"     # stable | prerelease

# --- url source ---
# url             = "https://mirror.example.com/spt/{version}/spt-{target}.tar.gz"
# url_index       = "https://mirror.example.com/spt/release-manifest.json"
# url_fingerprint = "SHA256:abc…"   # REQUIRED for source = "url"

# --- static source ---
# static_dir = "/srv/spt/releases"

[updater.window]
# Auto-install only fires inside this window. Omit for "any time".
# allow_from = "02:00"
# allow_to   = "06:00"
# timezone   = "UTC"

[updater.staging]
dir       = "{state_dir}/updates"   # placeholder expanded by the runtime
keep_last = 3

[updater.verify]
require_minisign   = true     # default; flip to false ONLY for private mirrors
minisign_pubkey    = "/etc/spt/minisign.pub"
require_sha256sums = true
# gpg_pubkey       = "/etc/spt/gpg.pub"

[updater.action]
restart_supervisor = true
notify_audit       = true
# post_install_hook = "/usr/local/bin/spt-post-install.sh"
```

The schema validator (`spt_config::validate`) fires at load time on every
obvious misconfiguration — unknown enum values, mutually-exclusive fields,
required-but-missing fields (`url` source without `url_fingerprint`,
`require_minisign = true` without `minisign_pubkey`), and known footguns
(`mode = "auto"` with `enabled = false` emits a warning since the thread
that would install is never spawned).

## Modes of operation

| `mode`    | Behavior                                                       |
|-----------|----------------------------------------------------------------|
| `"off"`   | Even with `enabled = true`, the supervisor refuses to spawn the thread. Belt-and-braces lockout. |
| `"check"` | Background thread polls on the schedule; exposes `latest_version` via `spt update status`. No tracing-warn, no install. |
| `"warn"`  | `check` + emit a `tracing::warn!` and an audit event whenever a newer version is detected, so operators see a banner in their log pipeline. |
| `"auto"`  | `warn` + download + verify + atomic install + supervisor restart. The hands-off mode. |

## Release sources

Three backends:

### `source = "github"` (default)

Polls the GitHub Releases API for the configured `<owner>/<repo>`. Filters
by `github_channel`:

- `stable` (default) — skips releases flagged as pre-release.
- `prerelease` — includes pre-releases.

No authentication is needed for public repos. For private repos, set
`GITHUB_TOKEN` in the environment of the spt service.

### `source = "url"`

HTTPS GET against a configured `release-manifest.json` URL. Required:

- `url` — artifact URL template containing `{version}` and `{target}`
  placeholders, e.g.
  `https://mirror.example.com/spt/{version}/spt-{target}.tar.gz`.
- `url_index` — the manifest URL itself; defaults to deriving from `url`
  by stripping the artifact pattern and appending
  `release-manifest.json`.
- `url_fingerprint` — **required** SHA-256 pin on the manifest body. Without
  this pin, any TLS-MITM-capable adversary could swap the artifact set
  even over HTTPS.

### `source = "static"`

`file://` directory of release artifacts laid out like `dist/<version>/`.
For offline mirrors, smoke tests, and air-gapped operators who pull from
a curated subset.

## Schedule grammar

Exactly one of `schedule` (cron) or `interval` (`humantime`) must be set;
the load-time validator rejects configs that set both.

### Cron (`schedule`)

Standard 5-field POSIX crontab (`minute hour day-of-month month day-of-week`).
The updater internally prepends `0 ` for the seconds field so the underlying
`cron` crate's 6-field grammar is satisfied — operators write the familiar
5-field form. Times are interpreted in UTC unless `[updater.window].timezone`
is set.

Examples:

| Expression       | Meaning                       |
|------------------|-------------------------------|
| `0 6 * * *`      | 06:00 UTC daily (default)     |
| `0 */6 * * *`    | every 6 hours                 |
| `0 3 * * 1`      | 03:00 UTC every Monday        |
| `15 2 1 * *`     | 02:15 UTC on the 1st of every month |

### Interval (`interval`)

`humantime`-parsed duration: `"6h"`, `"24h"`, `"7d"`, `"30m"`. First tick
fires immediately on supervisor startup; subsequent ticks repeat at the
interval. Use this when you want "every N hours" semantics without
worrying about UTC midnight.

## Verification

| Field                       | Default | What it gates                                 |
|-----------------------------|---------|-----------------------------------------------|
| `require_minisign`          | `true`  | Refuse install without a valid minisign sig.  |
| `minisign_pubkey`           | unset   | Path to the trusted minisign `.pub`. Required when `require_minisign = true`. |
| `require_sha256sums`        | `true`  | Refuse install if the artifact's SHA-256 mismatches the entry in `SHA256SUMS`. |
| `gpg_pubkey`                | unset   | Optional. When present, the GPG signature on `SHA256SUMS.asc` becomes mandatory. |

The release pipeline (`.github/workflows/ci.yml`) produces minisign
signatures for every artifact under `dist/<version>/`. The `minisign.pub`
that signed the public releases lives at
`https://github.com/supermarsx/ssh-perma-tunnel/releases/download/<tag>/minisign.pub`
when present (it's also referenced in `release-manifest.json`).

Operators consuming a private mirror that doesn't replay signatures can
set `require_minisign = false`, which emits a `tracing::warn!` at config
load. Use deliberately.

## Maintenance window

`[updater.window]` constrains *auto-install*. Polling still happens on
the configured schedule; the install step is gated on the current
wall-clock time falling between `allow_from` and `allow_to` in the
configured `timezone`. When the install fires outside the window, the
thread defers to the next opportunity inside the window (logged at
`tracing::info!`).

Omit the whole block to install at any tick.

## Install lifecycle

1. **Stage** — download the artifact to
   `[updater.staging].dir/{version}/`. The `keep_last` setting retains the
   last N staged builds; older ones are GC'd on each successful install.
2. **Verify** — check the artifact's SHA-256 against `SHA256SUMS`, then
   verify the minisign signature against the configured public key.
3. **Swap** — atomically replace the running binary:
   * **Unix** — `fs::rename` over the live exe path. POSIX permits this;
     the running process keeps its open file mapping until it exits.
   * **Windows** — write to a sibling temp path and use
     `MoveFileEx(MOVEFILE_REPLACE_EXISTING)` when nothing else holds
     the executable open, or schedule a delayed rename for the next
     reboot via `MOVEFILE_DELAY_UNTIL_REBOOT`. (Implementation lands in
     the install commit; the staged artifact remains on disk until then.)
4. **Restart** — when `[updater.action].restart_supervisor = true` (the
   default), the supervisor performs a graceful drain + re-exec.
5. **Post-install hook** — if `[updater.action].post_install_hook` is
   set, it runs after the restart with `SPT_UPDATE_VERSION` and
   `SPT_UPDATE_ARTIFACT` in the environment.

## CLI surface

Every command works regardless of `[updater].enabled`. Disabling only
prevents the *background* polling thread; manual invocations always run.

| Command                     | Description                                       |
|-----------------------------|---------------------------------------------------|
| `spt update check`          | One-shot poll. Prints whether a newer release is available. |
| `spt update download [--target X]` | Stage the artifact; doesn't install. |
| `spt update apply`          | Install the staged artifact (atomic swap).        |
| `spt update now`            | check + download + apply in one go.               |
| `spt update status`         | Last check, next-scheduled tick, current/latest, staged. |
| `spt update history`        | Past events from the audit log.                   |

## Threading model

When `[updater].enabled = true` and `mode != "off"`, the supervisor
spawns the updater on a **dedicated OS thread**:

```rust
std::thread::Builder::new()
    .name("spt-updater")
    .spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        rt.block_on(driver.run(...));
    });
```

The current-thread runtime owns the updater's I/O so long-blocking
downloads can't starve the supervisor's forward / tunnel handlers (which
run on the main multi-thread runtime). Shutdown is cooperative: the
supervisor sends a `Control::Shutdown` message and joins the thread.

The handle returned by `Updater::spawn` is cloneable, so the MCP /
status surface can call into the running thread without sharing a
runtime.

## Audit + telemetry

When `[updater.action].notify_audit = true` (the default), every poll
and every install emits a structured audit event through the workspace
audit pipeline:

| Event                    | Fields                                              |
|--------------------------|-----------------------------------------------------|
| `updater.check.ok`       | latest_version, current_version, update_available   |
| `updater.check.error`    | error_kind, message                                 |
| `updater.download.ok`    | version, artifact, sha256, size                     |
| `updater.verify.failed`  | version, artifact, reason                           |
| `updater.install.ok`     | version, from_version                               |
| `updater.install.failed` | version, error_kind, message                        |

`tracing` spans use the target `spt_updater::*` so log pipelines can
filter on the family.

## Operations playbook

### Enable warn-only updates (notify-on-new-release)

```toml
[updater]
enabled  = true
mode     = "warn"
schedule = "0 6 * * *"

[updater.verify]
require_minisign = true
minisign_pubkey  = "/etc/spt/minisign.pub"
```

Logs will carry a `tracing::WARN` whenever a newer version lands, with no
install. Operators promote to `mode = "auto"` once they've confirmed the
upgrade-readiness of their environment.

### Enable fully-auto updates with a maintenance window

```toml
[updater]
enabled  = true
mode     = "auto"
schedule = "0 2 * * *"

[updater.window]
allow_from = "02:00"
allow_to   = "04:00"
timezone   = "UTC"

[updater.verify]
require_minisign = true
minisign_pubkey  = "/etc/spt/minisign.pub"

[updater.action]
restart_supervisor = true
notify_audit       = true
```

### Disable auto-updates entirely

```toml
# No `[updater]` block at all — that's the supported way to opt out.
```

Equivalent and explicit:

```toml
[updater]
enabled = false
mode    = "off"
```

### Manual one-off check from a disabled config

```sh
spt update check    # works even with enabled = false
spt update status   # prints `note: background thread NOT running`
```

### Pin a custom mirror

```toml
[updater]
enabled         = true
mode            = "warn"
source          = "url"
url             = "https://releases.internal.example.com/spt/{version}/spt-{target}.tar.gz"
url_index       = "https://releases.internal.example.com/spt/release-manifest.json"
url_fingerprint = "SHA256:abc123…"      # SHA-256 of the manifest body
schedule        = "0 */6 * * *"

[updater.verify]
require_minisign = true
minisign_pubkey  = "/etc/spt/mirror-minisign.pub"
```

## Status

The `[updater]` schema + load-time validation + CLI surface scaffold are
live (commit `6076ac5`). The runtime poll path (source backends, atomic
install, supervisor restart wiring) is being landed incrementally in
subsequent commits in the updater series. Until those land:

- `spt update status` works end-to-end (renders the resolved config).
- `spt update check` parses the `[updater]` block but doesn't yet poll.
- `spt update {download, apply, now, history}` return a "scaffolded"
  notice with the resolved source/mode so operators can verify their
  config without waiting on the implementation.
