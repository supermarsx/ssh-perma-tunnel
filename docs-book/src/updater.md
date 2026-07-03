# Updater

`spt` ships with an embedded auto-updater that can poll a configured release
source, verify the artifact, and atomically replace the running binary. It is
**off by default** — a fresh config with no `[updater]` block produces zero
update activity. The operator opts in explicitly.

## Defaults and threat model

Three load-bearing defaults establish the security baseline:

1. **`enabled = false`** — the supervisor never spawns the polling thread.
2. **`mode = "off"`** — even if the thread is spawned, it does nothing.
3. **`verify.require_minisign = true`** — when the thread does install, it
   refuses any artifact that does not carry a valid minisign signature against
   the operator-supplied public key.

Manual `spt update *` commands work regardless of `enabled`. Disabling the
master switch only prevents the background polling thread.

## Configuration

```toml
[updater]
enabled  = false              # master switch; false → no background thread
mode     = "off"              # off | check | warn | auto
schedule = "0 6 * * *"        # 5-field cron (UTC by default)
# interval = "24h"            # alternative to schedule; mutually exclusive

source         = "github"           # github | url | static
github_repo    = "supermarsx/ssh-perma-tunnel"
github_channel = "stable"           # stable | prerelease

# --- url source ---
# url             = "https://mirror.example.com/spt/{version}/spt-{target}.tar.gz"
# url_index       = "https://mirror.example.com/spt/release-manifest.json"
# url_fingerprint = "SHA256:abc…"   # required when source = "url"

# --- static source ---
# static_dir = "/srv/spt/releases"

[updater.window]
# auto-install only fires inside this window; omit block for "any time"
allow_from = "02:00"
allow_to   = "06:00"
timezone   = "UTC"

[updater.staging]
dir       = "{state_dir}/updates"   # {state_dir} expanded by the runtime
keep_last = 3

[updater.verify]
require_minisign   = true           # default; flip false only for private mirrors
minisign_pubkey    = "/etc/spt/minisign.pub"
require_sha256sums = true
# gpg_pubkey       = "/etc/spt/gpg.pub"

[updater.action]
restart_supervisor = true
notify_audit       = true
# post_install_hook = "/usr/local/bin/spt-post-install.sh"
```

The schema validator fires at load time on every obvious misconfiguration:
unknown enum values, mutually exclusive fields, required-but-missing fields
(`source = "url"` without `url_fingerprint`, `require_minisign = true` without
`minisign_pubkey`), and known footguns (`mode = "auto"` with `enabled = false`
emits a warning since the thread that would install is never spawned).

## Modes

| `mode` | Behaviour |
|--------|-----------|
| `"off"` | Supervisor refuses to spawn the thread even when `enabled = true`. Belt-and-braces lockout. |
| `"check"` | Background thread polls on schedule; exposes `latest_version` via `spt update status`. No log warning, no install. |
| `"warn"` | `check` plus emit a `tracing::warn!` and an audit event whenever a newer version is detected. |
| `"auto"` | `warn` plus download, verify, atomic install, and supervisor restart. Hands-off mode. |

## Release sources

### `source = "github"` (default)

Polls the GitHub Releases API for the configured `<owner>/<repo>`. Filters by
`github_channel`:

- `stable` (default) — skips pre-releases.
- `prerelease` — includes pre-releases.

No authentication is needed for public repos. Set `GITHUB_TOKEN` in the service
environment for private repos.

### `source = "url"`

HTTPS GET against a `release-manifest.json` URL. The following fields are
required:

- `url` — artifact URL template containing `{version}` and `{target}`
  placeholders.
- `url_fingerprint` — SHA-256 pin on the manifest body. Without this pin, a
  TLS-MITM-capable adversary could swap the artifact set even over HTTPS.

`url_index` defaults to deriving from `url` by stripping the artifact pattern
and appending `release-manifest.json`.

### `source = "static"`

A `file://` directory of release artifacts laid out like `dist/<version>/`.
Suitable for offline mirrors, air-gapped operators, and smoke tests.

## Schedule

Exactly one of `schedule` (cron) or `interval` (humantime duration) must be
set; the load-time validator rejects configs that set both.

**Cron (`schedule`)** — standard 5-field POSIX crontab
(`minute hour day-of-month month day-of-week`). Times are interpreted in UTC
unless `[updater.window].timezone` is set.

| Expression | Meaning |
|------------|---------|
| `0 6 * * *` | 06:00 UTC daily (default) |
| `0 */6 * * *` | every 6 hours |
| `0 3 * * 1` | 03:00 UTC every Monday |
| `15 2 1 * *` | 02:15 UTC on the 1st of every month |

**Interval (`interval`)** — a `humantime`-parsed duration: `"6h"`, `"24h"`,
`"7d"`, `"30m"`. The first tick fires immediately on supervisor startup;
subsequent ticks repeat at the interval.

## Signature verification

| Field | Default | Effect |
|-------|---------|--------|
| `require_minisign` | `true` | Refuse install without a valid minisign signature. |
| `minisign_pubkey` | unset | Path to the trusted minisign `.pub`. Required when `require_minisign = true`. |
| `require_sha256sums` | `true` | Refuse install if the artifact SHA-256 mismatches `SHA256SUMS`. |
| `gpg_pubkey` | unset | When set, the GPG signature on `SHA256SUMS.asc` becomes mandatory. |

The release pipeline produces minisign signatures for every artifact. Operators
consuming a private mirror that does not replay signatures can set
`require_minisign = false`; doing so emits a `tracing::warn!` at config load.

## Maintenance window

`[updater.window]` constrains auto-install without affecting polling. The
install step is gated on the current wall-clock time falling between
`allow_from` and `allow_to` in the configured `timezone`. When a tick fires
outside the window, the thread defers and logs at `tracing::info!`. Omit the
`[updater.window]` block to install at any scheduled tick.

Only the background `auto` path is window-gated. Manual `spt update apply`
always runs.

## Install lifecycle

1. **Stage** — download the artifact to `[updater.staging].dir/{version}/`.
   `keep_last` limits how many past staged builds are retained; older ones are
   pruned on each successful install.
2. **Verify** — check the artifact SHA-256 against `SHA256SUMS`, then verify
   the minisign signature against the configured public key.
3. **Swap** — atomically replace the running binary:
   - **Unix** — `fs::rename` over the live exe path. POSIX permits this; the
     running process keeps its open file mapping until it exits.
   - **Windows** — write to a sibling temp path and use
     `MoveFileEx(MOVEFILE_REPLACE_EXISTING)`, or schedule a delayed rename for
     the next reboot via `MOVEFILE_DELAY_UNTIL_REBOOT`.
4. **Restart** — when `[updater.action].restart_supervisor = true` (the
   default), the supervisor performs a graceful drain and re-exec. The restart
   hook is injected by `spt-bin` at spawn time; without it the new binary takes
   effect only after a manual restart.
5. **Post-install hook** — when `[updater.action].post_install_hook` is set, it
   runs after the restart. The hook is executed directly via
   `std::process::Command` with no shell interpretation. The new version and
   staged artifact path are passed through the environment variables
   `SPT_UPDATE_VERSION` and `SPT_UPDATE_ARTIFACT`.

## CLI

All commands work regardless of `[updater].enabled`. Disabling the master
switch only prevents the background thread.

| Command | Description |
|---------|-------------|
| `spt update check` | One-shot poll. Prints whether a newer release is available. |
| `spt update download [--target X]` | Stage the artifact without installing. |
| `spt update apply` | Install the staged artifact (atomic swap). |
| `spt update now` | check + download + apply in one step. |
| `spt update status` | Last check, next-scheduled tick, current and latest version, staged artifact. |
| `spt update history` | Past install events from the audit log. |

See [CLI Reference](cli-reference.md) for the full `spt update` command group.

## Threading model

When `enabled = true` and `mode != "off"`, the supervisor spawns the updater
on a **dedicated OS thread** with its own current-thread Tokio runtime:

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

The current-thread runtime owns the updater's I/O so long-blocking downloads
cannot starve the supervisor's forward and tunnel handlers (which run on the
main multi-thread runtime). Shutdown is cooperative: the supervisor sends a
`Control::Shutdown` message and joins the thread.

## Audit events

When `[updater.action].notify_audit = true` (the default), every poll and every
install emits a structured audit event through the workspace audit pipeline:

| Event | Fields |
|-------|--------|
| `updater.check.ok` | `latest_version`, `current_version`, `update_available` |
| `updater.check.error` | `error_kind`, `message` |
| `updater.download.ok` | `version`, `artifact`, `sha256`, `size` |
| `updater.verify.failed` | `version`, `artifact`, `reason` |
| `updater.install.ok` | `version`, `from_version` |
| `updater.install.failed` | `version`, `error_kind`, `message` |

Tracing spans use the target `spt_updater::*` so log pipelines can filter on
the family.

## Relationship to remote config

The embedded updater and the remote-config subsystem are independent. Remote
config (`[runtime.remote_config]` / `spt-remote-config`) fetches the TOML
configuration document over HTTPS with body-fingerprint pinning and optional
SPTENC1 envelope decryption. The updater fetches release artifacts from a
release source. They share the same HTTPS-pinning design (`url_fingerprint`
for the updater, `fingerprint_sha256` for remote config) but are controlled
by separate config tables and CLI command groups.

See [Configuration Reference](configuration-reference.md) for `[runtime.remote_config]`.

## Operations playbook

### Warn-only (notify on new release, no install)

From [`examples/updater.toml`](https://github.com/supermarsx/ssh-perma-tunnel/blob/main/examples/updater.toml):

```toml
[updater]
enabled  = true
mode     = "warn"
schedule = "0 6 * * *"

[updater.staging]
dir       = "{state_dir}/updates"
keep_last = 3

[updater.verify]
require_minisign   = true
minisign_pubkey    = "/etc/spt/minisign.pub"
require_sha256sums = true

[updater.window]
allow_from = "02:00"
allow_to   = "06:00"
timezone   = "UTC"

[updater.action]
restart_supervisor = true
notify_audit       = true
```

### Fully automatic with maintenance window

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
# Omit the [updater] block entirely, or make it explicit:
[updater]
enabled = false
mode    = "off"
```

### Manual one-off check from a disabled config

```sh
spt update check    # works even with enabled = false
spt update status   # prints "note: background thread NOT running"
```

### Custom mirror with URL fingerprint pinning

```toml
[updater]
enabled         = true
mode            = "warn"
source          = "url"
url             = "https://releases.internal.example.com/spt/{version}/spt-{target}.tar.gz"
url_index       = "https://releases.internal.example.com/spt/release-manifest.json"
url_fingerprint = "SHA256:abc123…"
schedule        = "0 */6 * * *"

[updater.verify]
require_minisign = true
minisign_pubkey  = "/etc/spt/mirror-minisign.pub"
```
