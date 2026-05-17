# Snap Store submission runbook for `spt`

This is the maintainer-facing runbook for publishing `spt` to the Snap Store
(snapcraft.io). It documents every store-side field, the assets that must be
uploaded outside the snap itself, and the per-release command sequence.

## 0. One-time setup

1. Install snapcraft on the build host (Ubuntu 22.04+ recommended, or use
   `--use-lxd` from any Linux distro that supports LXD):

   ```sh
   sudo snap install snapcraft --classic
   sudo snap install lxd
   sudo lxd init --auto
   ```

2. Authenticate against the Snap Store with a publisher account:

   ```sh
   snapcraft login
   ```

3. Reserve the name (once per name, ever):

   ```sh
   snapcraft register spt
   ```

   If the name is already taken, request a transfer via
   <https://forum.snapcraft.io/c/store-requests/16>.

## 1. Per-release build + upload

From the repository root:

```sh
# Build the snap inside an LXD VM (clean, reproducible).
snapcraft --use-lxd

# Or, if you're already inside a clean Ubuntu 22.04 container:
snapcraft --destructive-mode

# Local smoke test before pushing to the store.
sudo snap install --dangerous ./spt_0.1.0_amd64.snap
snap run spt --version
snap run spt tunnel --help

# Upload + release to the chosen channel.
snapcraft upload spt_0.1.0_amd64.snap --release=edge
# Promote when ready:
snapcraft release spt <REVISION> beta
snapcraft release spt <REVISION> candidate
snapcraft release spt <REVISION> stable
```

`<REVISION>` is the integer revision number printed by `snapcraft upload`
or visible in `snapcraft list-revisions spt`.

## 2. Store metadata

### Categories

Pick the primary + at most two secondary categories from
<https://snapcraft.io/store-categories>. For `spt`:

- Primary: **network**
- Secondary: **security**, **utilities**

Set via the web UI (publisher.snapcraft.io → spt → Listing) or via
`snapcraft push-metadata --from-snap`.

### Title, summary, description

| Field       | Source                                        | Notes                                              |
|-------------|-----------------------------------------------|----------------------------------------------------|
| Title       | `title:` in snapcraft.yaml                    | Max 40 characters. Currently `spt`.                |
| Summary     | `summary:` in snapcraft.yaml                  | Max 79 characters. Plain text only.                |
| Description | `description:` in snapcraft.yaml              | Markdown allowed (limited subset — headings, lists, links, code blocks). |
| License     | `license:` in snapcraft.yaml                  | SPDX identifier. Currently `MIT`.                  |
| Contact     | `contact:` URL                                | Currently the GitHub issues URL.                   |
| Website     | `website:` URL                                | Currently the GitHub repo URL.                     |

`snapcraft push-metadata --from-snap ./spt_<VER>_amd64.snap` pushes all of
the above from the built snap in one shot.

### Icon

- **Spec:** 256×256 PNG, square, transparent background allowed.
- **File:** `packaging/snapcraft/icon-256.png` (referenced from
  `packaging/snap/snapcraft.yaml` via `icon:`).
- The shipped file is a placeholder — replace before first stable release.

### Banner / featured image

- **Spec:** 1920×1080 PNG or JPEG, <2 MB. Used in editorial features and
  the "Featured" carousel on snapcraft.io.
- **File:** upload via publisher.snapcraft.io → spt → Listing → Banner.
  Not shipped in this repo (operator-supplied).

### Screenshots

Snap Store requires **at least one**, recommends **three or more**, max nine.

- **Spec:** 1920×1080 PNG or JPEG, <2 MB each.
- Suggested screenshots to capture and upload:

  1. **`spt tunnel run --profile prod`** — terminal session showing the
     connection establishing, fingerprint pin, and "tunnel up" output.
  2. **`spt tunnel health`** — colorized health table with green/yellow/red
     status per forward, RTT, last-reconnect timestamp.
  3. **`spt mcp serve`** — the MCP server running with a sample
     `tools/call` request from `claude-cli` in a split pane.
  4. **`spt profile edit`** TUI — the ratatui-based profile editor with
     a populated forward list.
  5. **GPO ADMX preview** — Windows Group Policy Editor showing the spt
     ADMX policies loaded (cross-platform marketing shot).
  6. **`spt diagnose`** — pre-flight check output (DNS, port reachability,
     keychain access, MTU probe).

Upload via publisher.snapcraft.io → spt → Listing → Screenshots, or via
`snapcraft push-metadata` once images are committed under
`packaging/snapcraft/screenshots/<n>.png`.

### Videos

Optional. YouTube URL, embedded on the listing page. Spec: any YouTube
public/unlisted URL.

## 3. Tracks and channels

`spt` uses the default Snap Store risk model: a single `latest` track with
the four standard risk levels.

| Risk        | Audience                           | Promotion criteria                                    |
|-------------|------------------------------------|-------------------------------------------------------|
| `edge`      | CI / nightly builders              | Every successful main-branch build auto-pushes here.  |
| `beta`      | Power users + internal QA          | Manual promotion after smoke tests pass on edge.      |
| `candidate` | Pre-release validators             | One week minimum in beta with no P0/P1 regressions.   |
| `stable`    | General public                     | One week minimum in candidate; all release-blocking issues closed. |

If the project ever needs parallel major versions, add tracks via
`snapcraft list-tracks spt` / store-request forum. Example future layout:

- `latest/{edge,beta,candidate,stable}` — current major.
- `0.x/{stable}` — long-term-support branch for the previous major.

## 4. Auto-connect declarations

Strict-confinement snaps must declare which plugs the store should
auto-connect on install. Anything not auto-connected requires the user to
run `snap connect spt:<plug>` manually.

| Plug                         | Default      | Notes                                                                                          |
|------------------------------|--------------|------------------------------------------------------------------------------------------------|
| `network`                    | auto-connect | Standard for any network client.                                                               |
| `network-bind`               | auto-connect | Required to open local forward listeners.                                                      |
| `network-observe`            | manual       | Requires store-reviewer approval for auto-connect. File a request if `spt diagnose` needs it. |
| `home`                       | auto-connect | Standard for CLI tools that read `~/.config/spt`.                                              |
| `removable-media`            | manual       | Auto-connect not granted by default; operators connect when they want to read vaults from USB. |
| `hardware-observe`           | manual       | Only needed for `spt diagnose` NIC enumeration.                                                |
| `log-observe`                | manual       | Only needed for `spt log tail --system`.                                                       |
| `mount-observe`              | manual       | Only needed for `spt diagnose` mount probing.                                                  |
| `ssh-keys`                   | auto-connect | Standard for SSH clients. Reviewers consistently grant this for SSH-shaped snaps.              |
| `password-manager-service`   | manual       | Requires reviewer approval; needed for keychain integration on GNOME-Keyring/KWallet hosts.    |
| `etc-spt` (system-files)     | manual       | `system-files` interfaces never auto-connect — store policy. Operators must `snap connect`.    |

To request additional auto-connects, file at
<https://forum.snapcraft.io/c/store-requests/19> with the snap name,
interface, and a justification paragraph per interface.

## 5. Confinement model — for store reviewers

`spt` ships with `confinement: strict`. The plug set above is the complete
list of host resources the snap touches. Specifically:

- **Network**: outbound SSH/SSH3, inbound local-forward listeners, DNS
  resolver (built-in stub binding to `127.0.0.53:53` only inside the
  sandbox; no host bind).
- **Filesystem**: `$SNAP_USER_COMMON/spt` for state, `~/.config/spt` and
  `~/.local/share/spt` via `home`, optional `/etc/spt` via the
  `system-files: etc-spt` plug (operator-connected only).
- **Keychain**: GNOME Keyring or KWallet via `password-manager-service`
  (operator-connected only).
- **Hardware**: read-only NIC and mount enumeration during `spt diagnose`
  only; no device control, no raw sockets, no CAP_NET_RAW.

The snap does NOT need classic confinement. If a future reviewer challenges
the plug list, point them at
`packaging/snap/snapcraft.yaml`'s commented confinement-rationale block.

## 6. Channel branch maps and release scripts

CI publishes from `main` to `edge` on every green build. Use
`scripts/release/promote-snap.sh <revision> <risk>` (operator-maintained,
not in repo) to promote between risks.

## 7. Placeholder substitution table

When cutting a release, replace these placeholders before running
`snapcraft pack`:

| Placeholder        | Where                                | Replace with                                  |
|--------------------|--------------------------------------|-----------------------------------------------|
| `0.1.0` (version)  | `packaging/snap/snapcraft.yaml`      | New semver string, e.g. `0.2.0`.              |
| `icon-256.png`     | `packaging/snapcraft/icon-256.png`   | Real 256×256 PNG before first stable release. |
| Screenshots `1..6` | `packaging/snapcraft/screenshots/`   | Real 1920×1080 PNG/JPEG captures.             |

## 8. References

- Snap Store publisher docs: <https://snapcraft.io/docs/releasing-your-app>
- Interface reference: <https://snapcraft.io/docs/supported-interfaces>
- Confinement model: <https://snapcraft.io/docs/snap-confinement>
- Auto-connect requests: <https://forum.snapcraft.io/c/store-requests/19>
- Track-management requests: <https://forum.snapcraft.io/c/store-requests/16>
