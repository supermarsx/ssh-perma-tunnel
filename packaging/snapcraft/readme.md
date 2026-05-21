# Snap packaging assets

This directory holds the Snap Store submission materials that live *outside*
the snap itself (icon, store metadata, screenshots, listing copy). The build
recipe lives next door at `packaging/snap/snapcraft.yaml`.

For the full submission flow — categories, channels, auto-connect requests,
reviewer notes — see [`store-listing.md`](./store-listing.md).

## Local build

From the repository root:

```sh
# Clean, reproducible build inside an LXD VM (recommended).
snapcraft --use-lxd

# Or, inside a throwaway Ubuntu 22.04 container:
snapcraft --destructive-mode

# The build emits e.g. spt_0.1.0_amd64.snap in the repo root.
sudo snap install --dangerous ./spt_0.1.0_amd64.snap
snap run spt --version
snap run spt tunnel --help

# Lint (snapcraft 7.3+):
snapcraft lint spt_0.1.0_amd64.snap
```

## Store submission flow (short form)

```sh
snapcraft login
snapcraft register spt              # one-time, ever
snapcraft pack                      # or `snapcraft --use-lxd` for clean build
snapcraft upload spt_0.1.0_amd64.snap --release=edge
# ...promote across channels as confidence grows...
snapcraft release spt <REVISION> stable
```

Full per-channel promotion criteria are in
[`store-listing.md`](./store-listing.md#3-tracks-and-channels).

## Files in this directory

| File                   | Purpose                                                                                                   |
|------------------------|-----------------------------------------------------------------------------------------------------------|
| `icon-256.png`         | 256×256 app icon referenced from `packaging/snap/snapcraft.yaml`. **Placeholder — replace before release.** |
| `store-listing.md`     | The complete Snap Store submission runbook.                                                               |
| `readme.md`            | This file.                                                                                                |
| `screenshots/<n>.png`  | (Not committed) 1920×1080 screenshots. Operator-supplied.                                                 |

## Placeholder substitution table

| Placeholder                                  | Replace with                                                                              |
|----------------------------------------------|-------------------------------------------------------------------------------------------|
| `icon-256.png` (1×1 placeholder PNG)         | Real 256×256 brand icon, transparent background allowed.                                  |
| `version: '0.1.0'` in snapcraft.yaml         | The new semver string for this release.                                                   |
| `<REVISION>` in store-listing.md examples    | The integer revision printed by `snapcraft upload`.                                       |
| `Mariana/ssh-perma-tunnel` in contact URLs   | Whatever the canonical GitHub org/repo ends up being at publication time.                 |
| Banner image (uploaded via web UI)           | A 1920×1080 banner; not stored in the repo.                                               |

## Why the icon is a placeholder

Generating a real 256×256 brand-quality PNG from inside an agent host is
neither in-scope for packaging code nor a reproducible artifact. The shipped
`icon-256.png` is a minimal valid PNG so `snapcraft pack` succeeds; operators
must replace it with a real icon before pushing to the `stable` channel.
The store reviewer will flag a placeholder icon during review and reject
the snap if it ships as-is.

## Validation commands

| What                               | Command                                                |
|------------------------------------|--------------------------------------------------------|
| YAML parses                        | `python3 -c 'import yaml; yaml.safe_load(open("packaging/snap/snapcraft.yaml"))'` |
| snapcraft thinks it's well-formed  | `snapcraft expand-extensions` (dry-run, prints merged YAML) |
| Built snap lints clean             | `snapcraft lint spt_<VER>_amd64.snap`                  |
| Plug list is what we think it is   | `snap connections spt` (after `snap install --dangerous`) |
