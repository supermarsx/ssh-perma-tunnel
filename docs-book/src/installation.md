# Installation

`spt` ships as a single statically-linked (or dynamically-linked against minimal
system libraries) binary named `spt`. This chapter covers every supported
installation method for release **26.46**.

## Supported platforms

CI produces signed release artifacts for exactly these five targets:

| Target triple                 | Platform                        | Package formats    |
|-------------------------------|---------------------------------|--------------------|
| `x86_64-unknown-linux-gnu`    | Linux x86\_64 (glibc)           | deb, rpm, tar.gz   |
| `aarch64-unknown-linux-gnu`   | Linux aarch64 (glibc)           | deb, rpm, tar.gz   |
| `aarch64-apple-darwin`        | macOS Apple Silicon             | pkg, tar.gz        |
| `x86_64-pc-windows-msvc`      | Windows x86\_64                 | msi, zip           |
| `aarch64-pc-windows-msvc`     | Windows arm64                   | msi, zip           |

Two notes on absent targets:

- **No musl static build.** CI does not produce a musl-linked artifact. The
  `Cross.toml` entries for musl targets exist and `scripts/build/build-target.sh`
  can build them, but that path is not invoked in CI. If you need a statically
  linked binary, build it yourself:

      cargo build --release -p spt-bin --target x86_64-unknown-linux-musl

  You will need to supply the musl toolchain (`musl-tools` on Debian/Ubuntu,
  or the `x86_64-unknown-linux-musl` rustup target plus a musl cross-compiler).

- **No macOS Intel (`x86_64-apple-darwin`) artifact.** That runner was retired.
  The macOS artifact is arm64 only, packaged as a `universal`-named file for
  path stability. Rosetta 2 on Intel Macs can run arm64 binaries, but the
  artifact is not a true fat binary.

## Installing from a release artifact

Download from the [GitHub Releases page](https://github.com/supermarsx/ssh-perma-tunnel/releases).
Substitute `26.46` for the version token in all examples below.

### Linux — deb

```sh
sudo apt install ./spt_26.46_amd64.deb       # x86_64
sudo apt install ./spt_26.46_arm64.deb       # aarch64
```

The package installs:

- `/usr/bin/spt` — the binary.
- `/lib/systemd/system/spt.service` — the systemd unit (type `notify`, runs as
  `spt:spt` with `NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp=true`).
- `/etc/spt/spt.toml` — seeded from the bundled minimal example.

Review `/etc/spt/spt.toml`, then enable the unit:

```sh
sudo systemctl enable --now spt.service
```

### Linux — rpm

```sh
sudo dnf install ./spt-26.46-1.x86_64.rpm   # x86_64
sudo dnf install ./spt-26.46-1.aarch64.rpm  # aarch64
```

The rpm layout mirrors the deb: binary, systemd unit, and seeded config.

### macOS — pkg

Run the installer package (`spt-26.46.pkg`). It places the binary at
`/usr/local/bin/spt` and installs a LaunchDaemon plist at
`/Library/LaunchDaemons/com.mariana.spt.plist`. Load it:

```sh
sudo launchctl load -w /Library/LaunchDaemons/com.mariana.spt.plist
```

For a per-user (LaunchAgent) install see [Service Management](service.md).

### Windows — msi

Run the installer (`spt-26.46.msi`) as an administrator. It places the binary
in `%PROGRAMFILES%\spt\spt.exe` and registers the service with the Service
Control Manager (start type: Automatic, recovery: restart on failure). Start it
from an elevated PowerShell:

```powershell
Start-Service spt
```

### Community package managers

These are community-maintained or alpha-stage; they are not the primary release
channel but are convenient once accepted upstream:

| Manager | Command |
|---------|---------|
| Homebrew (macOS / Linux) | `brew install Mariana/tap/spt` |
| Scoop (Windows) | `scoop bucket add spt https://github.com/supermarsx/scoop-spt && scoop install spt` |
| AUR (Arch Linux, source) | `yay -S spt` |
| AUR (Arch Linux, binary) | `yay -S spt-bin` |
| winget (Windows) | `winget install Mariana.spt` |
| Snap | `sudo snap install spt` |
| Flatpak | `flatpak install flathub io.spt.spt` |
| Nix | `nix-env -iA nixpkgs.spt` (once in nixpkgs) |

## Docker

A hardened container image is published to GitHub Container Registry:

```sh
docker pull ghcr.io/supermarsx/spt:26.46
# or pull the latest release tag
docker pull ghcr.io/supermarsx/spt:latest
```

Multi-arch manifest covers `linux/amd64` and `linux/arm64`. The image is built
from the repository-root `Dockerfile` — `debian:bookworm-slim`, non-root user
(UID/GID `65532`), default features only (pure-Rust russh, no OpenSSL FFI, no
FUSE). See [Docker](docker.md) for the full deployment guide.

## Building from source

The minimum supported Rust version (MSRV) is **1.88**, pinned by
[`rust-toolchain.toml`](../../rust-toolchain.toml). Install Rust via
[rustup](https://rustup.rs/), then:

```sh
cargo build --release -p spt-bin
sudo install -m 0755 target/release/spt /usr/local/bin/spt   # Linux / macOS
```

On Windows, copy `target\release\spt.exe` to a directory on `%PATH%`.

### System dependencies

The SSH2 backend is the pure-Rust `russh` crate (rustls + ring). **There is no
native crypto dependency**: libssl-dev, openssl-devel, Homebrew `openssl@3`,
Strawberry Perl, and similar OpenSSL build-time requirements are **not needed**
for a default build.

The following system libraries are needed only when the corresponding optional
build feature is enabled:

| Feature | What it adds | System requirement |
|---------|-------------|-------------------|
| `mount-fuse` | SFTP filesystem mounts on Linux | `libfuse-dev` (Debian/Ubuntu) or `libfuse3-devel` (Fedora) at build time; `libfuse` + `fusermount` at runtime |
| `mount-winfsp` | SFTP filesystem mounts on Windows | [Dokany2](https://github.com/dokan-dev/dokany/releases) (`choco install dokany2 -y`); links `dokan2.dll` |
| `gssapi` | GSSAPI / Kerberos auth on Unix | System MIT KRB5 or Heimdal (`libgssapi_krb5.so.2` / the macOS GSS framework) at link and runtime |

The default build (no `--features` flag) requires none of these. The TLS layer
for the SSH3 backend, remote-config fetcher, and HTTPS observability sinks uses
**rustls** exclusively — no OpenSSL involvement anywhere in the default build.

### Cross-compilation

`Cross.toml` pins the `cross-rs` Docker images for the four Linux targets
(`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, and their musl
counterparts). Install [cross](https://github.com/cross-rs/cross) and pass the
target triple:

```sh
cross build --release -p spt-bin --target aarch64-unknown-linux-gnu
```

## Performance / native builds

The **default distributed binaries are fully portable**. They use the baseline
instruction set for each architecture (generic `x86_64` / `aarch64`) and run on
**any** CPU of that architecture, old or new. This is the artifact you get from
the Releases page, every package manager, and the Docker image. Nothing about
that changes.

For modern desktops and servers, CI additionally publishes an **optional,
CPU-optimized `-v3` artifact** built with a raised compile-time baseline. It is
a *supplementary* download — never the default — produced by the separate
[`build-native.yml`](https://github.com/supermarsx/ssh-perma-tunnel/blob/main/.github/workflows/build-native.yml)
workflow (on release tags and on demand). Look for the `-v3` suffix:

| Artifact | Baseline | Runs on |
|----------|----------|---------|
| `spt-x86_64-unknown-linux-gnu` (default) | generic `x86_64` | **any** x86_64 CPU |
| `spt-x86_64-unknown-linux-gnu-v3` | `x86-64-v3` (AVX2 / FMA / BMI2) | x86_64 CPUs from **~2015 onward** (Intel Haswell+, AMD Excavator/Zen+) |
| `spt-x86_64-pc-windows-msvc-v3` | `x86-64-v3` | same as above (Windows) |
| `spt-aarch64-unknown-linux-gnu-v3` | `neoverse-n1` | modern ARM server cores (AWS Graviton2-class) |

**The `-v3` binary requires an AVX2-capable CPU** (any x86_64 chip from roughly
2015 on). On an older CPU it will fault with an illegal-instruction error — use
the default portable binary there. If unsure, use the default; it is universal.

### What the optimization actually buys

- **X25519 key exchange (the main win).** `curve25519-dalek` selects its
  AVX2/AVX512 SIMD field backend at **compile time** from the target feature
  set. The portable build gets the serial backend; raising the baseline to
  include AVX2 switches dalek to its SIMD backend automatically, speeding up
  every SSH/TLS handshake's elliptic-curve math.
- **General autovectorization / codegen** across the workspace.

What the `-v3` artifact does **not** change, because it is already accelerated
at runtime regardless of the compile baseline:

- **Symmetric crypto** (AES-GCM, ChaCha20, SHA) — RustCrypto uses `cpufeatures`
  to pick AES-NI / SHA-NI / AVX2 / NEON paths at **runtime**.
- **TLS** — `ring` ships hand-written assembly with runtime CPU detection.

So on the symmetric-crypto and TLS hot paths the default portable binary is
already using your CPU's acceleration; the `-v3` artifact's edge is concentrated
in the compile-time-selected X25519 path and general codegen.

### Build a fully-native binary yourself

To squeeze out the maximum for *your specific machine* (not portable — pins to
the exact build host's microarchitecture), build with `target-cpu=native`:

```sh
RUSTFLAGS="-C target-cpu=native" cargo build --release -p spt-bin
```

```powershell
# Windows PowerShell
$env:RUSTFLAGS = "-C target-cpu=native"; cargo build --release -p spt-bin
```

The resulting binary is tuned for the CPU that compiled it and may crash with an
illegal-instruction fault on a different (older) CPU — never redistribute it as
a general artifact. To reproduce the CI `-v3` middle ground instead, substitute
`x86-64-v3` (x86_64) or `neoverse-n1` (aarch64) for `native`.

## Verifying release artifacts

Each release ships three integrity files: `SHA256SUMS`, `SHA512SUMS`, and
(when available) `B3SUMS`. Every artifact also has a `.minisig` sibling
produced with the project's minisign key (public key at
`packaging/minisign.pub`).

**Checksum verification:**

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

**minisign verification:**

```sh
minisign -V -p packaging/minisign.pub -m spt-26.46-x86_64-unknown-linux-gnu.tar.gz
```

Optional per-platform signatures may also be present:

- **Linux:** `.asc` detached GPG signatures when `LINUX_GPG_KEY` was set during
  the release workflow.
- **macOS:** the `.pkg` may be codesigned with a Developer ID certificate and
  notarized via Apple's notary service (stapled). Verify with `spctl -a -v
  spt-26.46.pkg` after download.
- **Windows:** the `.msi` and `.exe` may carry an Authenticode signature; verify
  with `signtool verify /pa spt-26.46.msi`.

The presence of optional signatures depends on whether the signing secrets were
configured in the CI environment at release time; checksums and minisign
signatures are always present.

## Portable mode

Running `spt --portable` confines every on-disk artifact (state, vault,
logs) to a self-contained tree next to the binary and skips all OS-level
side-effects:

| Subsystem | Default | With `--portable` |
|-----------|---------|------------------|
| State dir | platform data dir (`~/.local/state/spt`, `%LOCALAPPDATA%\spt`, …) | `<exe-dir>/data/state/` |
| Secrets resolver | keychain → vault → env → file | vault → env → file (keychain skipped) |
| Vault master key | OS keychain | `<exe-dir>/data/vault/master.key` (mode `0600` on Unix) |
| `~/.ssh/config` | read by `-J` chains | never read |
| journald / Event Log | available | no-op |

This makes `spt` fully self-contained: useful for USB/network-share deployments,
sandboxed CI, or environments where writing to the user profile is undesirable.
The portable root is created on first launch; if `<exe-dir>/data/` is not
writable `spt` exits with `RuntimeFailure` rather than silently corrupting state.
An explicit `--state-dir` always overrides the portable anchor.

## Uninstalling

```sh
# deb
sudo apt remove spt

# rpm
sudo dnf remove spt

# macOS pkg (manual)
sudo rm /usr/local/bin/spt
sudo launchctl unload /Library/LaunchDaemons/com.mariana.spt.plist
sudo rm /Library/LaunchDaemons/com.mariana.spt.plist

# Windows msi
msiexec /x spt-26.46.msi

# Docker image
docker image rm ghcr.io/supermarsx/spt:26.46
```

## Where next

- [Quick Start](quick-start.md) — a first working tunnel in five minutes.
- [Docker](docker.md) — hardened container deployment guide.
- [Service Management](service.md) — installing `spt` as a long-running service.
