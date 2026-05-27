# Installation

`spt` ships a single binary `spt` plus a per-OS service definition.

## Supported platforms

- Linux x86_64 / aarch64 (glibc + musl)
- macOS x86_64 / aarch64
- Windows x86_64

The minimum supported Rust version (MSRV) for source builds is 1.85.

Releases use the rolling `YY.N` scheme (current: `26.1`; e.g. `26.2`
next, then `27.1` on the year roll-over). Examples below reference
`26.1`; substitute the latest tag from the
[releases page](../docs/releases/) when installing.

## Linux packages

### deb

    sudo apt install ./spt_26.1_amd64.deb

The package installs `/usr/bin/spt`, `/lib/systemd/system/spt.service`, and
seeds `/etc/spt/spt.toml` from the bundled minimal example. Review the config
first, then enable the unit:

    sudo systemctl enable --now spt.service

### rpm

    sudo dnf install ./spt-26.1-1.x86_64.rpm

### musl static, no package

    curl -L -o spt https://example.invalid/releases/spt-26.1-x86_64-linux-musl
    chmod +x spt && sudo install -m 0755 spt /usr/local/bin/spt

## macOS (pkg)

Run the installer; it places `/usr/local/bin/spt` and a launch daemon plist
at `/Library/LaunchDaemons/com.mariana.spt.plist`. Load:

    sudo launchctl load -w /Library/LaunchDaemons/com.mariana.spt.plist

A user-scope (LaunchAgent) install is also available — see
[Service Integration](service-integration.md).

## Windows (msi)

The installer registers the service via SCM. Open an elevated PowerShell:

    Start-Service spt

## Building from source

    cargo build --release -p spt-bin
    sudo install -m 0755 target/release/spt /usr/local/bin/spt

### System dependencies

The SSH2 runtime is the pure-Rust `russh` crate (the legacy `libssh2`
compatibility lane was removed in t7). `spt` itself therefore has **no
native crypto dependency** — Strawberry Perl, libssl-dev, openssl-devel,
and Homebrew `openssl@3` are **not** required to build `spt` from source.

Per-platform notes for optional features:

- **Windows** — the `mount-winfsp` build feature pulls the `dokan` crate
  (MIT) which links against the system `dokan2.dll`. Install via
  Chocolatey: `choco install dokany2 -y`. Default builds (without
  `mount-winfsp`) have no native dependency.
- **Linux** — the `mount-fuse` build feature pulls `fuser 0.15`, which
  needs `libfuse` headers at build time (`sudo apt install libfuse-dev`
  on Debian/Ubuntu; `libfuse3-devel` on Fedora). At runtime the `spt`
  user needs read access to `/dev/fuse` and `fusermount` on `$PATH`.
- **macOS** — SFTP mounts shell out to `sshfs` + macFUSE (deprecation
  warned, see [SFTP](sftp.md)). `brew install --cask macfuse` then
  `brew install gromgit/fuse/sshfs-mac`.
- **Unix Kerberos / GSSAPI** — the `gssapi` build feature pulls the
  vendored `libgssapi` fork (`vendor/libgssapi-fork/`) and links against
  the system MIT KRB5 or Heimdal GSSAPI library (`libgssapi_krb5` on
  Linux, the GSS framework on macOS).

The TLS layer used by the SSH3 backend, the remote-config fetcher, and
all HTTPS event sinks is **rustls** end-to-end (no OpenSSL involvement),
per the spec's "single TLS stack" mandate.

## Verifying signatures

Releases are signed. Each artifact has an accompanying signature:

    sha256sum --check spt-26.1.SHA256

## Uninstalling

    sudo apt remove spt
    sudo dnf remove spt
    msiexec /x spt-26.1.msi
