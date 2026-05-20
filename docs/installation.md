# Installation

`spt` ships a single binary `spt` plus a per-OS service definition.

## Supported platforms

- Linux x86_64 / aarch64 (glibc + musl)
- macOS x86_64 / aarch64
- Windows x86_64

The minimum supported Rust version (MSRV) for source builds is 1.83.

## Linux packages

### deb

    sudo apt install ./spt_0.1.0_amd64.deb

The package installs `/usr/bin/spt`, `/lib/systemd/system/spt.service`, and
seeds `/etc/spt/spt.toml` from the bundled minimal example. Review the config
first, then enable the unit:

    sudo systemctl enable --now spt.service

### rpm

    sudo dnf install ./spt-0.1.0-1.x86_64.rpm

### musl static, no package

    curl -L -o spt https://example.invalid/releases/spt-0.1.0-x86_64-linux-musl
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

The production SSH2 runtime uses the pure-Rust `russh` backend. The workspace
still builds the legacy `libssh2` compatibility lane via `libssh2-sys`, so the
legacy crypto backend is selected per platform:

- **Windows** — uses **WinCNG** (Windows native crypto, BCryptPrimitives).
  No native dependencies required. In particular, **Strawberry Perl /
  OpenSSL are not needed**: the workspace deliberately disables the
  `vendored-openssl` feature on `ssh2` / `async-ssh2-lite` so
  `libssh2-sys` falls back to its WinCNG path.
- **Linux** — requires the system **OpenSSL development headers**:
  - Debian / Ubuntu: `sudo apt install libssl-dev pkg-config`
  - Fedora / RHEL: `sudo dnf install openssl-devel pkgconfig`
  - Alpine (musl): `apk add openssl-dev pkgconfig`
- **macOS** — requires OpenSSL via Homebrew:
  `brew install openssl@3 pkg-config`. If `cargo build` cannot find
  OpenSSL, set `OPENSSL_DIR=$(brew --prefix openssl@3)` before building.

The TLS layer used by the SSH3 backend, the remote-config fetcher, and
all HTTPS event sinks is **rustls** end-to-end (no OpenSSL involvement),
per the spec's "single TLS stack" mandate.

## Verifying signatures

Releases are signed. Each artifact has an accompanying signature:

    sha256sum --check spt-0.1.0.SHA256

## Uninstalling

    sudo apt remove spt
    sudo dnf remove spt
    msiexec /x spt-0.1.0.msi
