# spt build & release scripts

Reproducible cross-arch build pipeline drivable both locally and from CI.

## Target matrix

| Target triple | Native build host | Tarball | Deb | RPM | PKG | MSI/Zip |
| --- | --- | --- | --- | --- | --- | --- |
| `x86_64-unknown-linux-gnu`   | Linux x64                  | yes | yes | yes | -   | -   |
| `x86_64-unknown-linux-musl`  | Linux x64 + cross/musl     | yes | -   | -   | -   | -   |
| `aarch64-unknown-linux-gnu`  | Linux ARM64 / cross        | yes | yes | yes | -   | -   |
| `aarch64-unknown-linux-musl` | cross + musl               | yes | -   | -   | -   | -   |
| `x86_64-apple-darwin`        | macOS Intel / AS (cross)   | yes | -   | -   | (universal) | - |
| `aarch64-apple-darwin`       | macOS AS / Intel (cross)   | yes | -   | -   | (universal) | - |
| `x86_64-pc-windows-msvc`     | Windows                    | -   | -   | -   | -   | yes |
| `aarch64-pc-windows-msvc`    | Windows (cross-supported)  | -   | -   | -   | -   | yes |

The macOS PKG is one universal binary built via `lipo` from the two
`apple-darwin` per-arch binaries.

## Local flow (Linux/macOS)

```sh
# Build everything reachable from this host
bash scripts/build/build-all-local.sh

# Package what was built
bash scripts/package/pack-all.sh

# Checksum + minisign
bash scripts/sign/checksum-all.sh
bash scripts/sign/minisign-all.sh   # needs MINISIGN_SECRET_KEY env

# Manifest
bash scripts/release/manifest.sh

# Results: dist/<version>/
```

## Local flow (Windows)

```ps
.\scripts\build\build-all-local.ps1
.\scripts\package\pack-zip.ps1 -Target x86_64-pc-windows-msvc
.\scripts\package\pack-msi-windows.ps1 -Target x86_64-pc-windows-msvc
.\scripts\sign\sign-windows.ps1     # needs WINDOWS_SIGNING_CERT_BASE64 + WINDOWS_SIGNING_PASSWORD
```

For the six non-Windows targets, run the Linux/macOS flow on a host of
the matching family. cross-rs from Windows is not supported here.

## Required tools per host

| Tool | Used by | Required on |
| --- | --- | --- |
| `cargo` (MSRV 1.83 — pinned by `rust-toolchain.toml`) | every build script | all hosts |
| `cross` (`cargo install cross --locked`) | Linux non-native builds | Linux build hosts |
| `docker` (with `buildx`) | `cross`, `scripts/docker/build-image.sh` | Linux build hosts, container builds |
| `lipo` (Apple Command Line Tools) | `scripts/build/lipo-macos.sh` | macOS |
| `pkgbuild`, `productbuild` | `scripts/package/pack-pkg-macos.sh` | macOS |
| `cargo-deb` (`cargo install cargo-deb --locked`) | `pack-deb.sh` | Linux |
| `cargo-generate-rpm` | `pack-rpm.sh` | Linux |
| `cargo-wix` | `pack-msi-windows.ps1` | Windows |
| `cargo-cyclonedx@0.5.7` | `gen-sbom.sh` | any (auto-installed if absent) |
| `minisign` | `minisign-all.sh` | any |
| `b3sum` (optional) | `checksum-all.sh` | any |
| `gpg` (optional) | `sign-linux.sh`, `checksum-all.sh` | any |
| `signtool` (Windows SDK) | `sign-windows.ps1` | Windows |

All optional-secret-driven steps degrade with a `warn:` line and skip
rather than failing — so unauthenticated forks can still produce
unsigned artifacts.

## Signing material

See [`packaging/SIGNING.md`](../../packaging/SIGNING.md) for the trust
chain. tl;dr:

- `MINISIGN_SECRET_KEY` (CI secret) — required for project-level
  cryptographic provenance. Public key lives at `packaging/minisign.pub`.
- `MACOS_SIGNING_IDENTITY` (+ notary creds) — optional macOS Developer ID.
- `WINDOWS_SIGNING_CERT_BASE64` (+ password) — optional Authenticode.
- `LINUX_GPG_KEY` — optional GPG detach-signatures.

## CI consumption

`.github/workflows/release.yml` (owned by the `f-build-ci` executor)
calls these scripts directly. Keep their CLI shapes stable; the workflow
treats them as a public API.

## Layout

```
scripts/
├── build/      one-target build, lipo, strip, helpers
├── package/    tarball / zip / deb / rpm / pkg / msi
├── sign/       minisign / checksums / GPG / codesign / Authenticode
├── sbom/       cargo-cyclonedx wrapper
├── docker/     scratch + buildx image
└── release/    prepare / collect / manifest / publish
```

## Quality bar

- `bash -n scripts/**/*.sh` passes (syntax check).
- `pwsh -NoProfile -File <script> -Help` exits 0.
- shellcheck-clean where shellcheck is available.
- Reproducible-ish: `--locked` everywhere, `SOURCE_DATE_EPOCH`,
  `-C codegen-units=1` (set in `Cargo.toml` workspace `[profile.release]`),
  `-C strip=symbols`, sorted/owner-zeroed tar.
