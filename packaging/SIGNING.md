# Signing & integrity

This document describes the trust chain for spt release artifacts.

## Layers

1. **Checksums (always)** — Every release directory ships
   `SHA256SUMS`, `SHA512SUMS`, and (when `b3sum` is on `PATH`) `B3SUMS`.
   Produced by `scripts/sign/checksum-all.sh`.

2. **minisign (always, once configured)** — Each artifact has a sibling
   `<file>.minisig` produced by `scripts/sign/minisign-all.sh`. The public
   key is committed at `packaging/minisign.pub`; verify with:

   ```sh
   minisign -V -p packaging/minisign.pub -m spt-<version>-<target>.tar.gz
   ```

   Generate the keypair once with `minisign -G -p packaging/minisign.pub
   -s ~/.minisign/spt.key`, commit the public key, and provision the
   secret key as the `MINISIGN_SECRET_KEY` CI secret (file contents, not
   path). Optional `MINISIGN_PASSWORD` unlocks an encrypted key.

3. **Per-artifact GPG (optional)** — `scripts/sign/sign-linux.sh` produces
   `<file>.asc` for every artifact when `LINUX_GPG_KEY` (key id) is set.
   `scripts/sign/checksum-all.sh` will additionally detach-sign
   `SHA256SUMS` -> `SHA256SUMS.asc` if the same env var is set.

4. **macOS Developer ID (optional)** — `scripts/sign/sign-macos.sh`
   codesigns the .pkg with `MACOS_SIGNING_IDENTITY` and notarizes via
   `xcrun notarytool` if either Apple-ID creds (`MACOS_NOTARY_USER`,
   `MACOS_NOTARY_PASSWORD`, `MACOS_NOTARY_TEAM_ID`) or App Store Connect
   API key (`MACOS_NOTARY_KEY_PATH`, `MACOS_NOTARY_KEY_ID`,
   `MACOS_NOTARY_ISSUER`) are set. The pkg is stapled on success.

5. **Windows Authenticode (optional)** — `scripts/sign/sign-windows.ps1`
   signs `spt*.exe` and `spt*.msi` under `dist/<version>/` using
   `signtool` with a base64-encoded PFX from `WINDOWS_SIGNING_CERT_BASE64`
   and password from `WINDOWS_SIGNING_PASSWORD`. Default RFC-3161 TSA is
   `http://timestamp.digicert.com`; override with `WINDOWS_TIMESTAMP_URL`.

## Verification recipes

Tarball:

```sh
sha256sum -c SHA256SUMS --ignore-missing
minisign -V -p packaging/minisign.pub -m spt-<v>-<target>.tar.gz
gpg --verify spt-<v>-<target>.tar.gz.asc           # if .asc present
```

macOS pkg:

```sh
pkgutil --check-signature spt-<v>-universal.pkg
spctl -a -v --type install spt-<v>-universal.pkg
```

Windows MSI/EXE:

```ps
Get-AuthenticodeSignature spt-<v>-<target>.msi
```

## Threat model summary

- **Checksums** detect bit-rot and accidental corruption only.
- **minisign** is the project-controlled cryptographic root — the public
  key in this repo is the trust anchor. A repo compromise that swaps
  both binary and minisig + public key defeats the chain; mirror the
  `minisign.pub` out-of-band (web page, manpage, package channel).
- **GPG / Authenticode / Developer ID** add platform-native trust paths
  (web of trust, Microsoft Trusted Root, Apple notarization) that don't
  depend on this repo's git history.
