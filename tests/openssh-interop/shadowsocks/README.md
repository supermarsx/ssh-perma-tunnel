# Shadowsocks-2022 interop tests

Drives the `spt_obfs::shadowsocks::ShadowsocksTransport` against a
real `shadowsocks-rust` `ssserver` subprocess. Standalone workspace —
not pulled in by `cargo build --workspace` from the project root.

## Install `shadowsocks-rust` (CI Phase C)

### Linux (Ubuntu / Debian)

```bash
# Pre-built binary release (recommended for CI):
curl -L https://github.com/shadowsocks/shadowsocks-rust/releases/download/v1.20.4/shadowsocks-v1.20.4.x86_64-unknown-linux-gnu.tar.xz \
  | tar -xJ -C /usr/local/bin/ ssserver

# Verify:
ssserver --version    # expect ≥ v1.20
```

### macOS (`brew`)

```sh
brew install shadowsocks-rust
```

### Windows

Download the Windows `.zip` from
<https://github.com/shadowsocks/shadowsocks-rust/releases>, extract
`ssserver.exe` to a directory on `%PATH%` (e.g. `C:\tools\bin\`).

## Running the tests

```pwsh
$env:SPT_SS_INTEROP = "1"
cargo test --manifest-path tests/openssh-interop/shadowsocks/Cargo.toml \
    --test ss_2022_interop -- --include-ignored
```

Without `SPT_SS_INTEROP=1` the tests no-op (return early); without
`ssserver` on `$PATH` they also no-op. Both are by design so a normal
`cargo test` from a dev box passes regardless.

## Known wire gap

`crates/spt-obfs/src/shadowsocks.rs` uses AAD strings
(`b"spt-obfs/ss/len"`, `b"spt-obfs/ss/body"`) that DIVERGE from SIP022.
The four interop tests in `tests/ss_2022_interop.rs` are split into:

* `#[ignore]`'d end-to-end round-trip tests
  (`ss_2022_blake3_aes_256_gcm_round_trip`,
  `ss_2022_blake3_chacha20poly1305_round_trip`) — will fail until AAD
  reconciles. Reserved for a follow-up executor that fixes the source.
* Always-on tests
  (`ss_2022_kdf_known_vector_matches_reference`,
  `ss_2022_aead_replay_rejected`) — pin the KDF wire formula
  (`blake3::derive_key("shadowsocks 2022 session subkey", pw||salt)`)
  and the ciphertext-mauling rejection. Both pass against the current
  implementation.

See `.orchestration/logs/t8-A4.md` §wire-divergence for full detail.
