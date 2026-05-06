# RPM packaging

This directory holds RPM-specific assets. The actual RPM is produced by
[`cargo-generate-rpm`](https://github.com/cat-in-136/cargo-generate-rpm) which
reads `crates/spt-bin/Cargo.toml` `[package.metadata.generate-rpm]`.

CI flow on a Fedora / RHEL builder:

```
cargo build --release -p spt-bin
cargo generate-rpm -p crates/spt-bin
```

The systemd unit ships from `/packaging/systemd/spt.service`. CI is expected
to install it under `/lib/systemd/system/`.
