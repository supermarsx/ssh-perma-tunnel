# Conformance test fixtures

This directory holds the seed material the `docker-compose.yml` services
mount as read-only volumes. Files marked **(generate)** are intentionally
NOT committed — they are generated on first use by the CI workflow (or by
running `./scripts/generate.sh` locally) and live entirely under the
tester's control.

## Files

| Path | Purpose | Committed? |
|------|---------|------------|
| `spt_test_ed25519`        | Client-side ed25519 private key, no passphrase. Used for `auth.method = "publickey"` cells. | (generate) |
| `spt_test_ed25519.pub`    | Matching public key — copied into every server's `authorized_keys`. | (generate) |
| `host_keys/openssh/`      | Pre-generated OpenSSH host keys (rsa + ed25519 + ecdsa). Keeps `known_hosts` deterministic across container rebuilds. | (generate) |
| `host_keys/dropbear/`     | Pre-generated Dropbear host keys (`dropbear_ed25519_host_key`, `dropbear_rsa_host_key`). | (generate) |
| `host_keys/libssh/`       | Pre-generated libssh-server host keys. | (generate) |
| `sshd_config.d/openssh.conf` | Drop-in to enable both `AllowTcpForwarding yes` and `GatewayPorts clientspecified` on the OpenSSH service. | yes |

## Why aren't the keys committed?

These are *test* keys with no real-world value, but committing private SSH
keys to a public repo trips secret-scanners (GitHub, GitGuardian, ...) and
adds noise to every PR diff. Generating them on demand keeps the diff
clean and lets each CI run regenerate them if needed.

## Generation

```sh
cd tests/conformance/fixtures
mkdir -p host_keys/{openssh,dropbear,libssh}

# Client key.
ssh-keygen -t ed25519 -N "" -C "spt-conformance" -f spt_test_ed25519

# OpenSSH host keys.
ssh-keygen -t rsa     -b 3072 -N "" -f host_keys/openssh/ssh_host_rsa_key
ssh-keygen -t ed25519        -N "" -f host_keys/openssh/ssh_host_ed25519_key
ssh-keygen -t ecdsa   -b 256 -N "" -f host_keys/openssh/ssh_host_ecdsa_key

# Dropbear host keys (requires `dropbearkey` from the dropbear package).
dropbearkey -t ed25519 -f host_keys/dropbear/dropbear_ed25519_host_key
dropbearkey -t rsa     -f host_keys/dropbear/dropbear_rsa_host_key

# libssh host keys: ed25519 + rsa work; libssh's example loads any.
ssh-keygen -t rsa     -b 3072 -N "" -f host_keys/libssh/ssh_host_rsa_key
ssh-keygen -t ed25519        -N "" -f host_keys/libssh/ssh_host_ed25519_key
```

## Container bring-up

```sh
cd tests/conformance
docker compose up -d
docker compose ps   # verify all three are healthy
SPT_CONFORMANCE=1 cargo test -p spt-conformance-tests --test matrix -- --ignored
docker compose down -v
```
