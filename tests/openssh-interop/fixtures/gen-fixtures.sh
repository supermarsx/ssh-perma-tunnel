#!/bin/sh
# Regenerate the OpenSSH-interop fixture keypairs.
#
# Generates:
#   * client keypairs in keys/ (consumed by the `spt` binary under test)
#   * sshd host keys in host_keys/ (mounted into the docker containers)
#
# All keys are unencrypted (no passphrase) — the password-auth test uses a
# separately-configured account password, not a key passphrase.

set -eu

cd "$(dirname "$0")"
mkdir -p keys host_keys

# Wipe any pre-existing material so ssh-keygen doesn't prompt for overwrite.
# Docker creates missing file bind-mount sources as directories, so this must
# tolerate directory placeholders from an interrupted interop setup.
rm -rf keys/test_ed25519 keys/test_ed25519.pub
rm -rf keys/test_rsa keys/test_rsa.pub
rm -rf host_keys/ssh_host_ed25519_key host_keys/ssh_host_ed25519_key.pub
rm -rf host_keys/ssh_host_rsa_key host_keys/ssh_host_rsa_key.pub

# Client keys.
ssh-keygen -t ed25519 -N "" -C "spt-interop-test-ed25519" -f keys/test_ed25519
ssh-keygen -t rsa -b 3072 -N "" -C "spt-interop-test-rsa" -f keys/test_rsa

# Host keys.
ssh-keygen -t ed25519 -N "" -C "spt-interop-host-ed25519" -f host_keys/ssh_host_ed25519_key
ssh-keygen -t rsa -b 3072 -N "" -C "spt-interop-host-rsa" -f host_keys/ssh_host_rsa_key

# Keep local fixtures tidy on POSIX filesystems. On Windows mounts these chmod
# calls can fail; container host keys are copied and chmodded at startup.
chmod_or_warn() {
    if ! chmod "$@"; then
        echo "warning: chmod $* failed; continuing" >&2
    fi
}

chmod_or_warn 600 keys/test_ed25519 keys/test_rsa
chmod_or_warn 600 host_keys/ssh_host_ed25519_key host_keys/ssh_host_rsa_key
chmod_or_warn 644 keys/test_ed25519.pub keys/test_rsa.pub
chmod_or_warn 644 host_keys/ssh_host_ed25519_key.pub host_keys/ssh_host_rsa_key.pub

echo "fixtures generated:"
ls -la keys host_keys
