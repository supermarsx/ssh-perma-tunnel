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
rm -f keys/test_ed25519 keys/test_ed25519.pub
rm -f keys/test_rsa keys/test_rsa.pub
rm -f host_keys/ssh_host_ed25519_key host_keys/ssh_host_ed25519_key.pub
rm -f host_keys/ssh_host_rsa_key host_keys/ssh_host_rsa_key.pub

# Client keys.
ssh-keygen -t ed25519 -N "" -C "spt-interop-test-ed25519" -f keys/test_ed25519
ssh-keygen -t rsa -b 3072 -N "" -C "spt-interop-test-rsa" -f keys/test_rsa

# Host keys.
ssh-keygen -t ed25519 -N "" -C "spt-interop-host-ed25519" -f host_keys/ssh_host_ed25519_key
ssh-keygen -t rsa -b 3072 -N "" -C "spt-interop-host-rsa" -f host_keys/ssh_host_rsa_key

# Permissions matter for sshd host keys (must be 0600, root-readable inside
# the container). The linuxserver image runs as PUID 1000; the read-only
# bind mount carries the host-side mode through.
chmod 600 keys/test_ed25519 keys/test_rsa
chmod 600 host_keys/ssh_host_ed25519_key host_keys/ssh_host_rsa_key
chmod 644 keys/test_ed25519.pub keys/test_rsa.pub
chmod 644 host_keys/ssh_host_ed25519_key.pub host_keys/ssh_host_rsa_key.pub

echo "fixtures generated:"
ls -la keys host_keys
