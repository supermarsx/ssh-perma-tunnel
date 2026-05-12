#!/usr/bin/env bash
set -euo pipefail

: "${SPT_HOST_KEY_BASENAME:?SPT_HOST_KEY_BASENAME is required}"

src_dir=/fixtures/host_keys
dst_dir=/config/ssh_host_keys

copy_host_key() {
    local basename=$1
    local private_src="${src_dir}/${basename}"
    local public_src="${private_src}.pub"
    local private_dst="${dst_dir}/${basename}"
    local public_dst="${private_dst}.pub"

    if [[ ! -f "${private_src}" || ! -f "${public_src}" ]]; then
        echo "missing OpenSSH host key fixture: ${private_src} or ${public_src}" >&2
        exit 1
    fi

    cp "${private_src}" "${private_dst}"
    cp "${public_src}" "${public_dst}"
    chown "${PUID:-1000}:${PGID:-1000}" "${private_dst}" "${public_dst}"
    chmod 600 "${private_dst}"
    chmod 644 "${public_dst}"
}

mkdir -p "${dst_dir}"
rm -f "${dst_dir}"/ssh_host_*_key "${dst_dir}"/ssh_host_*_key.pub
copy_host_key "${SPT_HOST_KEY_BASENAME}"

# Windows libssh2/WinCNG builds do not negotiate ED25519 host keys. Keep a
# deterministic RSA host key available in the ED25519-labeled container so
# Windows tests can still validate pinning against the key actually negotiated.
if [[ "${SPT_HOST_KEY_BASENAME}" != "ssh_host_rsa_key" ]]; then
    copy_host_key ssh_host_rsa_key
fi

sshd_config=/config/sshd/sshd_config
set_sshd_option() {
    local key=$1
    local value=$2
    if grep -Eq "^#?${key}[[:space:]]+" "${sshd_config}"; then
        sed -i -E "s|^#?${key}[[:space:]].*|${key} ${value}|" "${sshd_config}"
    else
        printf '%s %s\n' "${key}" "${value}" >> "${sshd_config}"
    fi
}

set_sshd_option AllowTcpForwarding yes
set_sshd_option GatewayPorts yes

auth_dir=/config/.ssh
auth_file="${auth_dir}/authorized_keys"
mkdir -p "${auth_dir}"
cat /fixtures/keys/test_ed25519.pub /fixtures/keys/test_rsa.pub > "${auth_file}"
chown "${PUID:-1000}:${PGID:-1000}" "${auth_dir}" "${auth_file}"
chmod 700 "${auth_dir}"
chmod 600 "${auth_file}"
