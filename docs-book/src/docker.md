# Docker

`spt` ships a hardened container image defined by the repository-root
`Dockerfile` and `docker-compose.yml`. This is the recommended way to run
`spt` in a container when the default feature set suffices. The image is
published to GitHub Container Registry; you can also build it locally.

## What the image contains

The build uses a two-stage Dockerfile. The builder stage compiles the workspace
with `--release --locked` against the committed `Cargo.lock` using `rust:1.88-bookworm`.
The runtime stage is `debian:bookworm-slim` with:

- `/usr/local/bin/spt` — the stripped `spt` binary, built with **default
  features only** (pure-Rust `russh` SSH2 backend, no libssh2 FFI, no
  vendored OpenSSL, no FUSE).
- `libdbus-1-3` — pulled in by `spt-secrets`' `sync-secret-service` backend
  (always-on crate dependency).
- `libgssapi-krb5-2` — pulled in by `spt-auth-sspi`'s Unix GSSAPI backend
  (always-on crate dependency; Kerberos is linked but not usable without a
  `krb5.conf` / keytab mounted at runtime).
- `ca-certificates` — for rustls to validate HTTPS observability sinks.
- `tini` — clean PID-1: forwards SIGTERM/SIGINT to `spt` and reaps zombies.

A non-root system user (`spt`, UID/GID `65532`) is created in the image and
set as `USER`. Package lists are removed after `apt` to reduce CVE surface.

### Why debian-slim and not distroless

`gcr.io/distroless/cc-debian12:nonroot` ships none of the transitive
dependencies of `libdbus-1` and `libgssapi_krb5` (libsystemd, libcap,
libgcrypt, libkrb5*, liblzma, libzstd, …). Copying that entire chain
manually and keeping it in sync is brittle. The image therefore uses
`debian:bookworm-slim` with a non-root user; `cap_drop: [ALL]`,
`read_only: true`, and `no-new-privileges` in the compose profile neutralise
the shell and `apt` at runtime. The apt package lists are removed to reduce the
layer size and CVE exposure.

### Hardening properties at a glance

| Property | How |
|----------|-----|
| Minimal runtime | Only `libdbus-1-3`, `libgssapi-krb5-2`, `ca-certificates`, and `tini` |
| Non-root | Runs as `spt` (UID/GID `65532`); asserted in both image and compose |
| Binary only | No source, no build tools, no secrets in the image |
| Reproducible | `cargo build --release --locked` against the committed `Cargo.lock` |
| Read-only rootfs | `read_only: true` in compose; only an explicit state volume and `/tmp` tmpfs are writable |
| No privilege escalation | `security_opt: no-new-privileges:true`, `cap_drop: [ALL]` |
| Bounded blast radius | `mem_limit`, `memswap_limit`, `pids_limit`, `cpus`, `ulimits`, size-bounded tmpfs, capped JSON logs |

## Pulling the published image

```sh
# Pull a specific release
docker pull ghcr.io/supermarsx/spt:26.46

# Pull the latest release tag
docker pull ghcr.io/supermarsx/spt:latest
```

The multi-arch manifest covers `linux/amd64` and `linux/arm64`.

## Building the image locally

From the repository root (BuildKit cache mounts make repeat builds fast):

```sh
docker build -t spt:hardened .
```

The first build is slow because it compiles the full workspace. Subsequent
builds reuse the cargo registry and git caches.

Confirm the binary works and runs as a non-root user:

```sh
docker run --rm spt:hardened --version
docker run --rm spt:hardened tunnel --help
```

## Running with Docker Compose

The `docker-compose.yml` in the repository root is the canonical hardened
deployment. It pairs directly with the root `Dockerfile`.

```sh
# 1. Build the image.
docker build -t spt:hardened .

# 2. Prepare the config directory.
mkdir -p config
cp packaging/docker/example-config/spt.toml config/spt.toml
# Edit config/spt.toml to match your environment.

# 3. Start.
docker compose up -d

# 4. Watch logs.
docker compose logs -f
```

Validate the compose file without starting anything:

```sh
docker compose -f docker-compose.yml config
```

### The compose service block

Below is the complete hardened service definition from `docker-compose.yml`,
annotated for reference. Operators should read every line before relaxing a
control.

```yaml
services:
  spt:
    image: ${SPT_IMAGE:-spt:hardened}
    build:
      context: .
      dockerfile: Dockerfile
    container_name: spt
    restart: unless-stopped        # survives reboots; stops on docker compose down
    stop_grace_period: 45s         # matches spt's ~45s graceful-shutdown budget

    environment:
      SPT_LOG_LEVEL: ${SPT_LOG_LEVEL:-info}
      RUST_LOG: ${RUST_LOG:-info}
      RUST_BACKTRACE: "1"
      # NO secrets here — use mounted files or your orchestrator's secret store.

    user: "65532:65532"            # belt-and-suspenders with the image's USER

    read_only: true                # immutable rootfs; nothing can be modified at runtime
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777

    volumes:
      # Config: read-only bind mount. Edit on the host; container cannot rewrite it.
      - type: bind
        source: ./config
        target: /etc/spt
        read_only: true
      # Durable state: known_hosts cache, supervisor lock, snapshots.
      # Named volume so state survives restarts.
      - type: volume
        source: spt-state
        target: /var/lib/spt
      # Optional secrets bind mount — uncomment and point at a host directory.
      # - type: bind
      #   source: ./secrets
      #   target: /run/secrets
      #   read_only: true

    security_opt:
      - no-new-privileges:true    # block setuid/privilege escalation

    cap_drop:
      - ALL                       # drop every Linux capability
    # cap_add:
    #   - NET_BIND_SERVICE        # add only if spt must bind a port < 1024 inside
                                  # the container; prefer host-side port mapping

    ports:
      - "${SPT_FORWARD_PORT_1:-127.0.0.1:8080}:8080"   # loopback-bound by default

    healthcheck:
      test: ["CMD", "/usr/local/bin/spt", "tunnel", "health", "--output", "json"]
      interval: 30s
      timeout: 5s
      start_period: 30s
      retries: 3

    mem_limit: 256m
    memswap_limit: 256m           # == mem_limit → swap disabled; OOM-kill is real
    mem_reservation: 64m
    pids_limit: 256
    cpus: 0.50
    deploy:                       # keep in sync with legacy keys (Compose v5 rule)
      resources:
        limits: { memory: 256m, cpus: "0.50", pids: 256 }
        reservations: { memory: 64m }
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }
    ulimits:
      nofile: { soft: 4096, hard: 8192 }

volumes:
  spt-state:
    name: spt-state
```

## Required mounts

| Path in container | Purpose | Mount type |
|-------------------|---------|-----------|
| `/etc/spt/spt.toml` | Configuration | Read-only bind (`./config` → `/etc/spt`) |
| `/var/lib/spt` | State: known\_hosts, supervisor lock, snapshots | Writable named volume (`spt-state`) |
| `/tmp` | Scratch | tmpfs (compose-provided, size-bounded) |
| `/run/secrets` (optional) | Key / token files referenced by config | Read-only bind |

The read-only rootfs means `/var/lib/spt` **must** be a writable volume. If it
is not mounted or is read-only, the supervisor cannot persist its lock or
known\_hosts cache and will fail to start cleanly.

## File permissions and ownership

The container runs as UID/GID `65532`. Every file you bind-mount must be
readable by that identity on the host.

- **Config file and referenced key/token files** must be readable by UID
  `65532`. Either `chown 65532:65532 <file>` on the host, or make the config
  world-readable (`chmod 0644`). A file owned by host `root` with mode `0600`
  is unreadable inside the container.
- **Private keys and secret files** must be mode `0600` or `0400`. The Unix
  file-secret backend hard-rejects anything broader than owner read/write — this
  is a security check, not a bug. Set `chmod 0600 <keyfile>` and
  `chown 65532:65532 <keyfile>` on the host.
- Read-only bind mounts preserve the host's mode bits exactly; `read_only`
  only blocks writes inside the container and does not relax readability.

## Supplying secrets

No secrets are baked into the image. Provide them at runtime:

**Direct file path (recommended):** mount a host directory of key/token files
read-only at `/run/secrets` and reference them by absolute path in `spt.toml`:

```toml
[profiles.auth]
method = "public_key"
identity_file = "/run/secrets/id_ed25519"
```

**`secret://` references (file backend):** by default the file backend resolves
`secret://ns/name` against `<state_dir>/secrets/ns/name`, which maps to
`/var/lib/spt/secrets/...` inside the writable state volume. To resolve from
the read-only `/run/secrets` mount instead, set the backend root explicitly:

```toml
[secrets.file]
root = "/run/secrets"
```

**Environment variable:** pass `SPT_CONFIG_PASSPHRASE` via your orchestrator's
secret mechanism (Docker secrets, Kubernetes Secret, etc.) for the sealed-config
passphrase. Never pass it via a committed `.env`.

The OS keychain / secret-service backend does not function in this image (no
secret-service daemon runs in the container). Use the `file` or `env` backends.

See [Secrets & Vault](secrets.md) for the full secrets reference.

## Resource limits and hardening

The compose profile bounds every host resource the container can consume.
The defaults are sized for a typical multi-profile tunnel workload; adjust as
described below.

### Memory and OOM behavior

`mem_limit: 256m` is a hard cgroup ceiling. `memswap_limit: 256m` (equal to
`mem_limit`) disables the container's swap allotment, so a memory leak is
OOM-killed immediately rather than ballooning into host swap. The
`restart: unless-stopped` policy brings the container back automatically;
combined with `spt`'s own internal reconnect backoff, recovery from an OOM
event does not produce a tight restart storm.

To raise the ceiling, update **all three** memory knobs together, keeping
`mem_limit` and `memswap_limit` equal:

```yaml
mem_limit: 512m
memswap_limit: 512m     # always equal to mem_limit
mem_reservation: 128m
deploy:
  resources:
    limits:
      memory: 512m      # Compose v5 rule: must match mem_limit
    reservations:
      memory: 128m
```

### PIDs and file descriptors

`spt` runs as a single process with a small pool of async worker threads.
Each forward is an async task, not a new process, so 256 PIDs comfortably
covers hundreds of concurrent forwards plus healthcheck execs and transient
helpers.

Each forward/connection pair costs roughly one file descriptor (listener
socket + accepted socket). The default `nofile` soft limit of 4096 fits
approximately 200 concurrent forwards with headroom; raise both `soft` and
`hard` if your workload requires more.

### Default limit table

| Limit | Default | Threat addressed |
|-------|---------|-----------------|
| `mem_limit` / `memswap_limit` | 256 MiB each | Host memory exhaustion / runaway leak |
| `mem_reservation` | 64 MiB | Soft scheduler floor |
| `pids_limit` | 256 | Fork-bomb |
| `cpus` | 0.50 | CPU starvation of neighbours |
| `ulimits.nofile` (soft/hard) | 4096 / 8192 | Descriptor exhaustion |
| `/tmp` tmpfs size | 64 MiB | tmpfs fill → host RAM exhaustion |
| Log `max-size` / `max-file` | 10 MiB × 5 | On-disk log fill |

### Capability and namespace isolation

The `cap_drop: [ALL]` directive removes every Linux capability. `spt` needs
none for forwards that bind ports >= 1024. Add back `NET_BIND_SERVICE` only if
you must bind a privileged (< 1024) source port inside the container; most
deployments map host ports externally and need nothing.

The `no-new-privileges:true` security option blocks setuid/setgid escalation
for the process and any children. Docker's default seccomp profile (blocking
~44 dangerous syscalls) stays applied — the compose file never sets
`seccomp:unconfined`.

The compose file deliberately omits `privileged: true`, `network_mode: host`,
`pid: host`, `ipc: host`, and any Docker socket mount. A compromise stays
confined to this container's own namespaces.

### Network exposure

The `ports` entries bind to `127.0.0.1` on the host by default, so forwards
are not world-reachable. To expose a forward deliberately, change the host-side
bind address and put a firewall or reverse proxy in front. See
[Firewall](firewall.md) and [Security Model](security.md).

## Healthcheck

The image declares a `HEALTHCHECK` that runs:

```
/usr/local/bin/spt tunnel health --output json
```

in exec (no-shell) form. The compose file re-declares it so that
`docker compose ps` shows health status and the `start_period` applies
correctly during rolling updates.

## Optional features and limitations

This image is built with **default features only**. The following are
intentionally excluded:

| Feature | What it adds | Why excluded |
|---------|-------------|--------------|
| `mount-fuse` | SFTP filesystem mounts | Needs `--cap-add SYS_ADMIN` and `--device /dev/fuse` — incompatible with the locked-down cap-dropped profile |
| OS keychain / secret-service | D-Bus secret service at runtime | No secret-service daemon in the container; use `file` or `env` backends |
| GSSAPI / Kerberos | Linked (`libgssapi-krb5-2` present) | Needs a `krb5.conf` / keytab; mount your Kerberos config at runtime if required — nothing is preconfigured |
| `ssh2-vendored-openssl` | vendored OpenSSL + libssh2 | Default build uses pure-Rust russh; no OpenSSL needed |

For images that include libssh2 / OpenSSL or other optional features, see
the images under `packaging/docker/`.

## CI scanning

`.github/workflows/docker.yml` builds the image on pushes to `main`, on tags,
and on manual dispatch, then runs a Trivy vulnerability scan against the built
image, failing on HIGH or CRITICAL findings with an available fix. The image is
loaded locally for scanning only; no push to a registry is performed unless
release workflow credentials are present.
