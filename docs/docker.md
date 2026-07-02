# Docker — Hardened Container Deployment

This guide covers the **hardened, secure** container image for `spt`, defined by
the repository-root [`Dockerfile`](../Dockerfile) and
[`docker-compose.yml`](../docker-compose.yml).

It is the recommended way to run `spt` in a container. If you need optional
features that this minimal image deliberately omits (FUSE mounts, OS keychain,
GSSAPI/Kerberos), see [Optional features](#optional-features-and-limitations)
and the fatter [`packaging/docker/`](../packaging/docker/readme.md) images.

## What makes this image "hardened"

| Property | How |
| --- | --- |
| Minimal runtime | `debian:bookworm-slim` with **only** `libdbus-1-3`, `libgssapi-krb5-2`, `ca-certificates`, and `tini` installed |
| Non-root | Runs as the system user `spt` (UID/GID `65532`); `USER` set in the image and re-asserted in compose |
| Smallest dependency set | Built with **default features only**: pure-Rust russh SSH (rustls/ring) — no libssh2 FFI, no OpenSSL, no FUSE |
| Binary only | The final image contains just the `spt` binary + the runtime libs above — **no source, no build tools, no secrets** |
| Reproducible | `cargo build --release --locked` against the committed `Cargo.lock` |
| Read-only rootfs | compose sets `read_only: true`; only an explicit state volume + `/tmp` tmpfs are writable |
| No privilege escalation | `security_opt: no-new-privileges:true`, `cap_drop: [ALL]` |
| Bounded blast radius | `mem_limit`+`memswap_limit` (leak → OOM-kill, not host swap), `pids_limit`, `cpus`, `ulimits`, size-bounded tmpfs, capped JSON logs — see [Resource limits & hardening](#resource-limits--hardening) |

### Why debian-slim and not distroless

The first choice was `gcr.io/distroless/cc-debian12:nonroot` (no shell, no
package manager). It does not work for the **default** build. `ldd` on the built
binary shows it links two system libraries pulled in by always-on crates:

- `libdbus-1.so.3` — `spt-secrets` unconditionally enables the `keyring` crate's
  `sync-secret-service` backend.
- `libgssapi_krb5.so.2` — `spt-auth-sspi`'s Unix GSSAPI/Kerberos backend.

Each drags a transitive chain (libsystemd, libcap, libgcrypt, libkrb5*, liblzma,
libzstd, …). Distroless cc ships none of them, and hand-copying the whole chain
in and keeping it in sync is brittle. So the image uses `debian:bookworm-slim`
with a non-root user and installs *only* those two libs (+ ca-certs + tini; apt
resolves their chains), while every other hardening control lives in
`docker-compose.yml`. This is the sanctioned fallback when distroless cannot
satisfy a runtime library.

The tradeoff vs distroless: the slim base retains a shell and `apt` (the apt
package lists are removed to shrink the layer). The read-only rootfs,
`cap_drop: ALL`, and `no-new-privileges` in the compose profile are what
neutralise that surface at runtime — an attacker on a read-only, capability-less,
no-escalation container cannot meaningfully use the shell or package manager. If
you want a fatter image with libssh2/OpenSSL but the same non-distroless
posture, see [`packaging/docker/`](../packaging/docker/readme.md).

## Build

From the repository root:

```bash
docker build -t spt:hardened .
```

This is a full release compile of the workspace — it is slow on the first run.
BuildKit cache mounts make repeat builds fast. The `--locked` flag (baked into
the Dockerfile) makes the build fail rather than silently re-resolve
dependencies, so the image matches the committed lockfile exactly.

Confirm the binary works and the image is non-root:

```bash
docker run --rm spt:hardened --version
docker run --rm spt:hardened tunnel --help
```

## Run with Docker Compose (hardened profile)

```bash
docker build -t spt:hardened .
mkdir -p config
cp packaging/docker/example-config/spt.toml config/spt.toml   # or your own
docker compose up -d
docker compose logs -f
```

Validate the compose file without starting anything:

```bash
docker compose -f docker-compose.yml config
```

### The hardening flags, explained

Every security-relevant line in `docker-compose.yml` is commented inline. The
key ones:

- **`read_only: true`** — the container's root filesystem is immutable. An
  attacker who lands code execution cannot modify the image, drop a binary, or
  persist. Everything that must be writable is an explicit mount.
- **`tmpfs: /tmp` with `noexec,nosuid,nodev`** — scratch space that cannot be
  used to execute dropped binaries or escalate privileges, and is size-capped so
  it cannot exhaust host memory.
- **`cap_drop: [ALL]`** — removes every Linux capability. `spt` needs none for
  forwards that bind ports `>= 1024`. Only add back `NET_BIND_SERVICE` if `spt`
  must bind a privileged (`< 1024`) source port *inside* the container; most
  deployments map host ports instead and need nothing.
- **`security_opt: [no-new-privileges:true]`** — the process and all children
  can never gain privileges via setuid/setgid binaries.
- **`user: "65532:65532"`** — runs as the image's non-root user (minimal
  debian-slim, non-root), in addition
  to the image's own `USER` directive.
- **`mem_limit` + `memswap_limit` + `pids_limit` / `cpus` / `ulimits`** — cap
  memory (with swap disabled so a leak is OOM-killed, not swapped — see
  [Resource limits & hardening](#resource-limits--hardening)), process count
  (fork-bomb protection), CPU, and file descriptors so a compromised, buggy, or
  leaking container cannot starve the host.
- **`logging` max-size/max-file** — bounds on-disk logs so a chatty or attacked
  container cannot fill the host disk.
- **loopback-bound `ports`** — forwards are published to `127.0.0.1` on the host
  by default, not `0.0.0.0`, so they are not world-reachable.

## Resource limits & hardening

The compose profile bounds every host resource a container can consume, so a
runaway leak, a fork-bomb, a descriptor storm, or a full compromise stays
contained. Both [`docker-compose.yml`](../docker-compose.yml) and
[`packaging/docker/docker-compose.yml`](../packaging/docker/docker-compose.yml)
ship the **same** hardened defaults.

| Limit | Default | Threat it addresses | How to tune |
| --- | --- | --- | --- |
| `mem_limit` | `256m` | Host memory exhaustion / **runaway leak** | Raise for more concurrent forwards; keep it equal to `memswap_limit` |
| `memswap_limit` | `256m` (= `mem_limit`) | Swap escape — without it the leak thrashes host swap instead of being killed | Always keep **equal to** `mem_limit` |
| `mem_reservation` | `64m` | Soft floor the scheduler keeps available | Raise proportionally with `mem_limit` |
| `pids_limit` | `256` | **Fork-bomb** — caps total processes/threads | Rarely needs raising (see math below) |
| `cpus` | `0.50` | CPU starvation of neighbours | Raise for high-throughput forwards |
| `ulimits.nofile` | soft `4096` / hard `8192` | **Descriptor exhaustion** | ~1 fd per forward/connection — see math below |
| `tmpfs … size=` | `/tmp` 64m, `/run/spt` 16m | **tmpfs fill → host RAM exhaustion** | Raise `size=` only if a workload needs more scratch |
| `logging max-size/max-file` | `10m` × `5` | Host **disk** fill from chatty/attacked logs | Raise for verbose debugging |

### Memory-leak → OOM-kill → restart (the key behavior)

`spt` is a long-lived supervisor; a slow leak must never take the host down.
The defaults guarantee it can't:

1. **`mem_limit: 256m`** is a hard cgroup ceiling. As RSS grows, the moment the
   container crosses 256 MiB the kernel OOM-killer terminates **this container's**
   processes — never a host process.
2. **`memswap_limit: 256m` (equal to `mem_limit`)** disables swap for the
   container. This is essential: with the default (swap allowed) a leak would
   balloon into host swap and the OOM-kill would *never* fire — it would just
   thrash the disk. Equal values ⇒ swap allotment is zero ⇒ the memory limit is
   real and enforced.
3. **`restart: unless-stopped`** brings the container straight back after the
   OOM-kill. Combined with spt's own internal reconnect backoff, the recovery is
   automatic and does **not** hot-loop (see [Restart behavior](#restart-behavior)).

Net effect: a leak degrades to a periodic in-container restart, fully invisible
to the host and to other containers.

**Raising the ceiling.** Give spt more headroom by raising **all three** memory
knobs together, keeping `mem_limit` and `memswap_limit` equal:

```yaml
mem_limit: 512m
memswap_limit: 512m        # keep EQUAL to mem_limit
mem_reservation: 128m
deploy:
  resources:
    limits:
      memory: 512m          # keep in sync with mem_limit (Compose v5 rule)
    reservations:
      memory: 128m
```

> **Compose v5 rule.** The legacy keys (`mem_limit`, `cpus`, `pids_limit`) and
> the `deploy.resources.limits` block describe the *same* limits; Compose v5
> **rejects distinct values** for the same limit. Always change both sides to
> the same number. Outside Swarm the `deploy` block is advisory and the legacy
> keys are what `docker compose up` enforces — both are declared so the file is
> correct in either mode.

### PID and file-descriptor math

- **PIDs (`256`).** spt runs as a single process with a small pool of async
  worker threads; **each forward is an async task, not a new process**, so it
  costs no PID. 256 therefore covers hundreds of forwards plus the healthcheck
  exec and any transient helper with wide headroom. It exists purely to cap a
  fork-bomb from a compromised container.
- **File descriptors (`nofile` soft `4096` / hard `8192`).** spt opens on the
  order of **one fd per forward/connection** (listener + accepted sockets),
  plus a handful for config, state, and logging. 4096 comfortably fits ~200
  concurrent forwards *with* their per-connection sockets and diagnostic
  headroom; the `8192` hard cap prevents unbounded fd growth from a leak or
  abuse. Raise both if you run many hundreds of high-fan-out forwards.

### tmpfs bounds

The read-only rootfs forces every writable path to be an explicit mount. The
only writable non-volume paths are tmpfs and are **size-bounded** so a fill
(accidental or malicious) is capped and cannot eat host RAM:

- `/tmp` — `size=64m`, `mode=1777`, `noexec,nosuid,nodev`.
- `/run/spt` (packaging image only) — `size=16m`, `mode=0750`,
  `noexec,nosuid,nodev`.

`noexec,nosuid,nodev` mean nothing dropped in tmpfs can be executed or used to
escalate. Durable state lives in the `spt-state` **named volume** at
`/var/lib/spt` (not a tmpfs), so it survives restarts and is not counted against
tmpfs RAM.

### Compromise containment (blast radius)

If the process is compromised, these controls confine it:

- **`cap_drop: [ALL]`** — no Linux capabilities. spt needs none for forwards
  binding ports `>= 1024`. Re-add **only** `NET_BIND_SERVICE`, and only if spt
  must bind a privileged (`< 1024`) source port *inside* the container; most
  deployments map host ports instead and add nothing.
- **`security_opt: [no-new-privileges:true]`** — no setuid/setgid escalation for
  the process or any child.
- **Default seccomp profile retained** — the compose files never set
  `seccomp:unconfined`, so Docker's default profile (which blocks ~44 dangerous
  syscalls) stays applied. Only override it if a syscall spt genuinely needs is
  denied — it isn't, for the default feature set.
- **`read_only: true` + non-root `user`** — immutable rootfs, unprivileged UID
  (`65532` hardened image, `1000` packaging image).
- **No namespace sharing** — the services declare **no** `privileged: true`, no
  `network_mode: host`, no `pid: host` / `ipc: host`, and **never** mount the
  Docker socket. A compromise cannot see host processes, the host network stack,
  or the Docker daemon. Do not add any of these without weighing the blast
  radius.

### Edge abuse / DoS

Two layers defend against connection abuse:

- **In-app (application layer).** spt enforces per-forward `max_connections` and
  connection-rate limits in the config — the first line of defence against a
  flood on a published forward. Configure these in `spt.toml`.
- **Container edge.** The example `ports` bind to **`127.0.0.1` on the host**,
  not `0.0.0.0`, so forwards are not world-reachable by default. To expose one
  deliberately, change the host side to `0.0.0.0:PORT` (or a specific host IP)
  and put a real firewall / reverse proxy in front — never rely on the container
  alone as your edge.

### Restart behavior

`restart: unless-stopped` restarts the container on any exit (crash, OOM-kill,
health-driven termination) **except** a deliberate `docker compose down` /
`docker stop`, and it survives host reboots. It does **not** hot-loop: spt's own
internal reconnect backoff paces connection retries inside the container, so a
persistent upstream outage produces backed-off retries, not a tight restart
storm. If you prefer a hard cap on restart attempts instead, use
`restart: on-failure:5` (stops trying after 5 consecutive failures) — at the
cost of losing automatic recovery from transient faults.

### Copy-paste hardened service

A minimal but fully-hardened service block, ready to drop into a compose file:

```yaml
services:
  spt:
    image: spt:hardened
    restart: unless-stopped
    stop_grace_period: 45s
    user: "65532:65532"

    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777
    volumes:
      - type: bind
        source: ./config
        target: /etc/spt
        read_only: true
      - type: volume
        source: spt-state
        target: /var/lib/spt

    security_opt:
      - no-new-privileges:true          # default seccomp stays applied
    cap_drop: [ALL]                      # add NET_BIND_SERVICE only for <1024 binds

    ports:
      - "127.0.0.1:8080:8080"            # loopback-bound by default

    # Memory-leak safety: hard ceiling, swap disabled, auto-restart on OOM-kill.
    mem_limit: 256m
    memswap_limit: 256m                  # == mem_limit → no swap escape
    mem_reservation: 64m
    pids_limit: 256                      # fork-bomb cap
    cpus: 0.50
    ulimits:
      nofile: { soft: 4096, hard: 8192 } # fd-exhaustion cap
    deploy:                              # keep in sync with legacy keys (v5 rule)
      resources:
        limits: { memory: 256m, cpus: "0.50", pids: 256 }
        reservations: { memory: 64m }
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }

volumes:
  spt-state:
    name: spt-state
```

## Required mounts

| Path in container | Purpose | Mount as |
| --- | --- | --- |
| `/etc/spt/spt.toml` | Configuration | **read-only** bind mount (`./config` → `/etc/spt`) |
| `/var/lib/spt` | State: known_hosts cache, supervisor lock, snapshots | **writable** named volume (`spt-state`) |
| `/tmp` | Scratch | tmpfs (compose-provided) |
| `/run/secrets` (optional) | Key/token files referenced by config | **read-only** bind mount |

The read-only rootfs means `/var/lib/spt` **must** be a writable volume or the
supervisor cannot persist its lock/known_hosts and will fail to start cleanly.

### File permissions & ownership

The container runs as the non-root user **UID/GID `65532`**, so every file you
bind-mount into it must be readable by that identity — the host UID, not
`root`, is what opens the file inside the container:

- **Config (`/etc/spt/spt.toml`) and any referenced key/token files** must be
  readable by UID/GID `65532`. Either `chown 65532:65532 <file>` on the host, or
  make the config world-readable (`chmod 0644`). A file owned by host `root`
  with mode `0600` is **unreadable** inside the container and `spt` will fail to
  start.
- **Private keys / secret files** must be mode **`0600`** (or `0400`). The Unix
  file-secret backend hard-rejects anything broader than owner read/write, so a
  world- or group-readable key is refused with a permission error — this is a
  security check, not a bug. Set `chmod 0600 <keyfile>` and
  `chown 65532:65532 <keyfile>` on the host.
- **Read-only bind mounts preserve the host's mode bits and ownership** — the
  container sees exactly the permissions the file has on the host. `read_only`
  only blocks writes; it does not relax the readability requirement above. Fix
  ownership/mode on the host before mounting.

## Supplying secrets safely

**No secrets are ever baked into the image or committed to any file.** The image
contains only the `spt` binary and CA certificates. Provide secrets at runtime:

- **Direct file path (recommended):** mount a host directory of key/token files
  read-only at `/run/secrets` and reference them by **absolute path** from
  `spt.toml` — e.g. `identity_file = "/run/secrets/id_ed25519"` or a
  bearer-token file path. Uncomment the `secrets` bind mount in
  `docker-compose.yml`. These paths are read directly; no secret backend is
  involved.
- **`secret://ns/name` references (file backend):** by default the file backend
  resolves `secret://ns/name` against `<state_dir>/secrets/<ns>/<name>` — i.e.
  `/var/lib/spt/secrets/...` inside the **writable state volume**, *not*
  `/run/secrets`. To resolve `secret://` material from a read-only mount
  instead, set the file backend's root explicitly:

  ```toml
  [secrets.file]
  # Resolve secret://ns/name from /run/secrets/ns/name (read-only mount).
  root = "/run/secrets"
  ```

  On Unix the backend still enforces owner-only mode (`0400`/`0600`) on every
  file it reads, so mount your secrets with those bits.
- **Environment variable:** for the sealed-config passphrase, pass
  `SPT_CONFIG_PASSPHRASE` via your orchestrator's secret mechanism (Docker
  secrets, Kubernetes Secret, etc.) — never via a committed `.env`.
- **Never** put secrets in the `Dockerfile`, in `environment:` literals, or in a
  committed `.env`. The `.dockerignore` excludes `.env*`, `*.pem`, and `*.key`
  so local credentials cannot leak into the build context, but the operator is
  responsible for how they inject secrets at runtime.

The OS keychain / secret-service backend will not function in this image: there
is no secret-service daemon (e.g. gnome-keyring) running in the container. Use
the file or env secret backends instead.

## Healthcheck

The image declares a `HEALTHCHECK` that runs `spt tunnel health --output json`
in exec (JSON-array) form — no shell dependency. The compose file re-declares it
so `docker compose ps` shows health status and the start-period applies during
rolling updates.

## Optional features and limitations

This image is built with **default features only** for the smallest, most
portable, least-privileged runtime. The following are intentionally **not**
included; each needs a fatter base image, extra runtime libraries, and (for
FUSE) extra capabilities:

| Feature | What it adds | Why it's excluded here |
| --- | --- | --- |
| `mount-fuse` (SFTP mount) | `fuser` + `libfuse`; needs `--cap-add SYS_ADMIN` and `--device /dev/fuse` | Requires kernel FUSE access — incompatible with the locked-down, cap-dropped profile |
| keychain / secret-service | `libdbus` / secret-service at runtime | Distroless has no D-Bus; use file/env secret backends instead |
| GSSAPI / Kerberos | linked (`libgssapi-krb5-2`), but needs a `krb5.conf` + keytab to function | The libs are present; mount your Kerberos config/keytab at runtime if you use it — nothing is preconfigured |
| `ssh2-vendored-openssl` | vendored OpenSSL + system libssh2 | The default build uses pure-Rust russh — no OpenSSL needed |

If you need any of these, use the Debian/Alpine images under
[`packaging/docker/`](../packaging/docker/readme.md) (which link libssh2 +
OpenSSL and run on a non-distroless base), or build a custom image with the
required `--features` and runtime libraries. Those images trade attack surface
for capability; prefer this hardened image whenever the default feature set
suffices.

## CI

[`.github/workflows/docker.yml`](../.github/workflows/docker.yml) builds this
image (on push to `main`, on tags, and on manual dispatch) and runs a
[Trivy](https://github.com/aquasecurity/trivy) vulnerability scan against the
built image, failing on **HIGH/CRITICAL** findings with an available fix. It
does **not** push to any registry (no credentials assumed) — the image is loaded
locally purely so it can be scanned.
