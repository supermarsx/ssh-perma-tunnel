# Use Cases & Recipes

This chapter is a cookbook. Each recipe pairs a real-world scenario with a
complete, copy-pasteable `spt` configuration (and the equivalent CLI where one
exists), plus operational notes on how to run it durably and what to watch. The
common thread across every recipe is the tool's core promise: a **long-lived,
config-driven, self-healing tunnel supervisor** that binds services only where
you want them, verifies the remote host before sending a byte, and keeps the
link up across reconnects, network changes, and reboots.

## How to read these recipes

Every config file starts with `version = 1` and one or more `[[profiles]]`
blocks. A few conventions apply throughout:

- **Trust is mandatory.** A profile that omits `[profiles.trust]` fails to
  load — there is no silent trust-on-first-connect. Each recipe pins the host
  key via `known_hosts` or a SHA-256 SPKI pin. See [trust.md](trust.md).
- **Secrets are never inline.** Passwords, passphrases, tokens, and OTP seeds
  are given as references (`secret://ns/name`, `env:NAME`, or
  `file:///abs/path`) resolved at runtime by the secrets backend. See
  [secrets.md](secrets.md). Inline plaintext is rejected in `--strict` mode.
- **Loopback by default.** Local and dynamic forwards bind `127.0.0.1` unless
  you explicitly set `bind_mode` to something wider and add `expose = true`.
  This is a feature: your tunnelled service is reachable only from the machine
  running `spt`.
- **Validate before you run.** `spt config validate --strict --config <path>`
  parses, schema-checks, and flags mistakes with dotted field paths.

For the full field surface behind any key used here, see
[forwarding.md](forwarding.md), [transports.md](transports.md),
[authentication.md](authentication.md), and the field-level
[Configuration Reference](configuration-reference.md).

---

## Reach a loopback-bound remote service

### Scenario

A database, admin panel, or internal API on the server listens only on
`127.0.0.1` (or a private management interface). That is the correct posture:
the service has **no public listener at all**. You still need to reach it from
your workstation.

The anti-pattern is to "fix" this by rebinding the service to `0.0.0.0` and
poking a hole in the firewall. That trades a zero-exposure service for a
publicly reachable one whose only defense is the app's own auth. Instead, tunnel
it: the service stays bound to loopback on the server, `spt` opens a
`direct-tcpip` channel to it over SSH, and re-exposes it **only on your local
loopback**. Authentication is your SSH server's (keys, trust pinning), not the
app's login page, and the attack surface on the public internet stays exactly as
small as it was — one SSH port.

### Config

```toml
version = 1

[[profiles]]
name     = "admin-panel"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "tunnel"

[profiles.auth]
method        = "public_key"
identity_file = "~/.ssh/id_ed25519"
passphrase    = "secret://ssh/bastion/passphrase"

# Pin the host key AND require it to appear in known_hosts — strictest mode.
[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true
accept_new       = false
pin_sha256       = ["SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="]

[profiles.crypto]
policy = "modern"

# Reconnect forever with capped exponential backoff.
[profiles.reconnect]
initial_delay = "1s"
max_delay     = "2m"
jitter        = "20%"

[[profiles.forwards]]
name           = "admin"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:18443"   # only reachable from this machine
target         = "127.0.0.1:8443"    # the server's loopback-bound panel
target_resolve = "remote"            # let the SSH server resolve/connect
required       = true
idle_timeout   = "15m"
max_connections = 64
```

Browse to `https://127.0.0.1:18443/` and you are talking to the server's
loopback-only admin panel. Nothing on the server binds a public interface.

### Notes

- **Keep the local bind on loopback.** `bind = "127.0.0.1:18443"` (the default
  `bind_mode = "loopback"`) means only local processes reach it. If you ever
  need to serve it to a LAN, that requires `bind_mode = "all_interfaces"` +
  `expose = true` — a deliberate, auditable opt-in (see the "Bind policy"
  section of [forwarding.md](forwarding.md)). Prefer not to.
- **Layer a firewall allowlist.** Enable the firewall planner to generate rules
  scoped to your binds:

  ```toml
  [firewall]
  enabled     = true
  manager     = "auto"
  apply_rules = false        # plan-only until you review; then set true
  bind_policy = "loopback_only"
  ```

  Preview with `spt firewall plan --profile admin-panel --json`.
- **Capture the pin out-of-band.** Get the SHA-256 to put in `pin_sha256` with
  `spt key inspect bastion.example.com:22` before enabling the profile.
- **Run it durably:** `spt tunnel run --foreground` to test, then install it as
  a service (see [Run any recipe as a service](#run-any-recipe-as-a-service)).
  Watch health with `spt tunnel status --watch`.

---

## SMTP relay access

### Scenario

An internal, authenticated SMTP relay listens on the management network or the
server's loopback (port 25, 587, or 465). A local application needs to send mail
through it, but you do not want to expose the relay publicly — an open or
semi-open relay is a spam magnet and a reputation risk. Point the app at
`localhost:2525` and let `spt` carry the SMTP session to the relay over SSH.

### Config

```toml
version = 1

[[profiles]]
name     = "smtp-relay"
enabled  = true
protocol = "ssh2"
host     = "mail-gw.example.com"
port     = 22
user     = "relay"

[profiles.auth]
method = "agent"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

# Mail connections are long-lived and low-traffic; keep the SSH session warm
# so an idle relay socket is not silently reaped by a middlebox.
[profiles.connection]
tcp_nodelay        = true
socket_keepalive   = true
keepalive_idle     = "30s"
keepalive_interval = "10s"
keepalive_retries  = 3

[profiles.reconnect]
initial_delay = "2s"
max_delay     = "1m"
jitter        = "20%"

[[profiles.forwards]]
name                     = "smtp"
type                     = "local"
transport                = "tcp"
bind                     = "127.0.0.1:2525"
target                   = "smtp.internal:587"   # relay on the mgmt network
target_resolve           = "remote"
required                 = true
idle_timeout             = "10m"
max_connections          = 256
max_bytes_per_second_in  = "5MiB"
max_bytes_per_second_out = "5MiB"
```

Configure your local app's SMTP host as `localhost` port `2525`. Submission auth
(SASL) and STARTTLS still terminate at the relay exactly as before — the tunnel
is transparent to the SMTP conversation.

### Notes

- **Idle/keepalive tuning matters here.** Mail sessions can sit idle between
  sends. `socket_keepalive` plus a modest `keepalive_idle` keeps the underlying
  SSH transport alive; `idle_timeout = "10m"` on the forward closes truly-dead
  submission sockets without killing the tunnel.
- **Pick the target port to match the relay.** Use `:587` for submission
  (STARTTLS), `:465` for implicit TLS, or `:25` for a loopback-only MTA hop.
- **CLI equivalent** (adds the forward to an existing profile):

  ```bash
  spt forward add local --profile smtp-relay \
      --listen 127.0.0.1:2525 --to smtp.internal:587 --tcp
  ```
- **Watch:** `spt tunnel stats --profile smtp-relay --forward smtp` shows bytes
  and connection counts; a stuck queue on the app usually shows as zero new
  connections here.

---

## Jump-host permanent links for remote access

### Scenario

The machine you actually want is on a private network, reachable only *through*
a bastion. Doing this by hand with OpenSSH `ProxyJump` works for one-off shells,
but for a service link you want it permanent and self-healing: if the bastion
blips or the target reboots, `spt` re-establishes the whole chain end-to-end
without you re-running anything. This recipe covers **both directions** — reach
*in* to a private service with `-L`, and publish *out* from behind the bastion
with `-R`.

### Config — reach in through a two-hop chain (-L)

```toml
version = 1

[[profiles]]
name     = "private-db"
enabled  = true
protocol = "ssh2"
# The FINAL hop (the machine that carries the forwards) is the profile host.
host     = "db-host.internal"
port     = 22
user     = "ops"

[profiles.auth]
method = "agent"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

[profiles.reconnect]
initial_delay = "1s"
max_delay     = "2m"
jitter        = "25%"

# Intermediate hop: the public bastion. Each hop verifies its own host key
# and can carry its own auth block. target_resolve = "previous-hop" resolves
# the next host from the bastion's vantage point.
[[profiles.hops]]
name           = "bastion"
protocol       = "ssh2"
host           = "bastion.example.com"
port           = 22
user           = "jump"
kind           = "ssh"
target_resolve = "previous-hop"

[profiles.hops.trust]
mode             = "pinned"
pin_sha256       = ["SHA256:0000000000000000000000000000000000000000000="]

[[profiles.forwards]]
name           = "postgres"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:5432"
target         = "127.0.0.1:5432"    # loopback on db-host.internal
target_resolve = "remote"
required       = true
```

`spt` opens `bastion.example.com`, tunnels a `direct-tcpip` channel to
`db-host.internal:22`, re-establishes SSH through it, and then binds
`127.0.0.1:5432` locally. `psql -h 127.0.0.1` reaches a database two hops away
that has no route to the public internet.

The same chain can be injected ad-hoc without editing the config:

```bash
spt tunnel run -J jump@bastion.example.com --profiles private-db
# or preflight the whole path:
spt profile test private-db -J jump@bastion.example.com
```

### Config — publish out from behind the bastion (-R)

To expose a service that runs on your side (or on the target) *out* through the
bastion so colleagues can reach it, use a remote forward. The SSH server binds
the listener; connections come back down the tunnel to your `target`.

```toml
[[profiles.forwards]]
name           = "expose-app"
type           = "remote"
transport      = "tcp"
bind           = "127.0.0.1:9000"   # address the bastion binds (loopback = safe)
target         = "127.0.0.1:3000"   # local service to publish
target_resolve = "local"
required       = true
```

Anyone with a shell on the bastion can now reach your app at
`bastion:127.0.0.1:9000`. To make the bastion listener reachable from its LAN,
set `bind = "0.0.0.0:9000"` and `expose = true` — and note the SSH server's
`GatewayPorts` directive must permit non-loopback remote binds.

### Notes

- **Why a supervised link beats manual `ProxyJump`:** the supervisor owns the
  reconnect/backoff/health loop for *every* hop. A dropped bastion, a rebooted
  target, or a laptop that changed networks (`network_change_reconnect = true`)
  all trigger a clean re-establish of the full chain, not a dead socket you
  discover an hour later.
- **Per-hop trust and auth.** Each `[[profiles.hops]]` entry can carry its own
  `[trust]` and `[auth]` sub-tables (shown above with a pinned bastion key).
  There is no way to skip host-key verification on an intermediate hop.
- **Proxy hops, not just SSH.** A hop's `kind` can be `socks5` or
  `http-connect` to traverse an existing corporate proxy; supply
  `proxy_username` and `proxy_password_ref = "secret://proxies/alice"`. See the
  "Hop kinds" table in [forwarding.md](forwarding.md).
- **More than two hops:** stack additional `[[profiles.hops]]` entries in order;
  the last session (the profile `host`) carries the forwards.

---

## Remote folder mounts

### Scenario

You want a remote directory to appear as a local folder — browse it in your file
manager, open files in your editor, `grep` across it — without syncing or
copying. `spt` mounts a remote path over SFTP using the platform's userspace
filesystem layer (FUSE on Linux, macFUSE on macOS, WinFsp/Dokany on Windows).

### Config

Filesystem mounts are gated by capability flags and declared per profile:

```toml
version = 1

[capabilities]
allow_sftp              = true
allow_filesystem_mounts = true
# allow_writeback_cache = true   # only if you enable cache = "writeback"

[[profiles]]
name     = "fileserver"
enabled  = true
protocol = "ssh2"
host     = "files.example.com"
port     = 22
user     = "data"

[profiles.auth]
method        = "public_key"
identity_file = "~/.ssh/id_ed25519"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

[[profiles.sftp_mounts]]
name        = "data"
enabled     = true
remote_path = "/srv/data"
mount_point = "/mnt/spt-data"      # on Windows use drive_letter = "S:" instead
read_only   = true                 # safest default; drop for read/write
cache       = "metadata"           # none | metadata | writeback
allow_other = false
required    = false
```

The remote `/srv/data` now appears at `/mnt/spt-data` while the tunnel is up.

### Run it

```bash
# Verify SFTP works over the profile first.
spt sftp test --profile fileserver

# Register a mount entry (equivalent to the [[profiles.sftp_mounts]] block):
spt sftp mount add --profile fileserver --name data \
    --remote /srv/data --mount-point /mnt/spt-data --read-only --cache metadata

# Activate / preview / tear down:
spt sftp mount plan  --profile fileserver --name data --json
spt sftp mount start --profile fileserver --local /mnt/spt-data --remote /srv/data
spt sftp mount stop  /mnt/spt-data           # or: spt sftp umount /mnt/spt-data

# On Windows, mount to a drive letter instead:
spt sftp drive add --profile fileserver --name data --remote /srv/data --letter S:
```

### Notes

- **Platform FUSE requirement.** Linux needs FUSE (kernel module + libfuse);
  macOS needs macFUSE; Windows needs WinFsp (or Dokany). The default Docker
  image is built **without** `mount-fuse` and cannot mount (it would need
  `--cap-add SYS_ADMIN` + `--device /dev/fuse`, which the hardened profile
  deliberately drops — see [docker.md](docker.md)).
- **Reconnect behavior.** The mount is tied to the profile's session. If the
  tunnel drops, the supervisor reconnects and the mount is re-established; set
  `required = true` if a failed mount should mark the whole profile unhealthy.
- **Write-back caching.** `cache = "writeback"` improves write throughput but
  buffers dirty data locally and requires `allow_writeback_cache = true` in
  `[capabilities]`. Start with `read_only = true` + `cache = "metadata"` and
  relax only when you need writes. For one-off transfers without a mount, use
  `spt sftp get` / `spt sftp put` (and the recursive variants with `--resume`).
- **`allow_other`** exposes the mount to other local users (FUSE `allow_other`);
  leave it `false` unless you specifically need shared access.

---

## Dynamic SOCKS proxy for an internal network

### Scenario

You need to browse many hosts inside a private network — a wiki, an internal
registry, a handful of dashboards — without a forward per service. A dynamic
proxy lets each request name its own destination; `spt` opens a channel per
target over the tunnel.

### Config

```toml
version = 1

[capabilities]
allow_dynamic_proxy = true

[[profiles]]
name     = "corp-proxy"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "browse"

[profiles.auth]
method = "agent"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

[[profiles.forwards]]
name            = "socks"
type            = "dynamic"
transport       = "tcp"
bind            = "127.0.0.1:1080"
max_connections = 128
proxy_protocols = ["socks5", "http_connect"]
# Restrict where the proxy may reach — deny wins over allow.
allow_targets   = ["*.internal", "10.0.0.0/8"]
deny_targets    = ["169.254.0.0/16", "10.99.0.0/24"]
```

Point your browser (or `curl --socks5-hostname 127.0.0.1:1080`) at the proxy.
SOCKS5/SOCKS4A domain requests are resolved on the SSH server side, so
`*.internal` names that only exist in the remote zone just work.

### Notes

- **Lock down the target ACL.** Without `allow_targets` a dynamic proxy will
  reach anything the server can — including link-local and cloud metadata
  endpoints. The allowlist above confines it to your internal ranges; keep a
  deny rule for `169.254.0.0/16`.
- **CLI equivalent:**

  ```bash
  spt forward add dynamic --profile corp-proxy --listen 127.0.0.1:1080 \
      --connections 128 --proxy-protocol socks5 --proxy-protocol http-connect
  ```
- See the "Dynamic SOCKS and HTTP CONNECT proxy" section of
  [forwarding.md](forwarding.md) for the full protocol and ACL semantics.

---

## Database access (Postgres / MySQL)

### Scenario

Run an app or a migration locally against a production/staging database that is
firewalled to the bastion's network. The classic local-forward case: bind the DB
port on your loopback, point the client at `localhost`.

### Config

```toml
version = 1

[[profiles]]
name     = "prod-pg"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "dba"

[profiles.auth]
method        = "public_key"
identity_file = "~/.ssh/id_ed25519"
passphrase    = "secret://ssh/dba/passphrase"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

[profiles.reconnect]
initial_delay = "1s"
max_delay     = "1m"

[[profiles.forwards]]
name           = "postgres"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:5432"
target         = "db.internal:5432"     # or db.internal:3306 for MySQL
target_resolve = "remote"
required       = true
idle_timeout   = "30m"
```

```bash
psql   "host=127.0.0.1 port=5432 dbname=app user=app sslmode=require"
mysql  --host=127.0.0.1 --port=3306 app
```

### Notes

- **Store the DB password as a secret too**, and let your client read it from
  the same vault/env indirection — e.g. `PGPASSWORD="$(spt secret get
  db/password --reveal)"` in a wrapper, or a `.pgpass` file. Do not hardcode it.
- **`sslmode=require`/DB TLS still applies** end-to-end; the tunnel does not
  terminate the database's own TLS. Keep it on.
- **Avoid port clashes** with a local DB by binding a non-default local port
  (e.g. `127.0.0.1:15432`) and pointing the client there. Set
  `on_bind_conflict = "next_port"` if you want `spt` to auto-pick a free port.

---

## RDP / VNC over a tunnel

### Scenario

Reach a Windows RDP host or a VNC server that lives on a private segment,
without exposing 3389/5900 to the internet — both are heavily scanned and
brute-forced. Tunnel them to a local port and connect the desktop client to
`localhost`.

### Config

```toml
version = 1

[[profiles]]
name     = "remote-desktop"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "ops"

[profiles.auth]
method = "agent"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

[profiles.connection]
tcp_nodelay      = true     # interactive: minimise per-packet latency
socket_keepalive = true

[[profiles.forwards]]
name           = "rdp"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:33890"
target         = "win-host.internal:3389"
target_resolve = "remote"
required       = true

[[profiles.forwards]]
name           = "vnc"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:59000"
target         = "kvm-host.internal:5900"
target_resolve = "remote"
```

Connect your RDP client to `127.0.0.1:33890` and your VNC viewer to
`127.0.0.1:59000`.

### Notes

- **`tcp_nodelay = true`** disables Nagle on the tunnel socket, which noticeably
  improves interactive responsiveness for keyboard/mouse traffic.
- Two forwards can share a single profile/session — no need for a second SSH
  connection.
- RDP's own Network Level Authentication and TLS still apply; the tunnel just
  removes the public listener.

---

## Scraping metrics from a loopback-bound exporter

### Scenario

A Prometheus exporter (node_exporter, an app's `/metrics`, a database exporter)
binds `127.0.0.1:9100` on a remote host — the recommended posture, since metrics
often leak internal topology. You want your local Prometheus or a manual `curl`
to scrape it without opening the exporter to the network.

### Config

```toml
version = 1

[[profiles]]
name     = "metrics"
enabled  = true
protocol = "ssh2"
host     = "app-host.example.com"
port     = 22
user     = "monitor"

[profiles.auth]
method        = "public_key"
identity_file = "~/.ssh/id_ed25519"

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "~/.ssh/known_hosts"
strict           = true

[[profiles.forwards]]
name           = "node-exporter"
type           = "local"
transport      = "tcp"
bind           = "127.0.0.1:9100"
target         = "127.0.0.1:9100"   # exporter's own loopback bind
target_resolve = "remote"
required       = true
# Register a stable name so a local scrape config can target it by hostname.
dns_names      = ["node1.metrics.local"]
```

Scrape `http://127.0.0.1:9100/metrics`, or enable the built-in resolver
(`[dns] enabled = true`, `auto_records = true`) so the `dns_names` entry
resolves and your Prometheus job can list `node1.metrics.local:9100`.

### Notes

- **`spt`'s own metrics** are separate and complementary. Enable the Prometheus
  exporter for the supervisor itself to watch tunnel health alongside the app:

  ```toml
  [observability.metrics]
  enabled    = true
  format     = "prometheus"
  state_file = "/var/lib/spt/metrics.prom"
  ```

  Or serve them over the read-only status API (`[status_api] enabled = true`,
  `expose_metrics = true`).
- One profile can carry a forward per exporter; give each a distinct local port
  and `dns_names` entry.

---

## Censorship-resistant / obfuscated transport

### Scenario

You are on a hostile or filtered network that blocks raw SSH by DPI signature,
or throttles/kills long-lived TCP. Two independent tools help: **SSH3**
(SSH-over-QUIC/HTTP3), which looks like HTTP/3 to port 443 and survives
IP/network changes better than TCP; and the **obfuscation transports**, which
wrap the SSH2 stream so an observer sees a WebSocket, a fronted HTTPS POST, a
Shadowsocks flow, or an obfs4-style handshake instead of SSH.

> **Interop scope.** SSH3 and all four obfuscation transports are validated
> `spt`-to-`spt` (and against mock acceptors). They are **not** guaranteed
> bit-compatible with third-party servers (`obfs4proxy`, `meek-server`,
> `ssserver`, or the `francoismichel/ssh3` reference server). Treat them as
> `spt`-to-`spt` unless you have matched the server side. See
> [transports.md](transports.md).

### Config — SSH3 over QUIC (with a UDP forward)

```toml
version = 1

[[profiles]]
name                     = "edge-quic"
enabled                  = true
protocol                 = "ssh3"
endpoint                 = "https://edge.example.com:443/ssh3"
user                     = "netops"
acknowledge_experimental = true      # required; silences the experimental warning
connect_timeout          = "10s"

[profiles.auth]
method = "bearer_token"
token  = "secret://ssh3/edge/token"

[profiles.tls]
server_name       = "edge.example.com"
system_roots      = true
allow_self_signed = false
pin_sha256        = ["SHA256:abc123..."]

[profiles.ssh3]
enable_datagrams = true              # map UDP forwards onto QUIC datagrams
idle_timeout     = "30s"
keepalive        = "10s"

[[profiles.forwards]]
name           = "dns"
type           = "local"
transport      = "udp"
bind           = "127.0.0.1:1053"
target         = "dns.internal:53"
target_resolve = "remote"
required       = true
```

The peer side is another `spt` running `spt ssh3-serve` (see
[transports.md](transports.md) and [cli-reference.md](cli-reference.md)):

Store the exact `Authorization` header value in a root-readable file on the
responder (for a bearer-token profile this includes the `Bearer ` prefix), and
pin the responder to the one service this recipe needs:

```bash
install -m 0600 -o root -g root /dev/stdin /run/credentials/spt.ssh3.authz <<'EOF'
Bearer replace-with-the-secret-value-from-ssh3/edge/token
EOF

spt ssh3-serve --listen 0.0.0.0:443 --cert chain.pem --key key.pem \
    --fixed-target dns.internal:53 \
    --require-authorization-file /run/credentials/spt.ssh3.authz
```

Do not expand long-lived secrets into `spt ssh3-serve` command-line arguments:
process arguments are commonly visible to other local users. Always pair a
public responder with `--fixed-target` or one or more `--allow-target` entries;
without either option, the server intentionally behaves as an open relay for
any authorized peer.

### Config — obfuscated SSH2 (WebSocket / Shadowsocks)

Obfuscation sits *beneath* SSH2: the handshake, auth, and channel data all pass
through the obfuscated outer layer. Add a `[profiles.transport.obfuscation]`
block to an ordinary SSH2 profile.

```toml
# Wrap SSH in a WebSocket upgrade to :443 (traverses WS-permitting proxies).
[profiles.transport.obfuscation]
kind = "websocket"
url  = "wss://edge.example.com/tunnel"
headers = [
    ["X-Auth-Token", "secret://websocket/token"],
]
```

```toml
# Or wrap SSH in Shadowsocks AEAD-2022 framing (no identifiable signature).
[profiles.transport.obfuscation]
kind     = "shadowsocks"
method   = "2022-blake3-aes-256-gcm"
password = "secret://obfs/shadowsocks/psk"   # MUST be a secret reference
```

### Notes

- **SSH3 is experimental.** Every connect attempt warns unless
  `acknowledge_experimental = true`. For production tunnels today, use SSH2 —
  optionally with an obfuscation wrapper. UDP forwards map natively onto QUIC
  datagrams only when `enable_datagrams = true`.
- **Pin the TLS leaf** for SSH3 (`pin_sha256`) and for any fronted transport;
  `allow_self_signed = true` is refused with an empty pin set.
- **Shadowsocks/obfs4 `password`/keys are always secret references** resolved at
  runtime. The four transports and their exact threat models are documented in
  the "Obfuscation transports" section of [transports.md](transports.md).

---

## Run any recipe as a service

### Scenario

Every recipe above becomes an always-on link once you hand it to the OS service
manager: it starts at boot, restarts on failure, and participates in normal
operational tooling. `spt` supports systemd, launchd, Windows SCM, OpenRC, SysV,
and Windows Task Scheduler. One service = one config file.

### Config

Shape the generated unit from the config so `install` needs fewer flags:

```toml
[service]
description    = "spt production tunnels"
user           = "spt"          # system scope only; omit for --user installs
group          = "spt"
restart_policy = "on-failure"
sd_notify      = true           # systemd Type=notify
watchdog_sec   = 30             # systemd WatchdogSec; spt pings at half-interval

[service.env]
RUST_LOG = "info"
# SSH_AUTH_SOCK = "/run/user/1000/keyring/ssh"   # if using method = "agent"
```

### Run it

```bash
# Linux (systemd) — system scope
sudo spt service install --config /etc/spt/spt.toml --system
sudo spt service start   --config /etc/spt/spt.toml --system
spt service status       --config /etc/spt/spt.toml --system --json

# Linux — per-user (no root)
spt service install --config ~/.config/spt/spt.toml --user

# macOS (launchd) / Windows (SCM, elevated)
sudo spt service install --config /usr/local/etc/spt/spt.toml --system
spt service install --config "C:\ProgramData\spt\spt.toml" --system

# Preview the unit before installing:
spt service render --config /etc/spt/spt.toml --system --format unit
```

### Notes

- **Agent auth in a service:** export `SSH_AUTH_SOCK` in `[service.env]` (or
  switch to `method = "public_key"` with an explicit `identity_file`), since a
  daemon has no login session agent.
- **Reload without restart:** `spt config reload --wait` (or
  `systemctl reload`) re-reads the config and reconnects only changed profiles
  when `restart_changed_profiles = true`.
- **Watchdog vs. tunnel health** are distinct: `watchdog_sec` is an OS-level
  liveness check on the process; the supervisor's own reconnect loop guards
  individual forwards. Full details in [service.md](service.md).

---

## Run any recipe in Docker

### Scenario

Ship the tunnel as a hardened container: read-only rootfs, non-root user, all
Linux capabilities dropped, bounded memory/PIDs/CPU. Ideal for a sidecar that
exposes an internal service to other containers on a loopback bind.

### Config

The image uses **default features** (pure-Rust russh SSH2 backend; no FUSE, no
OS keychain). Use the `file` or `env` secret backend, since no secret-service
daemon runs in the container:

```toml
version = 1

[secrets]
backend = "file"

[secrets.file]
root = "/run/secrets"          # mount your key/token files here, read-only

[[profiles]]
name     = "sidecar"
enabled  = true
protocol = "ssh2"
host     = "bastion.example.com"
port     = 22
user     = "tunnel"

[profiles.auth]
method        = "public_key"
identity_file = "/run/secrets/id_ed25519"    # mounted read-only, mode 0600

[profiles.trust]
mode             = "known_hosts"
known_hosts_file = "/var/lib/spt/known_hosts"
accept_new       = true        # non-interactive TOFU for ephemeral containers
strict           = false

[[profiles.forwards]]
name           = "api"
type           = "local"
transport      = "tcp"
bind           = "0.0.0.0:8080"   # inside the container; map to host loopback
target         = "api.internal:80"
target_resolve = "remote"
required       = true
expose         = true             # required for the non-loopback in-container bind
```

### Run it

```bash
docker pull ghcr.io/supermarsx/spt:latest

docker run --rm \
  -v "$PWD/config:/etc/spt:ro" \
  -v spt-state:/var/lib/spt \
  -v "$PWD/secrets:/run/secrets:ro" \
  -p 127.0.0.1:8080:8080 \
  ghcr.io/supermarsx/spt:latest \
  tunnel run --foreground --config /etc/spt/spt.toml
```

Or with the repository's hardened `docker-compose.yml` (`docker compose up -d`).

### Notes

- **Bind `0.0.0.0` inside the container, map to host loopback outside.** The
  in-container bind needs `expose = true`; the host-side `-p 127.0.0.1:8080:8080`
  keeps it off the public network. Never publish a forward on `0.0.0.0` at the
  host level without a firewall/reverse proxy in front.
- **`/var/lib/spt` must be a writable volume** (the rootfs is read-only) so the
  supervisor can persist its lock and the `known_hosts` cache — that is also
  where non-interactive TOFU appends first-seen keys.
- **File permissions:** the container runs as UID/GID `65532`; every mounted key
  must be readable by that identity and mode `0600`/`0400`. See
  [docker.md](docker.md) for the full hardening rationale, resource limits, and
  healthcheck.
- **No FUSE, no keychain** in the default image — the "Remote folder mounts"
  recipe needs a differently-built image with `mount-fuse`, `--cap-add
  SYS_ADMIN`, and `--device /dev/fuse`.

---

## See also

- [Forwarding](forwarding.md) — local/remote/dynamic/UDP/UDS forwards, bind
  policy, rate limits, and multi-hop chains in full.
- [Transports](transports.md) — SSH2 vs. SSH3, and the four obfuscation layers.
- [Authentication](authentication.md) — every auth method and per-hop auth.
- [Trust](trust.md) — host-key pinning, `known_hosts`, TOFU, and TLS pins.
- [Secrets](secrets.md) — backends, the `secret://` / `env:` / `file:///`
  reference forms, and the vault.
- [Service Management](service.md) and [Docker](docker.md) — durable deployment.
- [Configuration Reference](configuration-reference.md) — every table and field.
