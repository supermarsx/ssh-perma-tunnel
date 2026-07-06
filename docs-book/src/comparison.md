# Comparison with Other Tools

`spt` occupies a narrow, deliberate niche, and it is easy to mis-file it next to
tools that look superficially similar but solve a different problem. This chapter
places `spt` against the ecosystem of SSH clients, tunnel keep-alive utilities,
GUI terminals, transparent VPNs, and reverse-ingress services — honestly, with
their real strengths intact and `spt`'s real limitations conceded.

The short version: `spt` is not a better `ssh`, not a VPN, and not a hosted
relay. It is a **self-healing, observable, config-as-code tunnel supervisor**.
The closest one-line description is "`autossh` plus a service manager plus
trust/secrets hardening plus observability, distributed as a single static
binary." If what you want is an interactive shell, reach for OpenSSH or PuTTY. If
what you want is a public URL without running your own server, reach for ngrok or
Cloudflare Tunnel. If what you want is a forward that *stays up for months*,
reconnects itself, fails over, pins its host keys, keeps its secrets out of
plaintext, and tells your monitoring stack when something is wrong — that is the
gap `spt` fills.

## Where spt sits

Most SSH tunnelling tools fall into one of four families, and `spt` borrows from
several without belonging cleanly to any:

- **Interactive SSH clients** (OpenSSH, PuTTY, MobaXterm, Bitvise). Their centre
  of gravity is a human at a terminal. Port forwarding is a side feature layered
  onto a shell session. `spt` has no shell at all — see
  [Introduction](introduction.md), which states the scope boundary plainly: no
  interactive shell, no `scp`, no TUN/TAP.
- **Keep-it-alive wrappers** (`autossh`, `systemd` units, cron loops). Their job
  is to notice when `ssh` dies and start it again. This is the family `spt`
  competes with most directly — but `spt` replaces the *entire* stack (the SSH
  client, the monitor, the restart policy, the config, and the observability)
  with one supervised process. See [Resilience](resilience.md).
- **Transparent VPN-over-SSH** (`sshuttle`). It reroutes whole subnets through an
  SSH session using host firewall rules. `spt` never touches routing tables; it
  binds explicit listeners for explicit forwards. See [Forwarding](forwarding.md).
- **Reverse-ingress / relay services** (ngrok, Cloudflare Tunnel, frp, rathole).
  They expose a private service to the public internet, usually through a
  third-party or self-hosted relay speaking a bespoke protocol. `spt` speaks
  standard SSH to a server *you already run and trust*, and adds an experimental
  SSH-over-QUIC path. The trust model is fundamentally different.

`spt` is **client-only**. It connects to an existing SSH2 server (OpenSSH,
dropbear, …) or, over the experimental SSH3 backend, to an
[`francoismichel/ssh3`](https://github.com/francoismichel/ssh3) reference server
or another `spt` running `spt ssh3-serve`. There is no general server role and no
hosted relay. That is the single most important fact for the comparisons below:
`spt` presupposes that you control (or are authorised on) the far end. See the
[Architecture Overview](architecture.md) for the spt ↔ spt model.

## Feature matrix

The following tables compare `spt` against a representative tool from each family
across the dimensions that matter for an always-on forward. Cells use
✅ (first-class), ⚠️ (partial, scriptable, or with caveats), and ❌ (absent).
Notes are deliberately terse; the prose sections that follow give the fair,
full picture.

### Persistence, forwarding, and topology

| Capability | spt | OpenSSH `ssh` | autossh | PuTTY / KiTTY | sshuttle | ngrok / cloudflared | frp / rathole |
|---|---|---|---|---|---|---|---|
| Auto-reconnect on drop | ✅ state machine + backoff | ❌ dies on drop | ✅ restarts `ssh` | ⚠️ KiTTY only | ⚠️ restart on error | ✅ managed agent | ✅ built-in |
| Exponential backoff + jitter | ✅ full-jitter, `reset_after` | ❌ | ⚠️ fixed poll | ❌ | ❌ | ✅ | ✅ |
| Endpoint failover | ✅ priority/weighted/manual | ❌ | ❌ | ❌ | ❌ | ⚠️ via DNS/LB | ⚠️ external |
| Health checks / instability detect | ✅ probes + sliding-window | ⚠️ `ServerAliveInterval` | ⚠️ monitor port | ❌ | ❌ | ✅ heartbeats | ⚠️ heartbeat |
| Local forward (`-L`) | ✅ | ✅ | ✅ (via ssh) | ✅ | n/a | ⚠️ | ✅ |
| Remote/reverse forward (`-R`) | ✅ | ✅ | ✅ (via ssh) | ✅ | ❌ | ✅ core feature | ✅ core feature |
| Dynamic SOCKS (`-D`) | ✅ SOCKS4/4a/5 + HTTP CONNECT + ACLs | ✅ SOCKS5 | ✅ (via ssh) | ✅ | ❌ | ❌ | ⚠️ |
| UNIX-domain socket forward | ✅ both directions | ✅ (`streamlocal`) | ✅ (via ssh) | ❌ | ❌ | ❌ | ⚠️ |
| UDP forward | ✅ framed; native over SSH3/QUIC | ❌ | ❌ | ❌ | ⚠️ DNS only | ⚠️ | ✅ |
| Multi-hop / jump chain | ✅ per-hop auth+trust; SSH/SOCKS/HTTP hops | ✅ `ProxyJump` | ⚠️ via ssh cfg | ⚠️ chained sessions | ❌ | ❌ | ❌ |
| Transparent subnet routing (VPN) | ❌ explicit listeners only | ⚠️ `-w` TUN | ❌ | ❌ | ✅ its whole point | ⚠️ WARP | ❌ |
| Interactive shell / `scp` | ❌ (SFTP only) | ✅ | ✅ (via ssh) | ✅ | ❌ | ❌ | ❌ |

### Transport, obfuscation, and trust

| Capability | spt | OpenSSH `ssh` | autossh | PuTTY / KiTTY | sshuttle | ngrok / cloudflared | frp / rathole |
|---|---|---|---|---|---|---|---|
| SSH implementation | pure-Rust `russh` 0.61 | OpenSSH C | wraps OpenSSH | PuTTY C | OpenSSH C | bespoke (not SSH) | bespoke (not SSH) |
| QUIC / HTTP-3 transport | ⚠️ experimental SSH3 backend | ❌ | ❌ | ❌ | ❌ | ✅ (QUIC edge) | ❌ |
| Pluggable obfuscation | ✅ obfs4 / meek / WS / Shadowsocks (spt↔spt) | ❌ (via `ProxyCommand`) | ❌ | ❌ | ❌ | ⚠️ TLS fronting | ❌ |
| Host-key pinning | ✅ `known_hosts` TOFU + SHA-256 pin | ✅ `known_hosts` | ✅ (via ssh) | ✅ | ✅ (via ssh) | n/a (relay trust) | ⚠️ token |
| TLS SPKI pinning | ✅ for SSH3 + remote sinks | ❌ | ❌ | ❌ | ❌ | ⚠️ managed | ⚠️ |
| Trust model | **your own SSH server** | your own server | your own server | your own server | your own server | **third-party relay** | **self-hosted relay** |
| Post-quantum KEX | ⚠️ gated (ML-KEM) | ✅ (`mlkem768x25519`) | ✅ (via ssh) | ⚠️ recent builds | ✅ (via ssh) | ⚠️ managed | ❌ |

### Operations, secrets, and observability

| Capability | spt | OpenSSH `ssh` | autossh | PuTTY / KiTTY | sshuttle | ngrok / cloudflared | frp / rathole |
|---|---|---|---|---|---|---|---|
| Config-as-code (validated) | ✅ TOML schema + `config validate` | ⚠️ `~/.ssh/config` | ⚠️ flags/env | ⚠️ registry/session files | ⚠️ flags | ✅ YAML + dashboard | ✅ TOML |
| Hot reload (SIGHUP / file-watch) | ✅ | ⚠️ per-session `~C` | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| Encrypted secrets vault / keychain | ✅ AES-256-GCM + Argon2id + OS keychain | ⚠️ agent + key files | ❌ | ⚠️ Pageant | ❌ | ✅ managed | ⚠️ token file |
| Structured events / alerting | ✅ event bus: webhook/email/SMS/push/MCP/cmd | ❌ | ❌ | ❌ | ❌ | ✅ dashboard | ⚠️ |
| Metrics (Prometheus / OTLP) | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| SNMP agent + traps | ✅ SNMPv3 | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Status API / snapshot | ✅ read-only HTTP/JSON | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| Service integration | ✅ systemd/launchd/SCM/OpenRC/SysV/Task Sched | ❌ (roll your own) | ⚠️ + systemd | ⚠️ manual | ⚠️ | ✅ installer | ⚠️ |
| Hardened container image | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ⚠️ |
| SFTP transfer / FUSE mount | ✅ | ✅ (`sftp`/`scp`) | ❌ | ✅ (PSFTP) | ❌ | ❌ | ❌ |
| MCP control server | ✅ (read-only default) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Signed auto-updater | ✅ | ❌ (OS package mgr) | ❌ | ❌ | ❌ | ✅ | ❌ |
| GUI | ❌ (TUI configurator only) | ❌ | ❌ | ✅ | ❌ | ✅ web dashboard | ❌ |
| Cross-platform | ✅ Linux/macOS/Windows, x86-64 + aarch64 | ✅ | ⚠️ Unix-first | ⚠️ Windows-first | ⚠️ Unix + WSL | ✅ | ✅ |

Read these tables as a map of *emphasis*, not a scorecard. A ❌ against OpenSSH
for "structured events" does not make OpenSSH worse at being OpenSSH; it means
event routing is simply not what a general SSH client is for. The prose below
explains where each tool genuinely wins.

## vs OpenSSH

OpenSSH is the baseline everyone knows, and it is excellent. `ssh -L`, `ssh -R`,
and `ssh -D` cover every forward direction; `ProxyJump`/`-J` and `ProxyCommand`
handle arbitrarily deep bastion chains; `ControlMaster` + `ControlPersist`
multiplex many sessions over one connection; `~/.ssh/config` is a mature,
per-host declarative format; `ssh-agent`, OpenSSH certificates, GSSAPI, FIDO/U2F
security keys, and (in current releases) post-quantum key exchange give it an
authentication surface `spt` deliberately mirrors rather than exceeds. It is
audited, ubiquitous, and on virtually every machine including modern Windows. For
an interactive session, ad-hoc port forward, `scp`, or anything a human drives at
a prompt, OpenSSH is the right tool and `spt` is not a replacement.

What OpenSSH does *not* do is stay up on its own. A dropped connection ends the
`ssh` process; there is no reconnect, no backoff, no endpoint failover, and no
instability detection. `ServerAliveInterval`/`ServerAliveCountMax` will
eventually *notice* a dead link and `ExitOnForwardFailure` will refuse to start
if a forward cannot bind, but the recovery policy is still "the process exits and
something else must restart it." OpenSSH also has no built-in observability
(structured events, metrics, SNMP, a status snapshot), no encrypted secrets vault
beyond agent-held keys, no validated config with hot reload, and no packaged
service integration — those are left to the surrounding system. This is exactly
the boundary `spt` fills: it wraps a pure-Rust SSH stack in a supervisor
([Resilience](resilience.md)), a validated config with SIGHUP/file-watch reload,
a secrets layer ([Authentication](authentication.md),
[Security](security.md)), and a full observability stack
([Observability](observability.md)).

**When to pick OpenSSH instead:** interactive administration, one-off tunnels,
`scp`/`sftp` at the shell, jump-box workflows you drive by hand, or any
environment where installing another binary is unwelcome and a `systemd` unit
around `ssh` is "good enough." Many operators quite reasonably run OpenSSH for
interactive work and `spt` for the handful of forwards that must never go down.

## vs autossh

`autossh` is the tool `spt` competes with most directly, and it earned its place.
It launches `ssh`, watches it through a pair of monitoring ports (or, more
commonly today, through `ServerAliveInterval`), and restarts the session when it
detects a failure. It is tiny, battle-tested, dependency-light, and reuses your
existing `~/.ssh/config` verbatim. Paired with a `systemd` unit
(`Restart=always`, `RestartSec=`) or a supervisor like `runit`, it is a
completely legitimate way to keep a single forward alive, and for a long time it
was the default answer to "how do I make this tunnel permanent."

The gap `spt` closes is everything *around* the restart. `autossh`'s recovery is
a fixed-interval poll-and-restart with no exponential backoff, no jitter, and no
`reset_after` stabilisation window — many `autossh` instances hammering the same
bastion after a network blip is a genuine reconnect-storm risk that `spt`'s
full-jitter backoff is specifically designed to avoid (see
[Resilience](resilience.md)). `autossh` has no concept of multiple endpoints or
failover, no sliding-window instability detection, no health-check depth control,
no structured events or metrics, no secrets management, and no validated config —
it is a thin wrapper, so everything else is on you and your surrounding scripts.
`spt` folds the SSH client, the monitor, the backoff policy, endpoint failover,
keepalive-driven liveness, secrets resolution, host-key pinning, and observability
into one supervised process with one validated config file, and ships native
service units for six init systems so you are not hand-writing the wrapper unit at
all ([Service](service.md)).

**When to pick autossh instead:** a single, simple, long-lived forward on a Unix
box where you already have OpenSSH configured, you do not need failover or
metrics, and adding a several-megabyte Rust binary is more than the problem
warrants. `autossh` + a `systemd` unit is the minimal, honest answer for that
case, and `spt` is overkill for it. `spt` pays off when you have *many* forwards,
need failover or alerting, must keep secrets out of plaintext, or want a single
declarative source of truth across a fleet.

## vs PuTTY / KiTTY / MobaXterm / Bitvise

On Windows the tunnelling story has historically run through GUI clients, and
they are good at what they do. **PuTTY** is the reference Windows SSH client: a
capable terminal, per-session tunnel configuration, the `plink` command-line
companion for scripting, `pageant` as the key agent, and `PSFTP`/`PSCP` for
transfers. **KiTTY** is the popular PuTTY fork that adds precisely the operational
niceties PuTTY lacks — automatic reconnection, session folders, portable
configuration, and scripted logins — which makes it a real competitor for
"keep a tunnel up" on a Windows desktop. **MobaXterm** wraps a tabbed terminal, an
X server, an embedded toolbox, and a graphical tunnel manager into one polished
package that many Windows admins live in all day. **Bitvise SSH Client**
(formerly Tunnelier) is a particularly strong forwarding client: static and
dynamic port forwarding, an integrated FTP-to-SFTP bridge, auto-reconnect, and a
matching server product for the far end.

Where these part company with `spt` is model and target audience. They are
GUI-first, interactive, desktop-oriented, and (KiTTY, PuTTY, MobaXterm) largely
Windows-centric; their persistence features are attached to a session a user
opened, not to a headless service supervising many profiles unattended on a
server. They generally lack config-as-code with schema validation and hot reload,
an encrypted secrets vault with OS-keychain integration, an event bus that can
page an on-call engineer, Prometheus/OTLP metrics, an SNMP agent, and native
cross-platform service installation. `spt` is headless and daemon-first: the
[TUI](tui.md) is a *configurator*, not a terminal, and the output of an `spt`
deployment is a running service plus a stream of events and metrics, not a window
you keep open. `spt` is also natively cross-platform on the same config file
(Linux, macOS, Windows, x86-64 and aarch64), where these tools are strongest on
Windows specifically.

**When to pick a GUI client instead:** interactive Windows administration, users
who want a terminal and a tunnel manager in one window, occasional or
desk-bound forwards, X11 forwarding, or shops standardised on Bitvise/MobaXterm
tooling. For an engineer at a desk who wants to open a couple of tunnels and see a
terminal, PuTTY/KiTTY/MobaXterm is a better fit than a config-driven daemon. `spt`
earns its place when the forward has to run on a server with no one watching,
reconnect itself, and report into monitoring.

## vs sshuttle

`sshuttle` solves a genuinely different problem and solves it elegantly: it is a
"poor person's VPN" that transparently routes whole subnets over an ordinary SSH
connection. It installs local firewall rules (iptables/nft on Linux, pf on macOS)
to capture traffic to configured CIDRs, runs a small Python helper on the remote
(no special server software or root on the far end beyond a Python interpreter),
and can also tunnel DNS. The result is that unmodified applications reach a remote
network by IP with no per-service configuration — you say "route `10.0.0.0/8` and
DNS over this SSH host" and everything just works. For "give me network-level
access to that VPC through the bastion," `sshuttle` is often the fastest path and
`spt` cannot do it at all.

`spt` is explicitly *not* a VPN: it has no TUN/TAP device and touches no routing
tables (see the scope note in [Introduction](introduction.md)). It forwards
**named, explicit** services — this local port to that remote host:port — rather
than transparently capturing a subnet. That explicitness is a feature for the
supervised-service use case: each forward has its own bind policy, ACLs, rate
limits, and required/optional health semantics ([Forwarding](forwarding.md)), and
the whole set is a validated config under a self-healing supervisor. `sshuttle`,
by contrast, is a foreground tool oriented at an operator's own machine; it
restarts on some errors but has no backoff/failover state machine, no endpoint
selection, no secrets vault, no metrics or eventing, and it needs local
privileges to install its firewall rules. It also carries only TCP (plus DNS),
not arbitrary UDP or UNIX-domain sockets.

**When to pick sshuttle instead:** you want broad, transparent, subnet-level
network access over SSH for interactive or developer use, without enumerating
individual services, and you are comfortable with local firewall manipulation.
When you instead need a fixed, enumerated set of forwards that stay up unattended
with failover and observability, that is `spt`.

## vs ngrok / cloudflared / frp / rathole

This family answers "expose a service behind NAT to the outside world," and the
trust model is the axis that separates them from `spt`. **ngrok** is a hosted
service: run the agent, get a public URL, and ngrok's global edge relays traffic
to your local process — with TLS, request inspection, auth, and zero server
infrastructure of your own. **Cloudflare Tunnel** (`cloudflared`) is similar in
spirit: the connector dials out to Cloudflare's edge, so a service with no public
IP becomes reachable through Cloudflare's network and zero-trust access policies,
again with no inbound ports and no server you operate. **frp** is the self-hosted
counterpart — you run `frps` on a box with a public IP and `frpc` clients dial in;
it proxies TCP, UDP, HTTP, and HTTPS with a rich feature set. **rathole** is a
lightweight, high-performance Rust reimplementation of the same self-hosted
reverse-proxy idea, focused on fast, lean NAT traversal.

The decisive difference is **who you trust with your plaintext**. ngrok and
Cloudflare Tunnel route your traffic through a *third-party relay*; that is
enormously convenient (public ingress in seconds, no server to run, no firewall
change) and is the correct choice when you have no reachable server of your own or
want a shareable public URL. But it means a third party sits in the data path, and
you depend on their service and terms. frp and rathole remove the third party but
introduce *their own* server component and *their own* wire protocol that you must
deploy, secure, and keep patched. `spt` takes neither path: it speaks **standard
SSH** to a server you already run and already trust — the same OpenSSH host you
use for everything else — and adds host-key/TLS pinning, an encrypted secrets
vault, and a supervisor on the client side. It reuses SSH's mature authentication
and its cryptographic track record rather than a bespoke protocol, and it never
interposes an outside relay. The flip side, stated honestly: `spt` **requires**
that trusted, reachable SSH endpoint. It gives you no public URL and no
NAT-traversal magic on its own; if you have nowhere to terminate the tunnel, `spt`
has nothing to connect to.

**When to pick this family instead:** you need public ingress with no server of
your own (ngrok, Cloudflare Tunnel); you want Cloudflare's zero-trust access
layer in front of internal apps (`cloudflared`); or you want a self-hosted
reverse proxy with a purpose-built protocol and HTTP-aware routing (frp/rathole).
`spt` is the choice when the far end is an SSH server you control and you want
SSH's trust model plus supervision, not a relay.

## vs hand-rolled scripts

Nearly every team has, at some point, written the tunnel supervisor as a shell
one-liner: `while true; do ssh -N -L ... ; sleep 5; done`, or a slightly fancier
Python/bash wrapper with a log line and a retry counter. This deserves respect: it
has zero dependencies beyond `ssh`, it is transparent and trivially auditable, and
for a throwaway or single-purpose forward it is genuinely the pragmatic answer.

The trouble is that the script is never actually finished. A naive loop has no
backoff, so a hard-down endpoint becomes a busy reconnect storm; no jitter, so a
fleet of boxes retries in lockstep against one bastion; no distinction between a
transient blip and a persistently unstable link; no host-key pinning discipline
(people disable `StrictHostKeyChecking` "temporarily" and never re-enable it); no
secrets handling beyond a key path or, worse, a password on the command line; no
structured logs, metrics, or alerting; and no graceful shutdown or service
integration. Each of those gaps is a small, well-understood engineering problem —
and `spt` is, in effect, the accumulation of all of them solved once, correctly,
and tested: full-jitter exponential backoff with a stabilisation window and
instability detection ([Resilience](resilience.md)), enforced host-key/pin trust
([Security](security.md)), a secrets vault with zeroize-on-drop
([Authentication](authentication.md)), an event/metrics/SNMP stack
([Observability](observability.md)), and native service units. The scripts also
tend to rot: they accrete per-host special cases until nobody dares touch them,
whereas `spt`'s behaviour lives in a validated config that `spt config validate`
checks before it ever runs.

**When to pick a script instead:** a genuinely disposable, run-it-once forward on
your own laptop, or a constrained environment where you truly cannot add a binary
and a five-line loop is proportionate. The moment that script grows a retry
counter, a log file, a second endpoint, or a credential, it is reimplementing
`spt` badly — and that is the signal to switch.

## When to choose spt

Reach for `spt` when most of the following are true:

- The forward must **stay up unattended** for weeks or months and recover on its
  own across drops, restarts, DNS changes, and network moves.
- You want **config-as-code**: one validated TOML file, hot-reloadable, that is
  the single source of truth for every profile and forward across a fleet.
- You need more than reconnect — **endpoint failover**, instability detection,
  keepalive-driven liveness, and health checks of tunable depth.
- **Secrets must not live in plaintext**: references resolve through an OS
  keychain, an encrypted vault, env, or files, with zeroize-on-drop.
- **Trust must be enforced**: `known_hosts` TOFU or SHA-256 host-key pins for
  SSH2, and TLS SPKI pinning for the SSH3/QUIC path and remote sinks.
- You want **observability built in**: structured events routed to
  webhook/email/SMS/push/MCP/command sinks, Prometheus/OTLP metrics, an SNMPv3
  agent, a read-only status API, and Windows Event Log integration.
- You want it to run as a **first-class service** on systemd/launchd/Windows
  SCM/OpenRC/SysV/Task Scheduler, or inside a hardened container, on Linux, macOS,
  or Windows across x86-64 and aarch64.
- You need the fuller forwarding surface: local/remote/dynamic, UNIX-domain
  sockets, UDP (framed, or native over SSH3/QUIC), multi-hop chains with per-hop
  auth and trust, SFTP transfer and FUSE mounts, and pluggable obfuscation.

Reach for **something else** when:

- You want an **interactive shell**, `scp`, or ad-hoc hand-driven tunnels →
  OpenSSH, or PuTTY/KiTTY/MobaXterm/Bitvise on Windows.
- You want **transparent subnet-level VPN access** over SSH → sshuttle.
- You need a **public URL or NAT traversal with no server of your own**, or a
  hosted zero-trust access layer → ngrok or Cloudflare Tunnel; frp/rathole if you
  want a self-hosted reverse proxy with its own protocol.
- The job is a **single throwaway forward** and adding a binary is
  disproportionate → `autossh` + a `systemd` unit, or a small script.

In one sentence: choose `spt` when a tunnel is *infrastructure* — something that
has to be declared, supervised, secured, and monitored like any other service —
and choose one of the tools above when a tunnel is a *session*, a *route*, or a
*relay*.

## Related pages

- [Introduction](introduction.md) — scope boundary and what `spt` is and is not
- [Architecture Overview](architecture.md) — the spt ↔ spt client model
- [Transports](transports.md) — SSH2, experimental SSH3, and obfuscation
- [Forwarding](forwarding.md) — every forward kind and multi-hop chains
- [Authentication](authentication.md) — the full SSH2/SSH3 auth surface
- [Resilience](resilience.md) — reconnect, backoff, failover, and health checks
- [Security](security.md) — trust boundaries, secrets, and hardening
- [Observability](observability.md) — events, metrics, SNMP, and status
