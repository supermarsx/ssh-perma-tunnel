# Firewall

`spt` plans and applies OS firewall rules for forwarded services. The planner
is pure and cross-platform; actual rule application requires administrator or
root privileges and an explicit `--yes` flag.

## Supported backends

| Backend | OS | Native command |
|---------|----|----------------|
| `nftables` | Linux (default) | `nft -f -` |
| `iptables` | Linux (legacy fallback) | `iptables` |
| `pf` | macOS | `pfctl -a com.spt -f -` |
| `windows_firewall` | Windows | `netsh advfirewall` |

All four planner implementations compile and run on every platform so that
golden-file tests can pin rendered output without needing the target OS. The
`new_planner()` function selects the platform-appropriate implementation at
runtime. On unsupported platforms it returns `UnsupportedPlatform`.

## Plan versus apply

The planner separates rendering from execution:

- `plan()` is **pure**: same input always yields the same native script.
  No filesystem, network, or shell access occurs. Tests use this path
  exclusively, and CI verifies renderer correctness through snapshot tests.
- `apply(plan, dry_run: true)` logs the rendered script and returns `Ok(())`
  without shelling out. Use this to verify the rendered output without making
  any changes.
- `apply(plan, dry_run: false)` shells out to the native command. This requires
  administrator or root privileges and must be invoked with `--yes`. Without
  `--yes`, the CLI refuses with a clear message and makes no changes. This is
  a deliberate safety gate.
- `remove(plan)` clears all rules tagged with `spt:<id>` using the same
  shell-out path. Also requires `--yes` and elevated privileges.

```
spt firewall plan --json
spt firewall apply --system --dry-run     # safe preview; no changes
spt firewall apply --system --yes         # live apply; needs admin/root
spt firewall remove --system --yes        # live remove; needs admin/root
```

`spt firewall status` reports `"live rule application not yet implemented"` only
on a genuinely unsupported platform. On supported platforms it shows the current
applied state.

## Configuration

```toml
[firewall]
enabled   = true
manager   = "auto"              # auto | nftables | iptables | pf | windows_firewall | none
apply_rules = false             # when true, spt applies rules on startup (still needs --yes)
bind_policy = "explicit"        # explicit | loopback_only | any
default_interface = "eth0"
allow_all_interfaces = false

[firewall.platform]
linux   = "auto"                # auto | nftables | iptables | none
macos   = "pf"                  # pf | none
windows = "windows_firewall"    # windows_firewall | none
```

`manager = "auto"` selects `nftables` on Linux (falling back to `iptables`),
`pf` on macOS, and `windows_firewall` on Windows. `[firewall.platform]` lets
you override the per-OS choice independently.

## Rule representation

Rules are config-agnostic. The `spt-bin` dispatcher translates `[firewall]`
config and forward bind addresses into a flat list of `Rule` values:

| Field | Values |
|-------|--------|
| `id` | Stable identifier embedded into the native rule as `spt:<id>`. Must match `[A-Za-z0-9._-]`. |
| `direction` | `in` or `out`. |
| `action` | `allow`, `deny` (silent drop), or `reject` (ICMP/RST). |
| `protocol` | `tcp` or `udp`. |
| `source_cidr` | Optional source CIDR (e.g. `10.0.0.0/8`). Absent matches any. |
| `source_port` | Optional source port. |
| `dest_cidr` | Optional destination CIDR. |
| `dest_port` | Optional destination port. |
| `interface` | Optional interface name. nftables uses `iif`/`oif`; pf uses `on`; netsh uses the adapter alias. |

All operator-controlled fields (`id`, `interface`, `source_cidr`, `dest_cidr`)
are validated against strict allowlists before any renderer interpolates them
into a native command. Invalid rules are rejected fail-closed and logged at
`warn`; they never reach the renderer.

### Renderer behaviour

**nftables**: emits `add table inet spt` followed by `flush table inet spt`
before the table body for idempotency. IPv6 CIDRs use `ip6 saddr`/`ip6 daddr`
selectors; IPv4 CIDRs use `ip saddr`/`ip daddr`. Rules are tagged with
`comment "spt:<id>"` so `remove` can match them.

**iptables**: emits one `iptables` command per rule. Chains are `INPUT` or
`OUTPUT`. Rules are annotated with `-m comment --comment spt:<id>`.

**pf**: emits `pass`/`block` rules with `label "spt:<id>"` so the anchor can
be flushed idempotently via `pfctl -a com.spt`.

**netsh**: emits one `netsh advfirewall firewall add rule` command per rule with
`name="spt:<id>"`. The `group=` and `interface=` parameters are omitted because
they are not valid on `add rule` in all supported Windows versions.

## Plan persistence

After a successful apply, the rendered plan is written to
`<state_dir>/firewall-plan.json`. On a subsequent run (including after a crash),
`spt` can load and replay the persisted plan to remove orphaned rules
idempotently without having to re-derive them from config.

## Interface and gateway configuration

Forwards that need to bind on a specific interface use:

```toml
[[profiles.forwards]]
bind_mode = "specific_interface"
bind_interface = "eth0"
```

or let `spt` select from a preference list:

```toml
[[profiles.forwards]]
bind_mode = "auto_interface"
bind_interface_preference = ["wg0", "eth0"]
```

`spt firewall bind-preview` resolves these modes to concrete listen addresses
before rendering the planned rules, so the rendered output reflects the actual
bind decisions.

Host-wide interface and gateway defaults live under `[network.interface]` and
`[network.gateway]`:

```bash
spt firewall gateway show --config /etc/spt/spt.toml --json
spt firewall gateway set --config /etc/spt/spt.toml \
  --default-interface eth0 \
  --default-gateway 192.0.2.1 \
  --gateway-interface eth0 \
  --route-check-target 198.51.100.10 \
  --require-gateway-match true
```

## Policy (Windows GPO overlay)

On Windows, GPO-style policies are readable and writable from the CLI:

```bash
spt firewall policy list --json
spt firewall policy show --config /etc/spt/spt.toml --json
spt firewall policy set Network.DefaultInterface eth0 --scope user
spt firewall policy set Network.AllowedInterfaces eth0,wg0 --scope machine --enforced
spt firewall policy set Capabilities.Ssh2Backend russh --scope machine --enforced
spt firewall policy set Capabilities.AllowGpoPolicyWrites false --scope machine --enforced
```

Write commands update `HKCU\Software\Policies\spt` (user scope) or
`HKLM\Software\Policies\spt` (machine scope). On non-Windows platforms, write
commands return `UnsupportedPlatform`; `list` still documents the supported
policy keys. If `[capabilities].allow_gpo_policy_writes = false` is set via
config or enforced policy, `policy set` returns `PermissionDenied` before
attempting any registry write.

## CLI

See [CLI Reference](cli-reference.md) for the full `spt firewall` command group,
including `spt firewall plan`, `spt firewall apply`, `spt firewall remove`,
`spt firewall status`, `spt firewall interfaces`, `spt firewall bind-preview`,
`spt firewall gateway`, and `spt firewall policy`.
