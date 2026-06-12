# Firewall

`spt` plans firewall rules per OS and applies them idempotently. The
binary refuses to run a non-dry-run apply without explicit operator
confirmation (`--yes`).

## Apply status

The per-OS renderers and the apply/remove/query plumbing **are
implemented** (no longer dry-run-only):

- The **renderers are pure and snapshot-tested** — same input always
  yields the same native script. nftables emits `ip6` / `meta nfproto`
  selectors for IPv6 CIDRs and a `flush table inet spt` preamble; the
  Windows `netsh advfirewall` renderer is corrected (no invalid params).
- **Live apply/remove** shells out to the native command (`nft`,
  `iptables`, `pfctl`, `netsh`) and requires **administrator / root**.
  Live execution is `#[ignore]`-gated in CI (needs a privileged runner);
  the renderer + plan correctness is what CI verifies.
- The applied plan is persisted to the state dir for crash-recovery /
  idempotent `remove`.

`spt firewall status` reports `"live rule application not yet
implemented"` only on a genuinely unsupported platform — it no longer
misdiagnoses an `UnsupportedPlatform` result as a permissions problem.

## Backends

| Backend         | OS      | Native command          |
|-----------------|---------|-------------------------|
| `Nftables`      | Linux   | `nft -f -`              |
| `Iptables`      | Linux   | `iptables`              |
| `Pf`            | macOS   | `pfctl -a com.spt`      |
| `WindowsFirewall` | Windows | `netsh advfirewall`   |

## Plan & apply

    spt firewall plan --json
    spt firewall apply --system --dry-run     # safe preview (no changes)
    spt firewall apply --system --yes         # live apply (needs admin/root)
    spt firewall remove --system --yes        # live remove (needs admin/root)

The planner is **pure** — same input always yields the same script — so
golden tests can pin the rendered output. A non-dry-run `apply`/`remove`
requires `--yes` and elevated privileges; without `--yes` it refuses.

## Interfaces, Gateways, And Policy

Specific-interface binds are configured per forward with
`bind_mode = "specific_interface"` and `bind_interface = "<name>"`. Automatic
selection uses `bind_mode = "auto_interface"` with
`bind_interface_preference = ["wg0", "eth0"]`. `spt firewall bind-preview`
resolves those modes to concrete listen addresses before rendering the planned
rules.

Host-wide defaults live under `[network.interface]` and `[network.gateway]`.
Manage them from the CLI:

```bash
spt firewall gateway show --config /etc/spt/spt.toml --json
spt firewall gateway set --config /etc/spt/spt.toml \
  --default-interface eth0 \
  --default-gateway 192.0.2.1 \
  --gateway-interface eth0 \
  --route-check-target 198.51.100.10 \
  --require-gateway-match true
```

GPO-style policies are visible and writable from the CLI:

```bash
spt firewall policy list --json
spt firewall policy show --config /etc/spt/spt.toml --json
spt firewall policy set Network.DefaultInterface eth0 --scope user
spt firewall policy set Network.AllowedInterfaces eth0,wg0 --scope machine --enforced
spt firewall policy set Capabilities.Ssh2Backend russh --scope machine --enforced
spt firewall policy set Capabilities.AllowGpoPolicyWrites false --scope machine --enforced
```

On Windows these commands write `HKCU`/`HKLM\Software\Policies\spt`. On other
platforms write commands return `UnsupportedPlatform`; `list` still documents
the supported policy keys. If config or enforced policy sets
`[capabilities].allow_gpo_policy_writes = false`, `policy set|unset` returns
`PermissionDenied` before attempting a registry write.

## Rule shape

Rules are config-agnostic; the dispatcher in `spt-bin` translates `[firewall]`
config plus forward bind addresses into a flat `Vec<Rule>`. Each rule has
direction, action (allow / deny / reject), L4 protocol, optional CIDR
source/dest, and an interface selector. Rules are tagged with `spt:<id>`
in their native form so `remove` is idempotent.

## See also

- `crates/spt-firewall/src/lib.rs` for the planner trait.
- `spt firewall interfaces` to list bind targets.
