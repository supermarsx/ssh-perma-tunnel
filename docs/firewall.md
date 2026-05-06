# Firewall

`spt` plans firewall rules per OS and applies them idempotently. The
binary refuses to run a non-dry-run apply without explicit operator
confirmation; in M0 only `--dry-run` is wired.

## Backends

| Backend         | OS      | Native command          |
|-----------------|---------|-------------------------|
| `Nftables`      | Linux   | `nft -f -`              |
| `Iptables`      | Linux   | `iptables`              |
| `Pf`            | macOS   | `pfctl -a com.spt`      |
| `WindowsFirewall` | Windows | `netsh advfirewall`   |

## Plan & apply

    spt firewall plan --json
    spt firewall apply --system --dry-run     # safe preview
    spt firewall remove --system --dry-run

The planner is **pure** — same input always yields the same script — so
golden tests can pin the rendered output.

## Rule shape

Rules are config-agnostic; the dispatcher in `spt-bin` translates `[firewall]`
config plus forward bind addresses into a flat `Vec<Rule>`. Each rule has
direction, action (allow / deny / reject), L4 protocol, optional CIDR
source/dest, and an interface selector. Rules are tagged with `spt:<id>`
in their native form so `remove` is idempotent.

## See also

- `crates/spt-firewall/src/lib.rs` for the planner trait.
- `spt firewall interfaces` to list bind targets.
