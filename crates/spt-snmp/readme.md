# spt-snmp

A standalone SNMPv3 USM agent and trap sender, written from scratch against
the relevant RFCs:

- **RFC 3411** — SNMP architecture
- **RFC 3412** — Message processing and dispatching
- **RFC 3414** — User-based Security Model (USM)
- **RFC 3416** — Protocol operations (Get / GetNext / GetBulk / Set / Trap)
- **RFC 3826** — AES-128-CFB privacy
- **RFC 7860** — HMAC-SHA-2 authentication for USM

`spt-snmp` was built for the [spt](https://github.com/supermarsx/ssh-perma-tunnel)
SSH permanent tunnel daemon, but it has **no `spt-*` dependencies** and is
intended to be usable on its own.

## Why a new crate?

The existing Rust SNMP ecosystem is split between manager-side libraries
(`snmp`, `snmp_mp`, `snmp-parser`) and partial agent implementations that
either don't support SNMPv3 USM, don't support modern authentication
(HMAC-SHA-256 per RFC 7860), or are tied to specific runtime structures.
`spt-snmp` aims to be:

- **Agent-first**, with a clean `MibRegistry` + `Handler` / `TableHandler`
  trait pair.
- **`authPriv` first-class**, using HMAC-SHA-256 + AES-128-CFB by default.
- **Dependency-light**: `tokio`, `aes`, `cfb-mode`, `hmac`, `sha2`, `sha1`,
  `md-5`, `rand`, `thiserror`, `tracing`, `zeroize`, `secrecy`, `async-trait`.
  No third-party SNMP crate; the codec and message envelope are
  hand-written.
- **No `unsafe`**, no panics outside tests.

## Quick start

```rust,no_run
use std::net::SocketAddr;
use spt_snmp::{
    AgentBuilder, AuthProtocol, ConstScalar, ObjectIdentifier, PrivProtocol,
    SecretBytes, UsmUser, Value,
};

# async fn run() -> spt_snmp::Result<()> {
let user = UsmUser::auth_priv(
    "monitor",
    AuthProtocol::HmacSha256,
    SecretBytes::from("auth-pass-very-long"),
    PrivProtocol::Aes128,
    SecretBytes::from("priv-pass-very-long"),
);

let agent = AgentBuilder::new()
    .bind("0.0.0.0:161".parse::<SocketAddr>().unwrap())
    .enterprise_pen(12345) // Use your registered IANA PEN.
    .add_user(user)
    .add_scalar(
        "1.3.6.1.4.1.12345.1.1.0".parse::<ObjectIdentifier>()?,
        ConstScalar::new(Value::OctetString(b"hello".to_vec())),
    )
    .run()
    .await?;
# let _ = agent;
# Ok(()) }
```

## Supported protocols

| Layer        | Protocol                | Status                                   |
|--------------|-------------------------|------------------------------------------|
| Auth         | HMAC-SHA-256 (RFC 7860) | Default; recommended                     |
| Auth         | HMAC-SHA-1   (RFC 3414) | Legacy                                   |
| Auth         | HMAC-MD5     (RFC 3414) | Legacy; do not use for new deployments   |
| Privacy      | AES-128-CFB  (RFC 3826) | Mandatory; default                       |
| Privacy      | AES-256-CFB  (Reeder)   | Net-snmp interop; not RFC standardized   |
| Privacy      | DES-CBC      (RFC 3414) | Stub: returns `Privacy` error            |

`AES-256-CFB` follows the de-facto convention used by `net-snmp` (key is
extended via repeated localization). It is **not** RFC standardized; we ship
it for interop with operators who already deploy it. Document this caveat in
your operations runbook.

## PDU support

`GetRequest`, `GetNextRequest`, `GetBulkRequest`, `SetRequest`, `Response`,
`SnmpV2-Trap`, `Report`, `InformRequest` (encode-only).

GetBulk performs a strict lexicographic walk against the registered scalars
and tables; tables expose a `next(after)` cursor and so can be infinite.

## USM counters

The agent maintains the full `usmStats*` counter set required by RFC 3414 §5
and emits the appropriate `Report-PDU` on each unauthenticated discovery,
unknown engine ID, unknown user, wrong digest, decryption error, time-window
violation, and unsupported security level.

## MIB

The companion enterprise MIB lives at
[`mibs/SPT-MIB.txt`](../../mibs/SPT-MIB.txt). The checked-in MIB uses the RFC
documentation PEN `32473` as a template only. Production deployments must set
`[observability.snmp].enterprise_id` to their registered IANA Private
Enterprise Number and publish the MIB under that subtree. `AgentBuilder::run`
rejects `32473` and the older `99999` placeholder by default; tests and
examples that intentionally use the RFC documentation subtree must call
`AgentBuilder::documentation_enterprise_pen()`.

## Relationship to `net-snmp`

This crate is interoperable with `net-snmp` clients (`snmpget`, `snmpwalk`,
`snmptrapd`) when configured with matching users. We test against:

```text
snmpwalk -v3 -l authPriv -u monitor -a SHA-256 -A "auth-pass-very-long" \
         -x AES -X "priv-pass-very-long" 127.0.0.1 1.3.6.1.4.1.12345
```

## License

MIT — see [`LICENSE`](../../license.md).
