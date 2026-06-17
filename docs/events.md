# Events

The event subsystem fans typed lifecycle events to a configurable set of
sinks. Bindings filter and template events; the dispatcher persists failed
deliveries to disk for retry.

## Runtime status

The events pipeline **is wired into `tunnel run`.** At startup the binary
constructs one `EventBus` (with a ring buffer), builds the sink registry
from `[[events.sinks]]`, spawns the `Dispatcher`, and threads an `EventBus`
handle into the supervisor so profile/forward lifecycle transitions re-emit
as canonical `Event`s. (Earlier builds left this subsystem inert — that
caveat no longer applies.)

**All sink kinds now fire at runtime.** Every configured `[[events.sinks]]`
entry is constructed at startup and delivers; a per-sink build failure is
logged loudly and that one sink is skipped (never silently dropped):

| Sink kind                       | Status                                    |
|---------------------------------|-------------------------------------------|
| `http` / `webhook_post`         | delivered                                 |
| `email` (SMTP)                  | delivered                                 |
| `sms`                           | delivered                                 |
| `push` / `webpush`              | delivered (`WebPushSink` when `subscriptions` + `vapid_private_key` are present, otherwise `PushSink`) |
| `command`                       | delivered (requires a matching `[[events.commands]]` entry with `allow_exec = true`) |
| `mcp_notify`                    | delivered to the loopback MCP broadcast channel — see caveat below |

**`mcp_notify` caveat.** The `mcp_notify` sink is live: it publishes each
event as a `spt/event` JSON-RPC frame onto the loopback MCP broadcast channel
(the same broadcast seam `stats_subscribe` streams over). However, a
client-facing MCP subscription tool to stream those frames out to a connected
client **is not yet provided** — so frames are dropped when nothing is
subscribed. The notifier itself is real (no Noop placeholder remains); only
the consumer-side subscription tool is pending.

**TUI configurability (v1).** The events surface is editable from the TUI for
`http`, `webhook_post`, `command`, and `mcp_notify` sinks plus their bindings.
`email` / `sms` / `push` sink **editing in the TUI** is still deferred
(configure those kinds by hand in TOML) — note this is a TUI-editor gap only;
all kinds deliver at runtime regardless of how they were configured.

## Event shape

Each `Event` carries:

- `kind` — e.g. `profile.degraded`, `forward.bind_failed`,
  `auth.failed`, `mcp.tool_called`.
- `severity` — info | warn | error.
- `fields` — a string-keyed map of event-specific data (already-redacted).
- `timestamp_ms` — Unix epoch milliseconds.

## Bindings

    [[events.bindings]]
    name = "ops-pager"
    match = { kind = "profile.degraded", severity = "error" }
    sinks = ["pagerduty", "slack"]
    dedupe = "5m"

`match` is a flat predicate; multiple keys AND together. `dedupe` suppresses
re-fires of identical events within the window.

## Sinks

    [[events.sinks]]
    name = "slack"
    type = "webhook_post"        # http | webhook_post | email | sms | push | command | mcp_notify
    endpoint = "https://hooks.slack.com/..."
    template = "{{kind}} on {{profile}}: {{message}}"

Templates use mustache-like `{{field}}` substitution. Unknown fields render
as the empty string (a `Null` field renders empty, never the literal
`"null"`).

For `email` sinks the subject line is templated too: `subject_template` is
configurable (it accepts the same `{{field}}` substitution) and defaults to
`"[{{severity}}] {{kind}}"` when omitted.

## Delivery & retries

Failed deliveries are spooled to `<state_dir>/spool/<sink>/` and retried
with exponential backoff. The spool size is bounded; oldest entries are
dropped first.

## Replay

    spt event replay --since 1h --binding ops-pager

Re-runs historical events through one binding for testing.

## Pinned TLS for sinks (t5-e2)

Every `[[events.sinks]]` entry honours three optional fields that select
the TLS posture for its outbound HTTPS / SMTP endpoint:

- `pin_spki_sha256 = ["SHA256:<base64>", ...]` — SPKI SHA-256 pin set.
  Non-empty enables leaf-cert pinning against the destination.
- `allow_self_signed = false` — when `true`, the WebPKI verifier is
  skipped and the pin set becomes the sole trust anchor. Requires a
  non-empty `pin_spki_sha256`.
- `max_cert_chain_depth = 5` — defaults to `Some(5)` when omitted.

HTTPS sinks (`http`, `webhook_post`, `webpush`, `sms`, generic `push`)
build their underlying `reqwest::Client` via
`spt_trust::PinnedTlsConnector::from_config_parts`. SMTP (`email`)
currently exposes the same schema-level fields; the `lettre 0.11.19`
transport's TLS wiring does not yet route through the pinned connector
(deferred — `lettre` does not surface a custom-verifier hook at the
locked version, and routing SMTP through a raw `tokio-rustls` wrapper
is a follow-up).
