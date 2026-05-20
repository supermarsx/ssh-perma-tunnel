# Events

The event subsystem fans typed lifecycle events to a configurable set of
sinks. Bindings filter and template events; the dispatcher persists failed
deliveries to disk for retry.

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
    type = "https"               # https|smtp|sms|push|command|mcp_notify
    endpoint = "https://hooks.slack.com/..."
    template = "{{kind}} on {{profile}}: {{message}}"

Templates use mustache-like `{{field}}` substitution. Unknown fields render
as the empty string.

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
