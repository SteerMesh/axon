# Wire protocol v1

Every application message is an envelope inside an authenticated Noise
channel. Relay routing headers are separate and contain no session payload.

```json
{
  "v": 1,
  "id": "01J...",
  "type": "session.output",
  "sid": "01J...",
  "epoch": "01J...",
  "seq": 1042,
  "ts": "2026-10-24T00:00:00Z",
  "data": "base64"
}
```

## Guarantees

- Request messages have a unique `id`; responses set `reply_to`.
- Input additionally has an `idempotency_key` scoped to the authenticated
  device.
- The maximum decoded application payload is 64 KiB.
- Output sequences are monotonic within one stream epoch.
- A replay request below `min_seq` returns `replay_gap` with retained bounds.
- `session.subscribe` atomically returns retained output and registers the
  device for subsequent `session.output` events. A new subscription replaces
  that device's previous subscription.
- `session.output` carries the stream epoch and sequence in the envelope; its
  data is the base64-encoded terminal byte chunk. `session.closed` terminates
  the live stream after the managed process exits. `session.resync` means the
  live subscriber fell behind while the process is still running; the client
  resumes with a new `session.subscribe` from its next expected sequence.
- Unknown major protocol versions are rejected before command dispatch.

## Error codes

| Code                  | Meaning                                      |
|-----------------------|----------------------------------------------|
| `invalid_message`     | Schema or size validation failed             |
| `unsupported_version` | The major protocol version is not supported  |
| `unauthorized`        | Device is not authorized for the operation   |
| `read_only`           | Session permission forbids input             |
| `not_found`           | Mate or session does not exist               |
| `replay_gap`          | Requested output has left the replay buffer  |
| `rate_limited`        | Device exceeded an operation limit           |
| `conflict`            | Name or command conflicts with existing data |

## Session output subscription

The client subscribes with the next sequence it needs:

```json
{"v":1,"id":"01J...","type":"session.subscribe","sid":"01J...","ts":"2026-10-24T00:00:00Z","data":{"from_seq":42}}
```

The response data uses the replay shape (`chunks`, `min_seq`, `max_seq`, and
`gap`). If `gap` is true, the client displays the loss boundary and subscribes
again from `min_seq`. Otherwise the Agent begins sending unsolicited encrypted
events after the response frame has been delivered:

```json
{"v":1,"id":"01J...","type":"session.output","sid":"01J...","epoch":"01J...","seq":43,"ts":"2026-10-24T00:00:01Z","data":"dGVybWluYWwgYnl0ZXM="}
```

Responses and pushed events share one serialized Noise send path so cipher
nonces and WebSocket frame order remain identical.
