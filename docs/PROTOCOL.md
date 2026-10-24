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
