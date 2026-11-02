# Implementation status

Axon has a complete MVP slice across the host agent, content-blind relay, and
mobile PWA. The current implementation is suitable for local development and
protocol validation, but it is not yet a production release.

## Implemented

- PTY ownership for shell, Claude, Kiro, SSH, Docker, and tmux targets.
- Ordered output replay with sequence numbers, retained bounds, and explicit
  replay-gap reporting.
- Idempotent, size-limited, serialized terminal input.
- Private Unix-domain IPC with local session control and live attachment.
- Ed25519 device identity, X25519 Noise IK channels, signed pairing records,
  one-time QR tokens, and revocation.
- SQLite device metadata and hashed audit entries.
- Content-blind WebSocket relay routing.
- Mobile-first installable PWA with terminal rendering, prompt composition,
  IndexedDB-held non-extractable keys, pairing, and encrypted command exchange.
- Encrypted session subscriptions with one atomic replay snapshot followed by
  server-pushed ordered output and terminal-closure events.
- Cross-language Go and TypeScript Noise interoperability tests.
- LaunchAgent and systemd user-service generation.
- Persisted paired Mate connection metadata (keys, relay URL) in the PWA's
  IndexedDB, with a device picker to reconnect without re-scanning a QR code
  and a distinct error path for mate key rotation/revocation.
- Relay-triggered Web Push wake notifications for a backgrounded or closed
  PWA: when the relay has no connected device peer for a frame -- the same
  content-blind check that already drops undeliverable frames -- it looks
  up a stored push subscription for that device and sends a fixed,
  content-free `{"type":"wake"}` payload. The relay centralizes VAPID key
  custody (`AXON_RELAY_VAPID_PUBLIC_KEY`/`AXON_RELAY_VAPID_PRIVATE_KEY`) and
  serves the public key over `GET /v1/vapid-key` so it can rotate without a
  PWA rebuild. Subscriptions are registered via `POST /v1/push/subscribe`
  and removed via `DELETE /v1/push/subscribe`, and are self-pruning: a
  404/410 from the push service deletes the stored row. This is distinct
  from, and complements, encrypted output delivered over an already-open
  WebSocket -- it exists specifically to reach a client that has none.
  Subscription cleanup is wired into the PWA's forget-device flow, so a
  forgotten device stops receiving wake pings.
- Scoped, expiring, self-verifying relay route credentials (Relay Access
  Tokens). Every mate and every device now authorizes its relay connection
  (and the push-subscribe REST calls above) with its own signed, scoped,
  time-limited token instead of one static shared secret used identically
  by everyone -- see `docs/ARCHITECTURE.md`'s "Relay credentials" section.
  The device-scope token is persisted alongside the rest of the PWA's
  `PairedMate` record and renewed in-channel via `relay.token.refresh`
  (see `docs/PROTOCOL.md`) before it expires. `devices.revoke` also now
  drops the device's live channel immediately rather than only via token
  expiry.

## Required upgrade action

Upgrading to this release is a **breaking change** for any deployed relay:
`AXON_RELAY_TOKEN` is gone. The relay now authenticates connections against
each mate's Ed25519 **public** signing key instead of a shared secret it
used to be handed directly, so an operator must provision
`AXON_RELAY_MATE_KEYS` before restarting `axon-relay`:

```
AXON_RELAY_MATE_KEYS=mate-id-1=<base64url-public-key>,mate-id-2=<base64url-public-key>
```

Each mate already prints its base64url-encoded public signing key as part of
its identity (`security.PublicKeyString`); there is nothing to generate —
only to copy from each mate into the relay's configuration. A relay started
without `AXON_RELAY_MATE_KEYS` (or with it empty) now refuses to start.
Mates no longer take a `--relay-token` flag or read `AXON_RELAY_TOKEN` at
all; that configuration can be removed from mate deployments.

## Production hardening remaining

- Add deployment manifests, relay rate limits, metrics, and operational alerts.
- Complete native-client hardware-backed presence assertions if biometric
  confirmation is required.

## Quality baseline

The continuous-integration gate runs race-enabled Go tests, enforces at least
90% aggregate coverage over `internal/` and `pkg/`, builds both binaries, runs
Go vulnerability analysis, builds and tests the PWA, and rejects high-severity
npm audit findings.
