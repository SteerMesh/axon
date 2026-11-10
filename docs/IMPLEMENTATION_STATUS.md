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
- Prometheus metrics (`internal/relay/metrics.go`) for `axon-relay`, served
  loopback-only by default on a separate port (`AXON_RELAY_METRICS_ADDR`,
  default `127.0.0.1:9090`) from the main connect port.
- Per-source-IP rate limiting (`internal/relay/ratelimit.go`) on
  `/v1/connect` and the push-subscribe REST calls, keyed on `r.RemoteAddr`.
- Docker and systemd deployment artifacts for `axon-relay`
  (`deploy/axon-relay/`): a distroless multi-stage Dockerfile,
  `docker-compose.yml`, and an `axon-relay.service` unit.
- Repeatable release automation (`.goreleaser.yaml`,
  `.github/workflows/release.yml`): pushing a `v*` tag builds `mesh-axon`
  for darwin/linux (amd64 and arm64) and `axon-relay` for darwin/linux/windows
  (amd64 and arm64, minus windows/arm64), then publishes them as GitHub
  release assets, each binary paired with its own `<asset>.sha256` sidecar
  file -- the exact contract `axonInstallFromGitHub` in
  `github.com/SteerMesh/mesh`'s `internal/ops/axon_install.go` expects when
  it falls back to downloading `mesh-axon` from this repo's releases.
  `mesh-axon` is not built for windows: `internal/target`'s PTY adapters
  (`command_unix.go`, `shell.go`) are unix-only (`//go:build unix`), so
  `cmd/mesh-axon` does not currently compile for `GOOS=windows` --
  unrelated to release tooling, and not addressed here. **No release has
  been tagged yet**: this only lands the automation itself. Cutting the
  first `v*` tag is a separate, explicit next step (see
  `docs/GETTING_STARTED.md`'s note on the `mesh mates install axon`
  fallback having nothing to find until that happens).

## Required upgrade action

Upgrading to this release is a **breaking change** for any deployed relay:
`AXON_RELAY_TOKEN` is gone. The relay now authenticates connections against
each mate's Ed25519 **public** signing key instead of a shared secret it
used to be handed directly, so an operator must provision
`AXON_RELAY_MATE_KEYS` before restarting `axon-relay`:

```
AXON_RELAY_MATE_KEYS=mate-id-1=<base64url-public-key>,mate-id-2=<base64url-public-key>
```

Run `mesh-axon identity` on each mate to get the `mate_id=base64url-pubkey`
value to add to the relay's `AXON_RELAY_MATE_KEYS`; it reads (or lazily
creates) that mate's identity file directly and prints its `mate_id`,
public signing key, and a ready-to-paste `AXON_RELAY_MATE_KEYS` fragment --
no running `serve` daemon required, and it never prints either private
key. A relay started without `AXON_RELAY_MATE_KEYS` (or with it empty) now
refuses to start. Mates no longer take a `--relay-token` flag or read
`AXON_RELAY_TOKEN` at all; that configuration can be removed from mate
deployments.

## Production hardening remaining

- Define operational alerts; deferred until the metrics above have
  captured real production traffic to set sane thresholds against.
- Complete native-client hardware-backed presence assertions if biometric
  confirmation is required.

## Quality baseline

The continuous-integration gate runs race-enabled Go tests, enforces at least
90% aggregate coverage over `internal/` and `pkg/`, builds both binaries, runs
Go vulnerability analysis, builds and tests the PWA, and rejects high-severity
npm audit findings.
