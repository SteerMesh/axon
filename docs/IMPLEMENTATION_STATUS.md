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

## Production hardening remaining

- Persist paired Mate connection metadata in the PWA and add a session picker.
- Implement Web Push subscription delivery from the host or notification
  service.
- Replace the relay bootstrap token with scoped, expiring route credentials.
- Add deployment manifests, relay rate limits, metrics, and operational alerts.
- Complete native-client hardware-backed presence assertions if biometric
  confirmation is required.

## Quality baseline

The continuous-integration gate runs race-enabled Go tests, enforces at least
90% aggregate coverage over `internal/` and `pkg/`, builds both binaries, runs
Go vulnerability analysis, builds and tests the PWA, and rejects high-severity
npm audit findings.
