# Architecture

## Product boundary

Mesh Axon is one product with three runtime components:

- **Axon Agent** owns PTY sessions on a host.
- **Axon Relay** routes opaque encrypted frames between authenticated peers.
- **Axon client** runs as a PWA initially and as a native client later.

Mesh Core may expose `mesh axon` convenience commands, but Axon owns its
protocol, processes, storage, and release lifecycle.

## Invariants

1. Domain packages do not import adapters, transports, or storage.
1. Remote input reaches a PTY only through an authorized, size-limited,
   idempotent command.
1. Terminal bytes remain ordered and are never silently discarded.
1. The relay never receives session plaintext or session traffic keys.
1. A revoked device cannot establish a new encrypted channel.

## Repository layout

```text
cmd/               Executable entry points
internal/domain/   Sessions, permissions, and state
internal/session/  PTY lifecycle and replay
internal/target/   Target adapters
internal/ipc/      Local request/response and event streaming
internal/relay/    Content-blind routing
internal/security/ Pairing and Noise channels
internal/store/    SQLite metadata and audit records
pkg/protocol/      Public, versioned wire contracts
web/               PWA client
```

## Delivery semantics

Output is ordered by `(session_id, stream_epoch, sequence)`. A bounded replay
buffer advertises its minimum and maximum retained sequence. Requests older
than the minimum receive `replay_gap`; Axon never promises unbounded lossless
history.

Input commands carry a device-scoped idempotency key. The Agent records recent
keys and returns the original acknowledgement for a retry instead of writing
the input twice.

## Trust boundaries

- TLS protects connections to the relay from passive network observers.
- Noise IK protects session frames from the relay.
- Devices use distinct Ed25519 signing and X25519 Noise static keys. Pairing
  binds both public keys into a signed device record.
- PWA confirmation is a user-experience safeguard, not proof of biometric
  presence. Hardware-backed user-presence assertions are reserved for native
  clients.
- Local IPC is restricted to the owning OS user.
