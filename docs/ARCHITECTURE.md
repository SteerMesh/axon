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

The relay is content-blind, not state-blind: it never sees plaintext or
traffic keys, but it does hold routing state (which mate and device peers
are currently connected) and, as of Web Push support, notification metadata
(which device endpoints are subscribed to be woken). Both are addressing
information the relay needs to do its job, not session content. The
`push_subscriptions` table is an instance of this: it stores where to send a
wake notification, never why one was sent.

## Repository layout

```text
cmd/               Executable entry points
internal/domain/   Sessions, permissions, and state
internal/session/  PTY lifecycle and replay
internal/target/   Target adapters
internal/ipc/      Local request/response and event streaming
internal/relay/    Content-blind routing and wake notifications
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

## Relay credentials: Relay Access Tokens (RATs)

The relay authorizes every WebSocket connection (and the push-subscribe REST
calls below) with a Relay Access Token instead of a single static shared
secret. A RAT is `base64url(json(claims)) + "." + base64url(signature)`,
where `signature` is an Ed25519 signature over the claims JSON by the
connecting mate's own identity signing key — the same key
`internal/security/pairing.go` already uses to sign `DeviceRecord`s. Claims
are `{mate_id, scope, device_id, iat, exp}`; `scope` is `"mate"`,
`"pairing"`, or `"device"`, and `device_id` is empty to mean "any device"
(used only for `"pairing"`-scope tokens, minted before the device's real ID
is known).

**The relay stores no credentials.** It is provisioned with each mate's
*public* signing key (`AXON_RELAY_MATE_KEYS`, see
`cmd/axon-relay/main.go`) and verifies a RAT purely by checking the
signature against that key and validating the claims — `mate_id` matches the
connection's claimed identity, `scope` is one the connection's role permits
(mate connections require `"mate"`; device connections accept `"pairing"` or
`"device"`; the push-subscribe REST endpoints require `"device"`, since by
the time a device calls them it already holds a real device-scope token),
`device_id` is the wildcard or matches exactly, and the token has not
expired (`internal/relay/hub.go`'s `authorizedConnect`/`authorizedDevice`,
`internal/security/relaytoken.go`'s `VerifyRelayToken`). This preserves the
relay's content-blind invariant: verifying a RAT never requires decoding or
trusting anything about the frame payload it protects, exactly as today the
relay forwards `RouteFrame.Payload` opaquely without ever decrypting it.

Three issuance paths, by scope:

- **Mate** — the mate mints its own fresh, short-lived (5m) token right
  before every dial attempt (`internal/remote/connector.go`). No caching or
  renewal is needed: the mate always holds its own private key locally, and
  minting costs nothing.
- **Pairing** — `PairingManager.Issue()` mints a wildcard-device, pairing-
  scope token alongside the existing one-time pairing token, carried in the
  `PairingBundle` (and therefore the QR code) as `RelayToken`. This lets an
  unpaired device open its first relay connection without any out-of-band
  relay secret.
- **Device** — `PairingManager.Complete()` mints a device-scope token (24h
  TTL) the instant the device's real ID is known, returned to the mate's
  `Endpoint` as part of `PairingResult` and relayed to the device inside the
  already Noise-encrypted pairing-reply payload — a channel the relay never
  decodes, so this adds no new exposure. A connected device can renew its
  token before it expires with an in-channel `relay.token.refresh` request
  (handled in `internal/remote/dispatcher.go`, called proactively by the PWA
  — see `web/src/pairing.ts`'s `refreshRelayToken` and `main.ts`'s refresh
  scheduling), avoiding a hard cutoff at 24h for long-lived sessions.

Because there is no relay-side token store, there is no way to revoke a RAT
directly — expiry is the only backstop on the relay side, which is why
`devices.revoke` now also drops the device's live Noise channel immediately
at the mate (`internal/remote/endpoint.go`'s `Revoke`, wired from
`internal/ipc/server.go`): revocation takes effect at the mate right away,
independent of when the device's relay token happens to expire.

The PWA persists its device-scope token (and its expiry) in IndexedDB
alongside the rest of its `PairedMate` record (`web/src/mateStore.ts`) so
that reload-and-reconnect (no QR re-scan) keeps working. This is a
deliberate, bounded tradeoff: the token alone grants only relay *routing*
access for at most 24h — it cannot complete a Noise handshake or read
session content, since the device's Noise and signing private keys remain
non-extractable, exactly as before this change.
