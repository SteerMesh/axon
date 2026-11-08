# Getting started

This is the end-to-end operational flow for Axon: build the binaries, stand
up a relay, start a mate, pair a device, and keep it connected. For *why*
Axon is shaped this way (trust boundaries, Relay Access Tokens, delivery
semantics), see `docs/ARCHITECTURE.md`. For the wire format, see
`docs/PROTOCOL.md`. For what's implemented versus still hardening, see
`docs/IMPLEMENTATION_STATUS.md`.

## Prerequisites

- A Go toolchain matching `go.mod`.
- Node.js and npm, for building the PWA (`web/`).
- `make`.

Godot is not involved in Axon at all — if you've seen it mentioned
elsewhere, that's an unrelated project.

Build both binaries:

```bash
make build
```

This produces `bin/mesh-axon` (the host-side agent and CLI) and
`bin/axon-relay` (the relay server).

## Step 1 — get your mate's identity

Before anything else, a mate (the machine that will own your terminal
sessions) needs a stable identity. Run:

```bash
./bin/mesh-axon identity
```

This loads (or lazily creates, on first run) an identity file under
`~/.mesh/axon/identity.json` and prints:

```text
Mate ID:    <mate-id>
Public key: <base64url-ed25519-public-key>

AXON_RELAY_MATE_KEYS fragment: <mate-id>=<base64url-ed25519-public-key>
```

It never prints a private key. The last line is the exact fragment the
relay operator needs — see Step 2. `identity` does not require a running
`serve` daemon.

If you're using the `mesh` wrapper (see "Alternative entry point" below)
instead of the standalone binary, the equivalent command is:

```bash
mesh axon identity
```

## Step 2 — start the relay

The relay (`bin/axon-relay`) routes opaque, end-to-end encrypted frames
between mates and devices. It never sees plaintext session content — see
`docs/ARCHITECTURE.md`'s "Trust boundaries" section.

Required environment variable:

- `AXON_RELAY_MATE_KEYS` — comma-separated `mate_id=base64url-public-key`
  pairs, one per mate allowed to connect. Use the fragment `identity`
  printed in Step 1. The relay stores no credentials of its own; this is
  the only way it learns which mates it may authenticate.

**The relay refuses to start without it.** If `AXON_RELAY_MATE_KEYS` is
unset or empty, `axon-relay` prints an error and exits immediately — it
will not come up in an unauthenticated state.

Optional environment variables:

- `AXON_RELAY_ADDR` — listen address (default `:8080`).
- `AXON_RELAY_ORIGINS` — comma-separated allowed WebSocket origins.
- `AXON_RELAY_VAPID_PUBLIC_KEY` / `AXON_RELAY_VAPID_PRIVATE_KEY` — enables
  Web Push wake notifications when both are set together (see Step 7).
- `AXON_RELAY_DB_PATH` — path to the push-subscription database (default
  `axon-relay.db`); only opened when the VAPID keys above are set.

Example:

```bash
export AXON_RELAY_MATE_KEYS="laptop=AbCdEf...=="
./bin/axon-relay
```

## Step 3 — start the mate

On the machine that will own your terminal sessions:

```bash
./bin/mesh-axon serve --relay-url wss://relay.example.com
```

`--relay-url` also reads from the `AXON_RELAY_URL` environment variable if
the flag is omitted. `serve` starts the local IPC socket (used by `run`,
`sessions`, `attach`, etc.) immediately, regardless of whether a relay URL
is configured; the relay connection is established separately once a
`--relay-url` is available.

Local agent state lives under `--data-dir` (default `~/.mesh/axon`):
identity, the local session store (`axon.db`), and an optional
`templates.yaml` for custom session templates.

Other `serve` flags:

- `--mate-id` — override the stable host identity (derived from the
  signing key by default).
- `--ssh-host` / `--docker-container` — allowlist specific SSH hosts or
  Docker containers as session targets (repeatable).

With the `mesh` wrapper:

```bash
mesh axon serve --relay-url wss://relay.example.com
```

## Step 4 — pair a device via the PWA

On the mate, issue a one-time pairing code:

```bash
./bin/mesh-axon pair
```

This prints a QR code and the same payload as text, valid for `--ttl`
(default 5 minutes, validated to 1s–1h — values outside this range are
rejected with an error rather than silently clamped). Open the Axon PWA on
your device and scan the QR code (or paste the payload text into the
pairing form).

**What's different from earlier Axon setups:** the pairing bundle now
carries a pairing-scope Relay Access Token automatically. There is no
separate relay ticket to hand-type into the PWA anymore — that manual step
was removed once relay credentials became scoped tokens minted from the
mate's own identity key (see `docs/ARCHITECTURE.md`'s "Relay credentials"
section). The QR code alone is sufficient to both authenticate the
device's first relay connection and complete the pairing handshake.

## Step 5 — reconnect without re-pairing

Reload the PWA. If it has previously paired with one or more mates, it
shows a device picker — a list of saved mates with their last-connected
time — instead of jumping straight to the QR scanner.

Selecting a saved mate reconnects using a device-scope Relay Access Token
persisted from the original pairing (or a later refresh), not a new QR
scan. This token is valid for 24 hours and the PWA proactively re-mints it
over the live encrypted connection before it expires, so routine reloads
never need a fresh QR code.

Re-pairing is only required if:

- The stored token has fully expired with no opportunity to refresh it
  (e.g. the device was offline past the 24h window) — the PWA detects this
  up front and prompts re-pairing rather than attempting a connection that
  would be rejected.
- The mate's signing key no longer matches what was recorded at pairing
  time (for example, the mate's identity was rotated or the device was
  revoked) — the Noise handshake fails and the PWA prompts re-pairing.

## Step 6 — revoke a device

```bash
./bin/mesh-axon devices list
./bin/mesh-axon devices revoke <device-id>
```

Revocation is immediate: it drops that device's live Noise channel and
cancels any active session subscription on the mate, in addition to
marking the device record revoked in the local store. A revoked device
cannot complete a new handshake either — the next packet it sends after
revocation is rejected and the PWA surfaces a "device revoked" error rather
than hanging.

## Step 7 — optional: Web Push

Without Web Push, a device that isn't actively connected simply won't
receive new output until it reconnects. With it enabled, the relay sends a
wake notification when it has no connected device for a frame it needs to
deliver.

To enable it:

1. Generate a VAPID keypair. Axon doesn't ship a key-generation
   subcommand; use any standard VAPID tool, for example the `web-push` npm
   package:

   ```bash
   npx web-push generate-vapid-keys
   ```

2. Set both keys on the relay:

   ```bash
   export AXON_RELAY_VAPID_PUBLIC_KEY="..."
   export AXON_RELAY_VAPID_PRIVATE_KEY="..."
   ```

   Both must be set together — if only one is present, the relay logs a
   warning and runs with push disabled rather than refusing to start.

3. The PWA handles the rest automatically: it fetches the relay's current
   public key (`GET /v1/vapid-key`), requests browser notification
   permission, and registers the subscription. There's nothing to
   configure on the device side.

The notification itself is deliberately generic — something like "a
session needs attention" — and carries no session content, device
identity, or any other detail. This preserves the relay's content-blind
invariant: it can tell a device to come back online without learning or
leaking anything about what it's coming back online *for*.

## Alternative entry point: `mesh axon`

Every `mesh-axon` subcommand above is also available as `mesh axon
<subcommand>` if you're running it through the `mesh` CLI instead of the
standalone binary. `mesh axon` is a thin passthrough: it resolves the
`mesh-axon` binary and execs it with the same arguments, so everything in
this document applies identically either way — just substitute `mesh axon`
for `./bin/mesh-axon`.

Binary resolution order for the passthrough:

1. `$AXON_BIN`, if set and the file exists.
2. `mesh-axon` on `$PATH`.
3. `~/.mesh/bin/mesh-axon`.
4. `~/.local/bin/mesh-axon`.

**Current limitation:** `mesh mates install axon` exists as a command, but
don't expect it to work yet. It tries a signed-manifest host first, then
falls back to downloading a GitHub release of this repo via the `gh` CLI —
and as of this writing, `SteerMesh/axon` has no tagged release at all, so
that fallback has nothing to find. Whether the manifest host has a build
available is outside what this repo can confirm. Until a release is
tagged, install `mesh-axon` by one of:

- Building it yourself (`make build`) and setting `AXON_BIN` to the
  resulting `bin/mesh-axon` path, or
- Copying that built binary into `~/.mesh/bin/`.

## Troubleshooting

**Relay refuses to start.**
Check for `AXON_RELAY_MATE_KEYS is required (comma-separated
mate_id=base64url-ed25519-public-key pairs)` on stderr. Run
`mesh-axon identity` on the mate and add the printed fragment to the
relay's environment.

**Mate can't connect to the relay / authentication fails.**
The relay verifies every connection against the public key provisioned in
`AXON_RELAY_MATE_KEYS`, keyed by `mate_id`. The default `mate_id` is derived
from the signing key itself (`"axon-" + base64(sha256(public-key)[:12])`),
so if a mate's identity was regenerated (e.g. its `identity.json` was
deleted) without pinning `--mate-id`, the mate now presents a *different*
`mate_id` as well as a different key — the relay won't see a known mate
with a mismatched key, it will see an unrecognized `mate_id` it has never
heard of. The same applies if the fragment was copied incorrectly. Either
way, re-run `mesh-axon identity` and update the relay's
`AXON_RELAY_MATE_KEYS` to re-provision it.

**Reconnect fails with an expired-token error.**
This is expected once a device's stored relay token has passed its 24h
expiry without being refreshed (for example, after a long time offline).
The PWA will prompt you to re-pair — run `mesh-axon pair` on the mate and
scan the new QR code.

**`mesh axon` reports "binary not found."**
The passthrough couldn't locate `mesh-axon` anywhere in its resolution
order. Either set `AXON_BIN` to point at a built binary, or place the
binary at `~/.mesh/bin/mesh-axon`. `mesh mates install axon` is not a
reliable fix today — see the limitation noted above.
