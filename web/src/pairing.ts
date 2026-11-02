import { NoiseIKInitiator } from './crypto/noiseIK';
import { loadOrCreateIdentity } from './identityStore';
import { type PairedMate, saveMate, touchLastConnected, updateRelayToken } from './mateStore';
import { base64, base64URL, fromBase64, mateRejection, RelayTransport, SecureTransport } from './relay';
import { withTimeout } from './timeout';
import type { AxonClient } from './client';

/** How long pairing and the Noise handshake may each wait for a relay reply. */
const PAIRING_STEP_TIMEOUT_MS = 15_000;

interface PairingBundle {
  mate_id: string;
  mate_signing_key: string;
  mate_noise_key: string;
  relay_url: string;
  one_time_token: string;
  /**
   * A pairing-scope Relay Access Token (see internal/security/relaytoken.go
   * on the mate). This replaces the old out-of-band relay ticket an
   * operator used to hand-type into the pairing form: the QR bundle now
   * carries everything this device needs to open its first relay
   * connection. It is wildcarded to any device_id, since the real
   * device_id isn't known until the device presents itself below.
   */
  relay_token: string;
  expires_at: string;
}

interface DeviceRecord {
  mate_id: string;
  device_id: string;
  device_signing_key: string;
  device_noise_key: string;
  paired_at: string;
  mate_signature: string;
}

/** The mate's reply to a completed pairing exchange (security.PairingResult). */
interface PairingReply {
  record: DeviceRecord;
  relay_token: string;
  relay_token_expires_at: number;
}

export interface PairedConnection {
  deviceId: string;
  mateId: string;
  relayUrl: string;
  /**
   * The device-scope Relay Access Token this connection authenticated
   * with. Callers that need to authorize a REST call against the same
   * relay (e.g. push.ts's subscribe/unsubscribe) reuse this instead of
   * asking for a separately typed ticket.
   */
  relayToken: string;
  transport: SecureTransport;
}

export async function pairAndConnect(encodedBundle: string): Promise<PairedConnection> {
  const bundle = decodeBundle(encodedBundle);
  if (Date.parse(bundle.expires_at) <= Date.now()) throw new Error('pairing code has expired');
  const identity = await loadOrCreateIdentity();
  const deviceId = await deviceIdentifier(identity.signingPublicKey);
  const presentationWithoutSignature = {
    device_id: deviceId,
    device_signing_key: base64(identity.signingPublicKey),
    device_noise_key: base64(identity.noisePublicKey),
  };
  const signedMessage = JSON.stringify({
    domain: 'mesh-axon-pairing-v1',
    token: bundle.one_time_token,
    mate_id: bundle.mate_id,
    ...presentationWithoutSignature,
  });
  const signature = new Uint8Array(await crypto.subtle.sign(
    'Ed25519',
    identity.signingKeyPair.privateKey,
    owned(new TextEncoder().encode(signedMessage)),
  ));

  const relay = new RelayTransport(bundle.relay_url, bundle.mate_id, deviceId, bundle.relay_token);
  await relay.opened();
  try {
    const pairingRequest = new TextEncoder().encode(JSON.stringify({
      token: bundle.one_time_token,
      presentation: { ...presentationWithoutSignature, signature: base64(signature) },
    }));
    relay.send(packet(0, pairingRequest));
    const pairingReply = await withTimeout(relay.receive(), PAIRING_STEP_TIMEOUT_MS, 'pairing timed out waiting for the mate');
    if (pairingReply[0] === 5) throw mateRejection(pairingReply.slice(1));
    if (pairingReply[0] !== 4) throw new Error('Mate rejected pairing');
    const reply = JSON.parse(new TextDecoder().decode(pairingReply.slice(1))) as PairingReply;
    await verifyRecord(reply.record, bundle);

    const prologue = new TextEncoder().encode(`mesh-axon-v1:${bundle.mate_id}:${deviceId}`);
    const initiator = new NoiseIKInitiator(identity.noiseKeyPair, fromBase64(bundle.mate_noise_key), prologue);
    relay.send(packet(1, await initiator.start(new TextEncoder().encode(deviceId))));
    const handshakeReply = await withTimeout(relay.receive(), PAIRING_STEP_TIMEOUT_MS, 'handshake timed out waiting for the mate');
    if (handshakeReply[0] === 5) throw mateRejection(handshakeReply.slice(1));
    if (handshakeReply[0] !== 2) throw new Error('Mate rejected the encrypted channel');
    const { channel } = await initiator.finish(handshakeReply.slice(1));
    try {
      // Remember this mate (and the device-scope relay token it just
      // minted) so the device can reconnect later without re-scanning the
      // QR code. Losing this is a worse UX, not a failed pairing — don't
      // let a storage problem undo a connection that otherwise succeeded.
      await saveMate({
        mateId: bundle.mate_id,
        noisePublicKey: fromBase64(bundle.mate_noise_key),
        signingPublicKey: fromBase64(bundle.mate_signing_key),
        relayUrl: bundle.relay_url,
        lastConnectedAt: Date.now(),
        relayToken: reply.relay_token,
        relayTokenExpiresAt: reply.relay_token_expires_at * 1000,
      });
    } catch {
      // ignored — see comment above
    }
    return {
      deviceId, mateId: bundle.mate_id, relayUrl: bundle.relay_url,
      relayToken: reply.relay_token, transport: new SecureTransport(relay, channel),
    };
  } catch (error) {
    // A failed or timed-out pairing attempt must not leave a stale device
    // socket registered on the relay — that blocks every retry until the
    // old tab is closed (see the Axon handoff notes on this exact pain
    // point).
    relay.close();
    throw error;
  }
}

/**
 * Thrown by {@link reconnectToMate} when the stored device-scope relay
 * token has already expired. Distinct from a network/crypto failure (see
 * {@link MateKeyMismatchError}) so the UI can specifically prompt
 * re-pairing instead of showing a raw connection error -- there is no way
 * to renew an expired token without a live connection to renew it over
 * (see refreshRelayToken), so once expired the only path back is
 * re-pairing.
 */
export class RelayTokenExpiredError extends Error {
  readonly mateId: string;

  constructor(mateId: string) {
    super(`"${mateId}"'s relay access has expired — re-pair this device to continue.`);
    this.name = 'RelayTokenExpiredError';
    this.mateId = mateId;
  }
}

/**
 * Thrown by {@link reconnectToMate} when the mate's live handshake doesn't
 * authenticate against the Noise key recorded at pairing time — most
 * plausibly because the mate rotated or revoked its key since. Distinct
 * from a network/offline failure so the UI can specifically prompt
 * re-pairing instead of showing a raw crypto error.
 */
export class MateKeyMismatchError extends Error {
  readonly mateId: string;

  constructor(mateId: string) {
    super(`"${mateId}" did not authenticate with its previously known key — re-pair this device to continue.`);
    this.name = 'MateKeyMismatchError';
    this.mateId = mateId;
  }
}

/**
 * Reconnects to a previously paired mate using its stored keys, relay URL,
 * and device-scope relay token — skipping the QR scan and signed
 * DeviceRecord exchange that {@link pairAndConnect} performs, since the
 * device and mate already trust each other's long-term keys. Only a
 * fresh Noise IK handshake is needed.
 *
 * Throws {@link RelayTokenExpiredError} up front if the stored token has
 * already expired, rather than attempting (and failing) to open the relay
 * connection with a token the relay will reject.
 */
export async function reconnectToMate(mate: PairedMate): Promise<PairedConnection> {
  if (mate.relayTokenExpiresAt <= Date.now()) throw new RelayTokenExpiredError(mate.mateId);
  const identity = await loadOrCreateIdentity();
  const deviceId = await deviceIdentifier(identity.signingPublicKey);

  const relay = new RelayTransport(mate.relayUrl, mate.mateId, deviceId, mate.relayToken);
  await relay.opened();
  try {
    const prologue = new TextEncoder().encode(`mesh-axon-v1:${mate.mateId}:${deviceId}`);
    const initiator = new NoiseIKInitiator(identity.noiseKeyPair, mate.noisePublicKey, prologue);
    relay.send(packet(1, await initiator.start(new TextEncoder().encode(deviceId))));
    const handshakeReply = await withTimeout(relay.receive(), PAIRING_STEP_TIMEOUT_MS, 'handshake timed out waiting for the mate');
    if (handshakeReply[0] === 5) throw mateRejection(handshakeReply.slice(1));
    if (handshakeReply[0] !== 2) throw new Error('Mate rejected the encrypted channel');

    let channel;
    try {
      ({ channel } = await initiator.finish(handshakeReply.slice(1)));
    } catch {
      // Noise IK mixes the responder's static key (mate.noisePublicKey) into
      // the handshake before any data is exchanged, so a mate that no
      // longer holds the matching private key fails authentication here —
      // it does not "succeed" with some other key. That failure is
      // indistinguishable, at this layer, from key rotation/revocation.
      throw new MateKeyMismatchError(mate.mateId);
    }

    try {
      // Same reasoning as the saveMate call in pairAndConnect: a Noise
      // handshake that just succeeded must not be torn down because a
      // bookkeeping write (last-connected timestamp) failed afterwards.
      await touchLastConnected(mate.mateId);
    } catch {
      // ignored — see comment above
    }
    return {
      deviceId, mateId: mate.mateId, relayUrl: mate.relayUrl,
      relayToken: mate.relayToken, transport: new SecureTransport(relay, channel),
    };
  } catch (error) {
    relay.close();
    throw error;
  }
}

/**
 * Re-mints the device-scope relay token over an already-open, paired
 * connection — mirroring what the mate's PairingManager.Complete does at
 * pairing time (see dispatcher.go's "relay.token.refresh" case) — and
 * persists the result so a later reload can still reconnect without
 * re-pairing. Call this proactively (see main.ts) before the current
 * token's expiry, not after: once a token has actually expired there is
 * no live connection left to refresh it over.
 */
export async function refreshRelayToken(client: Pick<AxonClient, 'request'>, mateId: string): Promise<void> {
  const response = await client.request<{ relay_token: string; relay_token_expires_at: number }>('relay.token.refresh');
  if (!response.data) throw new Error('relay token refresh returned no data');
  await updateRelayToken(mateId, response.data.relay_token, response.data.relay_token_expires_at * 1000);
}

function decodeBundle(encoded: string): PairingBundle {
  const standard = encoded.replaceAll('-', '+').replaceAll('_', '/');
  const padding = '='.repeat((4 - standard.length % 4) % 4);
  return JSON.parse(atob(standard + padding)) as PairingBundle;
}

async function deviceIdentifier(signingPublicKey: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', owned(signingPublicKey)));
  return `device-${base64URL(digest.slice(0, 12))}`;
}

/**
 * The device ID for this browser's local identity -- the same value
 * {@link pairAndConnect} and {@link reconnectToMate} use, derived purely
 * from the stored Ed25519 identity (so it's identical across every paired
 * mate). Exposed for call sites that need it without an active
 * {@link PairedConnection}, e.g. unsubscribing push notifications for a
 * mate that's being forgotten.
 */
export async function currentDeviceId(): Promise<string> {
  const identity = await loadOrCreateIdentity();
  return deviceIdentifier(identity.signingPublicKey);
}

async function verifyRecord(record: DeviceRecord, bundle: PairingBundle): Promise<void> {
  const binding = JSON.stringify({
    domain: 'mesh-axon-pairing-v1',
    mate_id: record.mate_id,
    device_id: record.device_id,
    device_signing_key: record.device_signing_key,
    device_noise_key: record.device_noise_key,
    paired_at: record.paired_at,
  });
  const key = await crypto.subtle.importKey('raw', owned(fromBase64(bundle.mate_signing_key)), 'Ed25519', false, ['verify']);
  const valid = await crypto.subtle.verify(
    'Ed25519', key, owned(fromBase64(record.mate_signature)), owned(new TextEncoder().encode(binding)),
  );
  if (!valid || record.mate_id !== bundle.mate_id) throw new Error('Mate pairing signature is invalid');
}

function packet(kind: number, payload: Uint8Array): Uint8Array {
  const result = new Uint8Array(payload.length + 1);
  result[0] = kind;
  result.set(payload, 1);
  return result;
}

function owned(value: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(value.length);
  result.set(value);
  return result;
}
