import { NoiseIKInitiator } from './crypto/noiseIK';
import { loadOrCreateIdentity } from './identityStore';
import { base64, base64URL, fromBase64, mateRejection, RelayTransport, SecureTransport } from './relay';
import { withTimeout } from './timeout';

/** How long pairing and the Noise handshake may each wait for a relay reply. */
const PAIRING_STEP_TIMEOUT_MS = 15_000;

interface PairingBundle {
  mate_id: string;
  mate_signing_key: string;
  mate_noise_key: string;
  relay_url: string;
  one_time_token: string;
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

export interface PairedConnection {
  deviceId: string;
  mateId: string;
  transport: SecureTransport;
}

export async function pairAndConnect(encodedBundle: string, relayTicket: string): Promise<PairedConnection> {
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

  const relay = new RelayTransport(bundle.relay_url, bundle.mate_id, deviceId, relayTicket);
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
    const record = JSON.parse(new TextDecoder().decode(pairingReply.slice(1))) as DeviceRecord;
    await verifyRecord(record, bundle);

    const prologue = new TextEncoder().encode(`mesh-axon-v1:${bundle.mate_id}:${deviceId}`);
    const initiator = new NoiseIKInitiator(identity.noiseKeyPair, fromBase64(bundle.mate_noise_key), prologue);
    relay.send(packet(1, await initiator.start(new TextEncoder().encode(deviceId))));
    const handshakeReply = await withTimeout(relay.receive(), PAIRING_STEP_TIMEOUT_MS, 'handshake timed out waiting for the mate');
    if (handshakeReply[0] === 5) throw mateRejection(handshakeReply.slice(1));
    if (handshakeReply[0] !== 2) throw new Error('Mate rejected the encrypted channel');
    const { channel } = await initiator.finish(handshakeReply.slice(1));
    return { deviceId, mateId: bundle.mate_id, transport: new SecureTransport(relay, channel) };
  } catch (error) {
    // A failed or timed-out pairing attempt must not leave a stale device
    // socket registered on the relay — that blocks every retry until the
    // old tab is closed (see the Axon handoff notes on this exact pain
    // point).
    relay.close();
    throw error;
  }
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
