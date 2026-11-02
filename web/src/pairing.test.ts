import 'fake-indexeddb/auto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { NoiseChannel } from './crypto/noiseIK';

const { FakeRelayTransport, noiseHandshake } = vi.hoisted(() => {
  class FakeRelayTransport {
    static instances: FakeRelayTransport[] = [];
    readonly relayUrl: string;
    readonly mateId: string;
    readonly deviceId: string;
    readonly ticket: string;
    readonly sent: Uint8Array[] = [];
    closed = false;
    #queue: Uint8Array[] = [];
    #pending: Array<(value: Uint8Array) => void> = [];

    constructor(relayUrl: string, mateId: string, deviceId: string, ticket: string) {
      this.relayUrl = relayUrl;
      this.mateId = mateId;
      this.deviceId = deviceId;
      this.ticket = ticket;
      FakeRelayTransport.instances.push(this);
    }

    opened(): Promise<void> {
      return Promise.resolve();
    }

    send(payload: Uint8Array): void {
      this.sent.push(payload);
    }

    receive(): Promise<Uint8Array> {
      const queued = this.#queue.shift();
      if (queued) return Promise.resolve(queued);
      return new Promise((resolve) => this.#pending.push(resolve));
    }

    queueReply(payload: Uint8Array): void {
      const waiting = this.#pending.shift();
      if (waiting) waiting(payload);
      else this.#queue.push(payload);
    }

    close(): void {
      this.closed = true;
    }
  }

  // Controls what the mocked Noise handshake does for the *next* finish()
  // call, so each test can choose success or a key-mismatch-shaped failure
  // without re-implementing Noise IK's math.
  const noiseHandshake: { finish: () => Promise<{ payload: Uint8Array; channel: NoiseChannel }> } = {
    finish: async () => ({ payload: new Uint8Array(), channel: { encrypt: (p) => p, decrypt: (c) => c } }),
  };

  return { FakeRelayTransport, noiseHandshake };
});

vi.mock('./relay', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./relay')>();
  return { ...actual, RelayTransport: FakeRelayTransport };
});

vi.mock('./crypto/noiseIK', async (importOriginal) => {
  const actual = await importOriginal<typeof import('./crypto/noiseIK')>();
  return {
    ...actual,
    NoiseIKInitiator: class {
      async start(): Promise<Uint8Array> {
        return new Uint8Array([0]);
      }

      finish(message: Uint8Array): Promise<{ payload: Uint8Array; channel: NoiseChannel }> {
        void message;
        return noiseHandshake.finish();
      }
    },
  };
});

vi.mock('./mateStore', () => ({
  saveMate: vi.fn(async () => undefined),
  touchLastConnected: vi.fn(async () => undefined),
  updateRelayToken: vi.fn(async () => undefined),
}));

// Imported after the mocks above so pairing.ts picks up the mocked modules.
const {
  MateKeyMismatchError, RelayTokenExpiredError, pairAndConnect, reconnectToMate, refreshRelayToken,
} = await import('./pairing');
const { saveMate, touchLastConnected, updateRelayToken } = await import('./mateStore');
const { loadOrCreateIdentity } = await import('./identityStore');

function toBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

function encodeBundle(bundle: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(bundle)).toString('base64')
    .replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

function packet(kind: number, payload: Uint8Array): Uint8Array {
  const result = new Uint8Array(payload.length + 1);
  result[0] = kind;
  result.set(payload, 1);
  return result;
}

function samplePairedMate(overrides: Partial<Parameters<typeof reconnectToMate>[0]> = {}) {
  return {
    mateId: 'mate-1',
    noisePublicKey: new Uint8Array(32).fill(3),
    signingPublicKey: new Uint8Array(32).fill(4),
    relayUrl: 'wss://relay.example/v1',
    lastConnectedAt: 1_700_000_000_000,
    relayToken: 'device-relay-token',
    relayTokenExpiresAt: Date.now() + 60_000,
    ...overrides,
  };
}

beforeEach(() => {
  FakeRelayTransport.instances.length = 0;
  noiseHandshake.finish = async () => ({ payload: new Uint8Array(), channel: { encrypt: (p) => p, decrypt: (c) => c } });
  vi.clearAllMocks();
});

describe('pairAndConnect', () => {
  it('reads the relay token from the bundle, and persists the device-scope token from the reply', async () => {
    const mateSigningKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const mateSigningPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', mateSigningKeyPair.publicKey));
    const bundle = {
      mate_id: 'mate-1',
      mate_signing_key: toBase64(mateSigningPublicKey),
      mate_noise_key: toBase64(new Uint8Array(32).fill(5)),
      relay_url: 'wss://relay.example/v1',
      one_time_token: 'one-time-token',
      relay_token: 'pairing-relay-token',
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    };

    const identity = await loadOrCreateIdentity();
    const pairingDone = pairAndConnect(encodeBundle(bundle));
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    // The relay transport must open with the bundle's relay token -- there
    // is no manually supplied ticket parameter anymore.
    expect(relay.ticket).toBe('pairing-relay-token');

    const record = {
      mate_id: bundle.mate_id,
      device_id: relay.deviceId,
      device_signing_key: toBase64(identity.signingPublicKey),
      device_noise_key: toBase64(identity.noisePublicKey),
      paired_at: new Date().toISOString(),
    };
    const binding = JSON.stringify({ domain: 'mesh-axon-pairing-v1', ...record });
    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', mateSigningKeyPair.privateKey, new TextEncoder().encode(binding)),
    );
    const expiresAtSeconds = Math.floor(Date.now() / 1000) + 86_400;
    const pairingReply = {
      record: { ...record, mate_signature: toBase64(signature) },
      relay_token: 'device-relay-token',
      relay_token_expires_at: expiresAtSeconds,
    };
    relay.queueReply(packet(4, new TextEncoder().encode(JSON.stringify(pairingReply))));
    relay.queueReply(packet(2, new Uint8Array(48)));

    const connection = await pairingDone;

    expect(connection.relayToken).toBe('device-relay-token');
    expect(saveMate).toHaveBeenCalledWith(expect.objectContaining({
      mateId: 'mate-1',
      relayUrl: bundle.relay_url,
      noisePublicKey: fromBase64Equivalent(bundle.mate_noise_key),
      signingPublicKey: mateSigningPublicKey,
      relayToken: 'device-relay-token',
      relayTokenExpiresAt: expiresAtSeconds * 1000,
    }));
    expect(relay.closed).toBe(false);
  });

  it('still returns a working connection even if persisting the mate fails', async () => {
    vi.mocked(saveMate).mockRejectedValueOnce(new Error('indexeddb unavailable'));
    const mateSigningKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const mateSigningPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', mateSigningKeyPair.publicKey));
    const bundle = {
      mate_id: 'mate-2',
      mate_signing_key: toBase64(mateSigningPublicKey),
      mate_noise_key: toBase64(new Uint8Array(32).fill(6)),
      relay_url: 'wss://relay.example/v1',
      one_time_token: 'one-time-token',
      relay_token: 'pairing-relay-token',
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    };

    const identity = await loadOrCreateIdentity();
    const pairingDone = pairAndConnect(encodeBundle(bundle));
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;

    const record = {
      mate_id: bundle.mate_id,
      device_id: relay.deviceId,
      device_signing_key: toBase64(identity.signingPublicKey),
      device_noise_key: toBase64(identity.noisePublicKey),
      paired_at: new Date().toISOString(),
    };
    const binding = JSON.stringify({ domain: 'mesh-axon-pairing-v1', ...record });
    const signature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', mateSigningKeyPair.privateKey, new TextEncoder().encode(binding)),
    );
    const pairingReply = {
      record: { ...record, mate_signature: toBase64(signature) },
      relay_token: 'device-relay-token',
      relay_token_expires_at: Math.floor(Date.now() / 1000) + 86_400,
    };
    relay.queueReply(packet(4, new TextEncoder().encode(JSON.stringify(pairingReply))));
    relay.queueReply(packet(2, new Uint8Array(48)));

    await expect(pairingDone).resolves.toMatchObject({ mateId: 'mate-2' });
  });

  it('rejects a pairing reply with an invalid mate signature', async () => {
    const mateSigningKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const otherKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const mateSigningPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', mateSigningKeyPair.publicKey));
    const bundle = {
      mate_id: 'mate-3',
      mate_signing_key: toBase64(mateSigningPublicKey),
      mate_noise_key: toBase64(new Uint8Array(32).fill(7)),
      relay_url: 'wss://relay.example/v1',
      one_time_token: 'one-time-token',
      relay_token: 'pairing-relay-token',
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    };

    const identity = await loadOrCreateIdentity();
    const pairingDone = pairAndConnect(encodeBundle(bundle));
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;

    const record = {
      mate_id: bundle.mate_id,
      device_id: relay.deviceId,
      device_signing_key: toBase64(identity.signingPublicKey),
      device_noise_key: toBase64(identity.noisePublicKey),
      paired_at: new Date().toISOString(),
    };
    const binding = JSON.stringify({ domain: 'mesh-axon-pairing-v1', ...record });
    // Signed with a key that does NOT match bundle.mate_signing_key.
    const badSignature = new Uint8Array(
      await crypto.subtle.sign('Ed25519', otherKeyPair.privateKey, new TextEncoder().encode(binding)),
    );
    const pairingReply = {
      record: { ...record, mate_signature: toBase64(badSignature) },
      relay_token: 'device-relay-token',
      relay_token_expires_at: Math.floor(Date.now() / 1000) + 86_400,
    };
    relay.queueReply(packet(4, new TextEncoder().encode(JSON.stringify(pairingReply))));

    await expect(pairingDone).rejects.toThrow('invalid');
  });

  it('rejects an expired pairing bundle before touching the relay', async () => {
    const bundle = {
      mate_id: 'mate-4',
      mate_signing_key: toBase64(new Uint8Array(32)),
      mate_noise_key: toBase64(new Uint8Array(32)),
      relay_url: 'wss://relay.example/v1',
      one_time_token: 'one-time-token',
      relay_token: 'pairing-relay-token',
      expires_at: new Date(Date.now() - 1000).toISOString(),
    };

    await expect(pairAndConnect(encodeBundle(bundle))).rejects.toThrow('expired');
    expect(FakeRelayTransport.instances).toHaveLength(0);
  });
});

describe('reconnectToMate', () => {
  it('opens a fresh Noise handshake using the stored relay token and touches lastConnectedAt', async () => {
    const mate = samplePairedMate();

    const reconnectDone = reconnectToMate(mate);
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    relay.queueReply(packet(2, new Uint8Array(48)));

    const connection = await reconnectDone;

    expect(connection.mateId).toBe(mate.mateId);
    expect(connection.relayToken).toBe(mate.relayToken);
    expect(relay.relayUrl).toBe(mate.relayUrl);
    // No manually supplied ticket -- the stored device-scope token is used.
    expect(relay.ticket).toBe(mate.relayToken);
    expect(touchLastConnected).toHaveBeenCalledWith(mate.mateId);
  });

  it('surfaces a clear error when the stored relay token has already expired, without touching the relay', async () => {
    const mate = samplePairedMate({ relayTokenExpiresAt: Date.now() - 1000 });

    await expect(reconnectToMate(mate)).rejects.toBeInstanceOf(RelayTokenExpiredError);
    expect(FakeRelayTransport.instances).toHaveLength(0);
  });

  it('still returns a working connection even if touchLastConnected fails', async () => {
    vi.mocked(touchLastConnected).mockRejectedValueOnce(new Error('indexeddb unavailable'));
    const mate = samplePairedMate();

    const reconnectDone = reconnectToMate(mate);
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    relay.queueReply(packet(2, new Uint8Array(48)));

    await expect(reconnectDone).resolves.toMatchObject({ mateId: mate.mateId });
    expect(relay.closed).toBe(false);
  });

  it('rejects with MateKeyMismatchError when the live handshake fails to authenticate', async () => {
    noiseHandshake.finish = async () => {
      throw new Error('ChaCha20Poly1305: invalid tag');
    };
    const mate = samplePairedMate();

    const reconnectDone = reconnectToMate(mate);
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    relay.queueReply(packet(2, new Uint8Array(48)));

    await expect(reconnectDone).rejects.toBeInstanceOf(MateKeyMismatchError);
    expect(relay.closed).toBe(true);
    expect(touchLastConnected).not.toHaveBeenCalled();
  });

  it('surfaces an explicit mate rejection (e.g. device revoked) without relabeling it as a key mismatch', async () => {
    const mate = samplePairedMate();

    const reconnectDone = reconnectToMate(mate);
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    relay.queueReply(packet(5, new TextEncoder().encode(JSON.stringify({ message: 'this device has been revoked' }))));

    await expect(reconnectDone).rejects.toThrow('this device has been revoked');
    await expect(reconnectDone).rejects.not.toBeInstanceOf(MateKeyMismatchError);
  });
});

describe('refreshRelayToken', () => {
  it('round-trips a relay.token.refresh request and persists the refreshed token', async () => {
    const expiresAtSeconds = Math.floor(Date.now() / 1000) + 86_400;
    const client = { request: vi.fn().mockResolvedValue({
      v: 1, id: 'req-1', type: 'relay.token.refresh.response', ts: new Date().toISOString(),
      data: { relay_token: 'fresh-token', relay_token_expires_at: expiresAtSeconds },
    }) };

    await refreshRelayToken(client, 'mate-1');

    expect(client.request).toHaveBeenCalledWith('relay.token.refresh');
    expect(updateRelayToken).toHaveBeenCalledWith('mate-1', 'fresh-token', expiresAtSeconds * 1000);
  });

  it('rejects when the mate returns no data', async () => {
    const client = { request: vi.fn().mockResolvedValue({ v: 1, id: 'req-1', type: 'error', ts: new Date().toISOString() }) };

    await expect(refreshRelayToken(client, 'mate-1')).rejects.toThrow('no data');
    expect(updateRelayToken).not.toHaveBeenCalled();
  });
});

function fromBase64Equivalent(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'));
}
