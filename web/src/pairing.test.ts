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
}));

// Imported after the mocks above so pairing.ts picks up the mocked modules.
const { MateKeyMismatchError, pairAndConnect, reconnectToMate } = await import('./pairing');
const { saveMate, touchLastConnected } = await import('./mateStore');
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
    ...overrides,
  };
}

beforeEach(() => {
  FakeRelayTransport.instances.length = 0;
  noiseHandshake.finish = async () => ({ payload: new Uint8Array(), channel: { encrypt: (p) => p, decrypt: (c) => c } });
  vi.clearAllMocks();
});

describe('pairAndConnect', () => {
  it('persists the mate keys and relay URL after a successful pairing', async () => {
    const mateSigningKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const mateSigningPublicKey = new Uint8Array(await crypto.subtle.exportKey('raw', mateSigningKeyPair.publicKey));
    const bundle = {
      mate_id: 'mate-1',
      mate_signing_key: toBase64(mateSigningPublicKey),
      mate_noise_key: toBase64(new Uint8Array(32).fill(5)),
      relay_url: 'wss://relay.example/v1',
      one_time_token: 'one-time-token',
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    };

    const identity = await loadOrCreateIdentity();
    const pairingDone = pairAndConnect(encodeBundle(bundle), 'relay-ticket-1');
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
    relay.queueReply(packet(4, new TextEncoder().encode(JSON.stringify({ ...record, mate_signature: toBase64(signature) }))));
    relay.queueReply(packet(2, new Uint8Array(48)));

    await pairingDone;

    expect(saveMate).toHaveBeenCalledWith(expect.objectContaining({
      mateId: 'mate-1',
      relayUrl: bundle.relay_url,
      noisePublicKey: fromBase64Equivalent(bundle.mate_noise_key),
      signingPublicKey: mateSigningPublicKey,
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
      expires_at: new Date(Date.now() + 60_000).toISOString(),
    };

    const identity = await loadOrCreateIdentity();
    const pairingDone = pairAndConnect(encodeBundle(bundle), 'relay-ticket-1');
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
    relay.queueReply(packet(4, new TextEncoder().encode(JSON.stringify({ ...record, mate_signature: toBase64(signature) }))));
    relay.queueReply(packet(2, new Uint8Array(48)));

    await expect(pairingDone).resolves.toMatchObject({ mateId: 'mate-2' });
  });
});

describe('reconnectToMate', () => {
  it('opens a fresh Noise handshake against the stored keys and touches lastConnectedAt', async () => {
    const mate = samplePairedMate();

    const reconnectDone = reconnectToMate(mate, 'relay-ticket-1');
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    relay.queueReply(packet(2, new Uint8Array(48)));

    const connection = await reconnectDone;

    expect(connection.mateId).toBe(mate.mateId);
    expect(relay.relayUrl).toBe(mate.relayUrl);
    expect(touchLastConnected).toHaveBeenCalledWith(mate.mateId);
  });

  it('still returns a working connection even if touchLastConnected fails', async () => {
    vi.mocked(touchLastConnected).mockRejectedValueOnce(new Error('indexeddb unavailable'));
    const mate = samplePairedMate();

    const reconnectDone = reconnectToMate(mate, 'relay-ticket-1');
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

    const reconnectDone = reconnectToMate(mate, 'relay-ticket-1');
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    relay.queueReply(packet(2, new Uint8Array(48)));

    await expect(reconnectDone).rejects.toBeInstanceOf(MateKeyMismatchError);
    expect(relay.closed).toBe(true);
    expect(touchLastConnected).not.toHaveBeenCalled();
  });

  it('surfaces an explicit mate rejection (e.g. device revoked) without relabeling it as a key mismatch', async () => {
    const mate = samplePairedMate();

    const reconnectDone = reconnectToMate(mate, 'relay-ticket-1');
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    const relay = FakeRelayTransport.instances[0]!;
    relay.queueReply(packet(5, new TextEncoder().encode(JSON.stringify({ message: 'this device has been revoked' }))));

    await expect(reconnectDone).rejects.toThrow('this device has been revoked');
    await expect(reconnectDone).rejects.not.toBeInstanceOf(MateKeyMismatchError);
  });

  it('reuses the same relay ticket across repeated reconnects without any extra minting step', async () => {
    const mate = samplePairedMate();
    const ticket = 'static-relay-ticket';

    const first = reconnectToMate(mate, ticket);
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(1));
    FakeRelayTransport.instances[0]!.queueReply(packet(2, new Uint8Array(48)));
    await first;

    const second = reconnectToMate(mate, ticket);
    await vi.waitFor(() => expect(FakeRelayTransport.instances).toHaveLength(2));
    FakeRelayTransport.instances[1]!.queueReply(packet(2, new Uint8Array(48)));
    await second;

    expect(FakeRelayTransport.instances[0]!.ticket).toBe(ticket);
    expect(FakeRelayTransport.instances[1]!.ticket).toBe(ticket);
  });
});

function fromBase64Equivalent(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'));
}
