import { describe, expect, it } from 'vitest';
import type { NoiseChannel } from './crypto/noiseIK';
import { mateRejection, SecureTransport } from './relay';

class FakeRelay {
  sent?: Uint8Array;
  incoming = new Uint8Array();

  send(payload: Uint8Array): void {
    this.sent = payload;
  }

  receive(): Promise<Uint8Array> {
    return Promise.resolve(this.incoming);
  }

  close(): void {}
}

function identityChannel(): NoiseChannel {
  return {
    encrypt: (plaintext) => plaintext,
    decrypt: (ciphertext) => ciphertext,
  };
}

describe('SecureTransport', () => {
  it('adds the encrypted transport packet type when sending', () => {
    const relay = new FakeRelay();
    const transport = new SecureTransport(relay, identityChannel());

    transport.send({ type: 'sessions.list' });

    expect(relay.sent?.[0]).toBe(3);
    expect(JSON.parse(new TextDecoder().decode(relay.sent?.slice(1)))).toEqual({ type: 'sessions.list' });
  });

  it('removes the encrypted transport packet type before decrypting', async () => {
    const relay = new FakeRelay();
    relay.incoming = new Uint8Array([3, ...new TextEncoder().encode('{"type":"sessions.list.response"}')]);
    const transport = new SecureTransport(relay, identityChannel());

    await expect(transport.receive()).resolves.toEqual({ type: 'sessions.list.response' });
  });

  it('rejects packets with an unexpected type', async () => {
    const relay = new FakeRelay();
    relay.incoming = new Uint8Array([2, 1]);
    const transport = new SecureTransport(relay, identityChannel());

    await expect(transport.receive()).rejects.toThrow('invalid encrypted transport packet');
  });

  it('surfaces a mate error packet instead of hanging or decrypting it', async () => {
    const relay = new FakeRelay();
    relay.incoming = new Uint8Array([
      5,
      ...new TextEncoder().encode(JSON.stringify({ code: 'channel_reset_required', message: 'pair again' })),
    ]);
    const transport = new SecureTransport(relay, identityChannel());

    await expect(transport.receive()).rejects.toThrow('pair again');
  });
});

describe('mateRejection', () => {
  it('prefers the message field over the code', () => {
    const payload = new TextEncoder().encode(JSON.stringify({ code: 'device_revoked', message: 'this device has been revoked' }));
    expect(mateRejection(payload).message).toBe('this device has been revoked');
  });

  it('falls back to the code when there is no message', () => {
    const payload = new TextEncoder().encode(JSON.stringify({ code: 'device_revoked' }));
    expect(mateRejection(payload).message).toBe('device_revoked');
  });

  it('falls back to a generic message for malformed payloads', () => {
    expect(mateRejection(new Uint8Array([1, 2, 3])).message).toBe('the mate rejected this request');
  });
});
