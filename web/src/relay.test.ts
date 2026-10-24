import { describe, expect, it } from 'vitest';
import type { NoiseChannel } from './crypto/noiseIK';
import { SecureTransport } from './relay';

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
});
