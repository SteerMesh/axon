import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { describe, expect, it } from 'vitest';
import { exportPublic, generateX25519, NoiseIKInitiator } from './noiseIK';

interface Message {
  mate_public?: string;
  device_public?: string;
  prologue?: string;
  payload?: string;
}

describe('Go and browser Noise interoperability', () => {
  it('completes IK and exchanges encrypted application data', async () => {
    const responder = spawn('go', ['run', '../test/interop/noise-responder'], { stdio: ['pipe', 'pipe', 'inherit'] });
    const lines = createInterface({ input: responder.stdout })[Symbol.asyncIterator]();
    const read = async (): Promise<Message> => JSON.parse((await lines.next()).value as string) as Message;
    const write = (message: Message): void => {
      responder.stdin.write(`${JSON.stringify(message)}\n`);
    };

    const hello = await read();
    const staticKey = await generateX25519();
    const staticPublic = await exportPublic(staticKey.publicKey);
    const prologue = new TextEncoder().encode('mesh-axon-v1:interop');
    const initiator = new NoiseIKInitiator(staticKey, fromBase64(hello.mate_public!), prologue);
    const first = await initiator.start(new TextEncoder().encode('browser-device'));
    write({ device_public: base64(staticPublic), prologue: base64(prologue), payload: base64(first) });

    const handshake = await read();
    const { payload, channel } = await initiator.finish(fromBase64(handshake.payload!));
    expect(new TextDecoder().decode(payload)).toBe('mate-accepted');

    write({ payload: base64(channel.encrypt(new TextEncoder().encode('terminal-data'))) });
    const reply = await read();
    expect(new TextDecoder().decode(channel.decrypt(fromBase64(reply.payload!)))).toBe('echo:terminal-data');

    responder.stdin.end();
    expect(await new Promise<number | null>((resolve) => responder.once('exit', resolve))).toBe(0);
  }, 30_000);
});

function base64(value: Uint8Array): string {
  return Buffer.from(value).toString('base64').replaceAll('=', '');
}

function fromBase64(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'base64'));
}
