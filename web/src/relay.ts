import type { NoiseChannel } from './crypto/noiseIK';

interface RouteFrame {
  v: 1;
  mate_id: string;
  from?: string;
  to?: string;
  payload: string;
}

export class RelayTransport {
  readonly #socket: WebSocket;
  readonly #mateId: string;
	readonly #pending: Array<{ resolve: (value: Uint8Array) => void; reject: (error: Error) => void }> = [];
	readonly #queue: Uint8Array[] = [];
	#closedError?: Error;

  constructor(relayURL: string, mateId: string, deviceId: string, ticket: string) {
    const url = new URL('/v1/connect', relayURL);
    url.searchParams.set('mate_id', mateId);
    url.searchParams.set('role', 'device');
    url.searchParams.set('device_id', deviceId);
    this.#mateId = mateId;
    this.#socket = new WebSocket(url, ['axon.v1', `bearer.${base64URL(new TextEncoder().encode(ticket))}`]);
    this.#socket.binaryType = 'arraybuffer';
	this.#socket.addEventListener('message', (event) => {
		try {
			const frame = JSON.parse(new TextDecoder().decode(event.data as ArrayBuffer)) as RouteFrame;
			const payload = fromBase64(frame.payload);
			const receiver = this.#pending.shift();
			if (receiver) receiver.resolve(payload);
			else this.#queue.push(payload);
		} catch {
			this.#closedError = new Error('relay sent an invalid routing frame');
		}
	});
	this.#socket.addEventListener('close', () => {
		this.#closedError = new Error('relay connection closed');
		for (const pending of this.#pending.splice(0)) pending.reject(this.#closedError);
	});
  }

  opened(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.#socket.addEventListener('open', () => resolve(), { once: true });
      this.#socket.addEventListener('error', () => reject(new Error('relay connection failed')), { once: true });
    });
  }

  send(payload: Uint8Array): void {
    const frame: RouteFrame = { v: 1, mate_id: this.#mateId, payload: base64(payload) };
    this.#socket.send(new TextEncoder().encode(JSON.stringify(frame)));
  }

  receive(): Promise<Uint8Array> {
	const queued = this.#queue.shift();
	if (queued) return Promise.resolve(queued);
	if (this.#closedError) return Promise.reject(this.#closedError);
	return new Promise((resolve, reject) => this.#pending.push({ resolve, reject }));
  }

  close(): void {
    this.#socket.close(1000, 'client closed');
  }
}

export class SecureTransport {
  readonly #relay: RelayTransport;
  readonly #channel: NoiseChannel;

  constructor(relay: RelayTransport, channel: NoiseChannel) {
    this.#relay = relay;
    this.#channel = channel;
  }

  send(message: unknown): void {
    this.#relay.send(this.#channel.encrypt(new TextEncoder().encode(JSON.stringify(message))));
  }

  async receive<T>(): Promise<T> {
    const encrypted = await this.#relay.receive();
    return JSON.parse(new TextDecoder().decode(this.#channel.decrypt(encrypted))) as T;
  }

	close(): void {
		this.#relay.close();
	}
}

export function base64(value: Uint8Array): string {
  let binary = '';
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary);
}

export function base64URL(value: Uint8Array): string {
  return base64(value).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
