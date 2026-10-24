import { chacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha256 } from '@noble/hashes/sha2.js';

const encoder = new TextEncoder();
const protocolName = encoder.encode('Noise_IK_25519_ChaChaPoly_SHA256');

export interface NoiseChannel {
  encrypt(plaintext: Uint8Array): Uint8Array;
  decrypt(ciphertext: Uint8Array): Uint8Array;
}

export class NoiseIKInitiator {
  readonly #staticKey: CryptoKeyPair;
  readonly #responderStatic: Uint8Array;
  readonly #prologue: Uint8Array;
  #ephemeral?: CryptoKeyPair;
  #symmetric?: SymmetricState;

  constructor(staticKey: CryptoKeyPair, responderStatic: Uint8Array, prologue = new Uint8Array()) {
    if (responderStatic.length !== 32) throw new Error('responder Noise key must be 32 bytes');
    this.#staticKey = staticKey;
    this.#responderStatic = responderStatic.slice();
    this.#prologue = prologue.slice();
  }

  async start(payload = new Uint8Array()): Promise<Uint8Array> {
    const symmetric = new SymmetricState();
    symmetric.mixHash(this.#prologue);
    symmetric.mixHash(this.#responderStatic);

    const ephemeral = await generateX25519();
    const ephemeralPublic = await exportPublic(ephemeral.publicKey);
    symmetric.mixHash(ephemeralPublic);
    symmetric.mixKey(await dh(ephemeral.privateKey, this.#responderStatic));

    const staticPublic = await exportPublic(this.#staticKey.publicKey);
    const encryptedStatic = symmetric.encryptAndHash(staticPublic);
    symmetric.mixKey(await dh(this.#staticKey.privateKey, this.#responderStatic));
    const encryptedPayload = symmetric.encryptAndHash(payload);

    this.#ephemeral = ephemeral;
    this.#symmetric = symmetric;
    return concat(ephemeralPublic, encryptedStatic, encryptedPayload);
  }

  async finish(message: Uint8Array): Promise<{ payload: Uint8Array; channel: NoiseChannel }> {
    if (!this.#ephemeral || !this.#symmetric) throw new Error('Noise handshake has not started');
    if (message.length < 48) throw new Error('Noise responder message is too short');

    const responderEphemeral = message.slice(0, 32);
    this.#symmetric.mixHash(responderEphemeral);
    this.#symmetric.mixKey(await dh(this.#ephemeral.privateKey, responderEphemeral));
    this.#symmetric.mixKey(await dh(this.#staticKey.privateKey, responderEphemeral));
    const payload = this.#symmetric.decryptAndHash(message.slice(32));
    const [sendKey, receiveKey] = this.#symmetric.split();
    return { payload, channel: channel(sendKey, receiveKey) };
  }
}

export async function generateX25519(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: 'X25519' }, false, ['deriveBits']) as Promise<CryptoKeyPair>;
}

export async function exportPublic(key: CryptoKey): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}

async function dh(privateKey: CryptoKey, publicBytes: Uint8Array): Promise<Uint8Array> {
  const publicKey = await crypto.subtle.importKey('raw', owned(publicBytes), { name: 'X25519' }, false, []);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: publicKey }, privateKey, 256));
}

class SymmetricState {
  #chainingKey: Uint8Array;
  #hash: Uint8Array;
  #cipher?: Cipher;

  constructor() {
    this.#hash = new Uint8Array(32);
    this.#hash.set(protocolName);
    this.#chainingKey = this.#hash.slice();
  }

  mixHash(data: Uint8Array): void {
    this.#hash = sha256(concat(this.#hash, data));
  }

  mixKey(input: Uint8Array): void {
    const [chainingKey, cipherKey] = hkdf2(this.#chainingKey, input);
    this.#chainingKey = chainingKey;
    this.#cipher = new Cipher(cipherKey);
  }

  encryptAndHash(plaintext: Uint8Array): Uint8Array {
    const ciphertext = this.#cipher ? this.#cipher.encrypt(owned(plaintext), owned(this.#hash)) : owned(plaintext);
    this.mixHash(ciphertext);
    return ciphertext;
  }

  decryptAndHash(ciphertext: Uint8Array): Uint8Array {
    const plaintext = this.#cipher ? this.#cipher.decrypt(owned(ciphertext), owned(this.#hash)) : owned(ciphertext);
    this.mixHash(ciphertext);
    return plaintext;
  }

  split(): [Uint8Array, Uint8Array] {
    return hkdf2(this.#chainingKey, new Uint8Array());
  }
}

class Cipher {
  readonly #key: Uint8Array;
  #nonce = 0n;

  constructor(key: Uint8Array) {
    this.#key = key.slice();
  }

  encrypt(plaintext: Uint8Array, aad = new Uint8Array()): Uint8Array {
    const result = chacha20poly1305(owned(this.#key), nonce(this.#nonce++), owned(aad)).encrypt(owned(plaintext));
    return result;
  }

  decrypt(ciphertext: Uint8Array, aad = new Uint8Array()): Uint8Array {
    return chacha20poly1305(owned(this.#key), nonce(this.#nonce++), owned(aad)).decrypt(owned(ciphertext));
  }
}

function channel(sendKey: Uint8Array, receiveKey: Uint8Array): NoiseChannel {
  const send = new Cipher(sendKey);
  const receive = new Cipher(receiveKey);
  return {
    encrypt: (plaintext) => send.encrypt(plaintext),
    decrypt: (ciphertext) => receive.decrypt(ciphertext),
  };
}

function hkdf2(chainingKey: Uint8Array, input: Uint8Array): [Uint8Array, Uint8Array] {
  const temporaryKey = hmac(sha256, chainingKey, input);
  const first = hmac(sha256, temporaryKey, new Uint8Array([1]));
  const second = hmac(sha256, temporaryKey, concat(first, new Uint8Array([2])));
  return [first, second];
}

function nonce(value: bigint): Uint8Array {
  if (value >= 0xffffffffffffffffn) throw new Error('Noise nonce exhausted');
  const result = new Uint8Array(12);
  new DataView(result.buffer).setBigUint64(4, value, true);
  return result;
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function owned(input: Uint8Array): Uint8Array<ArrayBuffer> {
  const result = new Uint8Array(input.byteLength);
  result.set(input);
  return result;
}

export const testInternals = { hkdf2, nonce };
