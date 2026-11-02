import { exportPublic, generateX25519 } from './crypto/noiseIK';
import { request, transactionDone, withDatabase } from './db';

const storeName = 'identity';

export interface StoredIdentity {
  noiseKeyPair: CryptoKeyPair;
  noisePublicKey: Uint8Array;
  signingKeyPair: CryptoKeyPair;
  signingPublicKey: Uint8Array;
}

export async function loadOrCreateIdentity(): Promise<StoredIdentity> {
  return withDatabase(async (database) => {
    const transaction = database.transaction(storeName);
    const noise = await request<CryptoKeyPair | undefined>(transaction.objectStore(storeName).get('noise'));
    const signing = await request<CryptoKeyPair | undefined>(transaction.objectStore(storeName).get('signing'));
    if (noise && signing) {
      return {
        noiseKeyPair: noise,
        noisePublicKey: await exportPublic(noise.publicKey),
        signingKeyPair: signing,
        signingPublicKey: new Uint8Array(await crypto.subtle.exportKey('raw', signing.publicKey)),
      };
    }

    const noiseKeyPair = await generateX25519();
    const signingKeyPair = await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify']) as CryptoKeyPair;
    const write = database.transaction(storeName, 'readwrite');
    write.objectStore(storeName).put(noiseKeyPair, 'noise');
    write.objectStore(storeName).put(signingKeyPair, 'signing');
    await transactionDone(write);
    return {
      noiseKeyPair,
      noisePublicKey: await exportPublic(noiseKeyPair.publicKey),
      signingKeyPair,
      signingPublicKey: new Uint8Array(await crypto.subtle.exportKey('raw', signingKeyPair.publicKey)),
    };
  });
}
