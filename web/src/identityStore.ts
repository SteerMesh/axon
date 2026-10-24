import { exportPublic, generateX25519 } from './crypto/noiseIK';

const databaseName = 'mesh-axon';
const storeName = 'identity';

export interface StoredIdentity {
  noiseKeyPair: CryptoKeyPair;
  noisePublicKey: Uint8Array;
  signingKeyPair: CryptoKeyPair;
  signingPublicKey: Uint8Array;
}

export async function loadOrCreateIdentity(): Promise<StoredIdentity> {
  const database = await openDatabase();
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
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(databaseName, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(storeName);
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

function request<T>(value: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    value.onsuccess = () => resolve(value.result);
    value.onerror = () => reject(value.error);
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}
