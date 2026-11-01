import { request, transactionDone, withDatabase } from './db';

const storeName = 'pairedMates';

export interface PairedMate {
  mateId: string;
  noisePublicKey: Uint8Array;
  signingPublicKey: Uint8Array;
  relayUrl: string;
  /** Epoch ms of the last successful connection (pairing or reconnect). */
  lastConnectedAt: number;
}

export async function saveMate(mate: PairedMate): Promise<void> {
  return withDatabase(async (database) => {
    const transaction = database.transaction(storeName, 'readwrite');
    transaction.objectStore(storeName).put(mate);
    await transactionDone(transaction);
  });
}

export async function listMates(): Promise<PairedMate[]> {
  return withDatabase(async (database) => {
    const transaction = database.transaction(storeName);
    return request(transaction.objectStore(storeName).getAll());
  });
}

export async function getMate(mateId: string): Promise<PairedMate | undefined> {
  return withDatabase(async (database) => {
    const transaction = database.transaction(storeName);
    return request(transaction.objectStore(storeName).get(mateId));
  });
}

export async function deleteMate(mateId: string): Promise<void> {
  return withDatabase(async (database) => {
    const transaction = database.transaction(storeName, 'readwrite');
    transaction.objectStore(storeName).delete(mateId);
    await transactionDone(transaction);
  });
}

/** No-op if `mateId` isn't a known paired mate. */
export async function touchLastConnected(mateId: string): Promise<void> {
  return withDatabase(async (database) => {
    const transaction = database.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    const existing = await request<PairedMate | undefined>(store.get(mateId));
    if (existing) store.put({ ...existing, lastConnectedAt: Date.now() });
    await transactionDone(transaction);
  });
}
