import { request, transactionDone, withDatabase } from './db';

const storeName = 'pairedMates';

export interface PairedMate {
  mateId: string;
  noisePublicKey: Uint8Array;
  signingPublicKey: Uint8Array;
  relayUrl: string;
  /** Epoch ms of the last successful connection (pairing or reconnect). */
  lastConnectedAt: number;
  /**
   * A device-scope Relay Access Token (see internal/security/relaytoken.go
   * on the mate), persisted here so a reload can reconnect without
   * re-scanning a QR code. This grants routing-level relay access only for
   * up to 24h -- it is not a session credential: the device's Noise and
   * signing private keys stay non-extractable in IndexedDB exactly as
   * before, so a RAT alone cannot complete a handshake or read session
   * content.
   */
  relayToken: string;
  /** Epoch ms when relayToken expires (relay_token_expires_at * 1000). */
  relayTokenExpiresAt: number;
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

/**
 * Persists a freshly refreshed relay token for an already-paired mate (see
 * pairing.ts's refreshRelayToken). No-op if `mateId` isn't known -- a
 * refresh response arriving for a mate this device no longer has recorded
 * isn't actionable.
 */
export async function updateRelayToken(mateId: string, relayToken: string, relayTokenExpiresAt: number): Promise<void> {
  return withDatabase(async (database) => {
    const transaction = database.transaction(storeName, 'readwrite');
    const store = transaction.objectStore(storeName);
    const existing = await request<PairedMate | undefined>(store.get(mateId));
    if (existing) store.put({ ...existing, relayToken, relayTokenExpiresAt });
    await transactionDone(transaction);
  });
}
