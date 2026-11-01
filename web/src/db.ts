/**
 * Shared IndexedDB plumbing for the `mesh-axon` database. `identityStore.ts`
 * and `mateStore.ts` each own one object store but both need the database
 * opened at the same version with a single `onupgradeneeded` — IndexedDB
 * only fires that event for the connection that first requests a higher
 * version, so if each module opened the database independently at its own
 * version, whichever module's store was added second would never actually
 * get created. Centralizing the open/upgrade here avoids that.
 */
const databaseName = 'mesh-axon';
const databaseVersion = 2;

interface ObjectStoreSpec {
  name: string;
  options?: IDBObjectStoreParameters;
}

const objectStores: ObjectStoreSpec[] = [
  { name: 'identity' },
  { name: 'pairedMates', options: { keyPath: 'mateId' } },
];

export function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(databaseName, databaseVersion);
    open.onupgradeneeded = () => {
      for (const store of objectStores) {
        if (!open.result.objectStoreNames.contains(store.name)) {
          open.result.createObjectStore(store.name, store.options);
        }
      }
    };
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
}

/**
 * Opens the database, runs `run` against it, and closes the connection
 * once `run` settles — every exported store function goes through this so
 * none of them has to remember to close what it opened. `IDBDatabase.close`
 * is safe to call while a transaction created from it is still finishing:
 * it just defers the actual close until that transaction completes, it
 * doesn't abort anything in flight.
 */
export async function withDatabase<T>(run: (database: IDBDatabase) => Promise<T>): Promise<T> {
  const database = await openDatabase();
  try {
    return await run(database);
  } finally {
    database.close();
  }
}

export function request<T>(value: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    value.onsuccess = () => resolve(value.result);
    value.onerror = () => reject(value.error);
  });
}

export function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
}
