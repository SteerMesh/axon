import 'fake-indexeddb/auto';
import { beforeEach, describe, expect, it } from 'vitest';
import { deleteMate, getMate, listMates, type PairedMate, saveMate, touchLastConnected } from './mateStore';

let counter = 0;
// Fresh id per test so tests can run in any order without reading each
// other's rows back — the underlying fake IndexedDB database persists for
// the lifetime of the test file.
function mate(overrides: Partial<PairedMate> = {}): PairedMate {
  counter += 1;
  return {
    mateId: `mate-${counter}`,
    noisePublicKey: new Uint8Array([1, 2, 3, counter]),
    signingPublicKey: new Uint8Array([4, 5, 6, counter]),
    relayUrl: 'wss://relay.example/v1',
    lastConnectedAt: 1_700_000_000_000,
    ...overrides,
  };
}

beforeEach(() => {
  counter += 1000; // keep every test's ids distinct from the last
});

describe('mateStore', () => {
  it('saves and retrieves a paired mate, including its binary key fields', async () => {
    const record = mate();

    await saveMate(record);
    const loaded = await getMate(record.mateId);

    expect(loaded).toEqual(record);
    expect(loaded?.noisePublicKey).toBeInstanceOf(Uint8Array);
  });

  it('returns undefined for a mate that was never saved', async () => {
    await expect(getMate('never-saved')).resolves.toBeUndefined();
  });

  it('lists every saved mate', async () => {
    const first = mate();
    const second = mate();
    await saveMate(first);
    await saveMate(second);

    const mates = await listMates();

    expect(mates).toEqual(expect.arrayContaining([first, second]));
  });

  it('overwrites an existing record when saved again with the same mateId', async () => {
    const record = mate();
    await saveMate(record);
    await saveMate({ ...record, relayUrl: 'wss://relay.example/v2' });

    await expect(getMate(record.mateId)).resolves.toMatchObject({ relayUrl: 'wss://relay.example/v2' });
  });

  it('deletes a mate', async () => {
    const record = mate();
    await saveMate(record);

    await deleteMate(record.mateId);

    await expect(getMate(record.mateId)).resolves.toBeUndefined();
  });

  it('deleting an unknown mate is a no-op, not an error', async () => {
    await expect(deleteMate('does-not-exist')).resolves.toBeUndefined();
  });

  it('touchLastConnected bumps lastConnectedAt on an existing mate', async () => {
    const record = mate({ lastConnectedAt: 1 });
    await saveMate(record);

    await touchLastConnected(record.mateId);

    const loaded = await getMate(record.mateId);
    expect(loaded?.lastConnectedAt).toBeGreaterThan(1);
  });

  it('touchLastConnected on an unknown mate is a no-op, not an error', async () => {
    await expect(touchLastConnected('does-not-exist')).resolves.toBeUndefined();
    await expect(getMate('does-not-exist')).resolves.toBeUndefined();
  });
});
