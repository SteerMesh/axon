import { describe, expect, it } from 'vitest';
import { testInternals } from './noiseIK';

describe('Noise primitives', () => {
  it('uses the Noise little-endian nonce layout', () => {
    expect(Array.from(testInternals.nonce(0x0102030405060708n))).toEqual([
      0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1,
    ]);
  });

  it('derives two distinct 32-byte cipher keys', () => {
    const [first, second] = testInternals.hkdf2(new Uint8Array(32), new Uint8Array([1, 2, 3]));
    expect(first).toHaveLength(32);
    expect(second).toHaveLength(32);
    expect(first).not.toEqual(second);
  });
});
