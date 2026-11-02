/** Thrown when {@link withTimeout} gives up waiting for a promise to settle. */
export class TimeoutError extends Error {}

/**
 * Rejects with a {@link TimeoutError} if `promise` has not settled within
 * `ms` milliseconds. Used to guarantee that a relay round trip (pairing,
 * handshake, or an AxonClient request) always reaches a visible outcome
 * instead of hanging forever when the Mate silently drops a frame or the
 * underlying transport never closes.
 */
export function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new TimeoutError(message)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}
