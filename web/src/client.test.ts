import { describe, expect, it, vi } from 'vitest';
import { AxonClient } from './client';

class FakeTransport {
  readonly sent: unknown[] = [];
  readonly #queued: unknown[] = [];
  readonly #pending: Array<(value: unknown) => void> = [];

  send(value: unknown): void {
    this.sent.push(value);
  }

  receive<T>(): Promise<T> {
    const queued = this.#queued.shift();
    if (queued) return Promise.resolve(queued as T);
    return new Promise<T>((resolve) => this.#pending.push(resolve as (value: unknown) => void));
  }

  push(value: unknown): void {
    const pending = this.#pending.shift();
    if (pending) pending(value);
    else this.#queued.push(value);
  }

  close(): void {}
}

describe('AxonClient', () => {
  it('dispatches unsolicited events without consuming pending responses', async () => {
    const transport = new FakeTransport();
    const client = new AxonClient(transport);
    const handler = vi.fn();
    client.on('session.output', handler);

    const response = client.request('sessions.list');
    const request = transport.sent[0] as { id: string };
    transport.push({
      v: 1, id: 'event-1', type: 'session.output', sid: 'session-1', seq: 4,
      ts: new Date().toISOString(), data: 'bGl2ZQ==',
    });
    await vi.waitFor(() => expect(handler).toHaveBeenCalledOnce());

    transport.push({
      v: 1, id: 'response-1', reply_to: request.id, type: 'sessions.list.response',
      ts: new Date().toISOString(), data: [],
    });
    await expect(response).resolves.toMatchObject({ reply_to: request.id });
    client.close();
  });

  it('stops dispatching after an event handler is removed', async () => {
    const transport = new FakeTransport();
    const client = new AxonClient(transport);
    const handler = vi.fn();
    const remove = client.on('session.output', handler);
    remove();
    transport.push({ v: 1, id: 'event-1', type: 'session.output', ts: new Date().toISOString() });
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(handler).not.toHaveBeenCalled();
    client.close();
  });

  it('rejects a request that never gets a reply instead of hanging forever', async () => {
    vi.useFakeTimers();
    try {
      const transport = new FakeTransport();
      const client = new AxonClient(transport);
      const response = client.request('session.create', undefined, undefined, 1000);
      const assertion = expect(response).rejects.toThrow('session.create request timed out');
      await vi.advanceTimersByTimeAsync(1000);
      await assertion;
      client.close();
    } finally {
      vi.useRealTimers();
    }
  });

  it('forgets a timed-out request so a late reply cannot resolve it twice', async () => {
    vi.useFakeTimers();
    try {
      const transport = new FakeTransport();
      const client = new AxonClient(transport);
      const response = client.request('sessions.list', undefined, undefined, 1000);
      const request = transport.sent[0] as { id: string };
      const assertion = expect(response).rejects.toThrow('timed out');
      await vi.advanceTimersByTimeAsync(1000);
      await assertion;

      // A reply that arrives after the timeout must be a harmless no-op, not
      // a crash or a resolution of a promise the caller already gave up on.
      transport.push({
        v: 1, id: 'late-reply', reply_to: request.id, type: 'sessions.list.response',
        ts: new Date().toISOString(), data: [],
      });
      await vi.advanceTimersByTimeAsync(0);
      client.close();
    } finally {
      vi.useRealTimers();
    }
  });
});
