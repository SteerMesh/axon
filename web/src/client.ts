import type { SecureTransport } from './relay';

interface Envelope<T = unknown> {
  v: 1;
  id: string;
  reply_to?: string;
  type: string;
  sid?: string;
  epoch?: string;
  seq?: number;
  ts: string;
  idempotency_key?: string;
  data?: T;
}

interface PendingRequest {
  resolve: (value: Envelope) => void;
  reject: (error: Error) => void;
}

type EventHandler = (envelope: Envelope) => void;

export class AxonClient {
  readonly #transport: Pick<SecureTransport, 'send' | 'receive' | 'close'>;
  readonly #pending = new Map<string, PendingRequest>();
  readonly #handlers = new Map<string, Set<EventHandler>>();
  #closed = false;

  constructor(transport: Pick<SecureTransport, 'send' | 'receive' | 'close'>) {
    this.#transport = transport;
    void this.#readLoop();
  }

  request<T>(type: string, data?: unknown, sessionId?: string): Promise<Envelope<T>> {
    if (this.#closed) return Promise.reject(new Error('Axon connection is closed'));
    const id = crypto.randomUUID();
    const envelope: Envelope = {
      v: 1,
      id,
      type,
      ts: new Date().toISOString(),
      ...(sessionId ? { sid: sessionId } : {}),
      ...(type === 'session.input' ? { idempotency_key: crypto.randomUUID() } : {}),
      ...(data === undefined ? {} : { data }),
    };
    this.#transport.send(envelope);
    return new Promise<Envelope<T>>((resolve, reject) => this.#pending.set(id, {
      resolve: resolve as (value: Envelope) => void,
      reject,
    }));
  }

  on<T>(type: string, handler: (envelope: Envelope<T>) => void): () => void {
    const handlers = this.#handlers.get(type) ?? new Set<EventHandler>();
    const eventHandler = handler as EventHandler;
    handlers.add(eventHandler);
    this.#handlers.set(type, handlers);
    return () => {
      handlers.delete(eventHandler);
      if (handlers.size === 0) this.#handlers.delete(type);
    };
  }

  close(): void {
    this.#closed = true;
    this.#transport.close();
    for (const pending of this.#pending.values()) pending.reject(new Error('Axon connection closed'));
    this.#pending.clear();
  }

  async #readLoop(): Promise<void> {
    try {
      while (!this.#closed) {
        const envelope = await this.#transport.receive<Envelope>();
        if (!envelope.reply_to) {
          for (const handler of this.#handlers.get(envelope.type) ?? []) handler(envelope);
          continue;
        }
        const pending = this.#pending.get(envelope.reply_to);
        if (!pending) continue;
        this.#pending.delete(envelope.reply_to);
        if (envelope.type === 'error') {
          const detail = envelope.data as { code?: string; message?: string } | undefined;
          pending.reject(new Error(`${detail?.code ?? 'error'}: ${detail?.message ?? 'request failed'}`));
        } else {
          pending.resolve(envelope);
        }
      }
    } catch (error) {
      this.#closed = true;
      const failure = error instanceof Error ? error : new Error(String(error));
      for (const pending of this.#pending.values()) pending.reject(failure);
      this.#pending.clear();
    }
  }
}
