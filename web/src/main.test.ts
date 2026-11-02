// @vitest-environment jsdom
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { PairedMate } from './mateStore';

// main.ts renders a real xterm Terminal, which needs canvas/ResizeObserver
// support jsdom doesn't provide. None of that is relevant to the device
// picker logic under test here, so it's stubbed out entirely.
vi.mock('@xterm/xterm', () => ({
  Terminal: class {
    loadAddon(): void {}
    open(): void {}
    writeln(): void {}
    write(): void {}
    onData(): void {}
    scrollToBottom(): void {}
    focus(): void {}
    reset(): void {}
  },
}));

vi.mock('@xterm/addon-fit', () => ({
  FitAddon: class {
    fit(): void {}
  },
}));

const {
  pairAndConnect, reconnectToMate, refreshRelayToken, MateKeyMismatchError, RelayTokenExpiredError,
} = vi.hoisted(() => ({
  pairAndConnect: vi.fn(),
  reconnectToMate: vi.fn(),
  refreshRelayToken: vi.fn(),
  MateKeyMismatchError: class MateKeyMismatchError extends Error {
    readonly mateId: string;

    constructor(mateId: string) {
      super(`"${mateId}" did not authenticate with its previously known key — re-pair this device to continue.`);
      this.name = 'MateKeyMismatchError';
      this.mateId = mateId;
    }
  },
  RelayTokenExpiredError: class RelayTokenExpiredError extends Error {
    readonly mateId: string;

    constructor(mateId: string) {
      super(`"${mateId}"'s relay access has expired — re-pair this device to continue.`);
      this.name = 'RelayTokenExpiredError';
      this.mateId = mateId;
    }
  },
}));
vi.mock('./pairing', () => ({ pairAndConnect, reconnectToMate, refreshRelayToken, MateKeyMismatchError, RelayTokenExpiredError }));

const { listMates, deleteMate, getMate } = vi.hoisted(() => ({ listMates: vi.fn(), deleteMate: vi.fn(), getMate: vi.fn() }));
vi.mock('./mateStore', () => ({ listMates, deleteMate, getMate }));

/**
 * A SecureTransport-shaped fake that replies to every AxonClient request
 * with a minimal, well-formed response on the next microtask — enough for
 * the post-connect flow (loadMeshOptions, refreshSessions) to settle
 * without hanging on AxonClient's real 15s request timeout.
 */
class AutoReplyTransport {
  readonly sent: Array<{ id: string; type: string }> = [];
  readonly #pending: Array<(value: unknown) => void> = [];
  readonly #queue: unknown[] = [];

  send(message: unknown): void {
    const { id, type } = message as { id: string; type: string };
    this.sent.push({ id, type });
    const data = type === 'mesh.options' ? { workspaces: [], targets: [] } : [];
    queueMicrotask(() => this.push({
      v: 1, id: `reply-${id}`, reply_to: id, type: `${type}.response`, ts: new Date().toISOString(), data,
    }));
  }

  receive<T>(): Promise<T> {
    const queued = this.#queue.shift();
    if (queued !== undefined) return Promise.resolve(queued as T);
    return new Promise((resolve) => this.#pending.push(resolve as (value: unknown) => void));
  }

  push(value: unknown): void {
    const pending = this.#pending.shift();
    if (pending) pending(value);
    else this.#queue.push(value);
  }

  close(): void {}
}

function samplePairedMate(overrides: Partial<PairedMate> = {}): PairedMate {
  return {
    mateId: 'mate-1',
    noisePublicKey: new Uint8Array(32),
    signingPublicKey: new Uint8Array(32),
    relayUrl: 'wss://relay.example/v1',
    lastConnectedAt: Date.now() - 60_000,
    relayToken: 'device-relay-token',
    relayTokenExpiresAt: Date.now() + 60_000,
    ...overrides,
  };
}

function samplePairedConnection(mateId: string) {
  return {
    deviceId: 'device-1', mateId, relayUrl: 'wss://relay.example/v1',
    relayToken: 'device-relay-token', transport: new AutoReplyTransport(),
  };
}

function pickerHidden(): boolean {
  return document.querySelector<HTMLElement>('#device-picker')!.hidden;
}

function pairingHidden(): boolean {
  return document.querySelector<HTMLElement>('.pairing')!.hidden;
}

beforeEach(() => {
  vi.resetModules();
  vi.clearAllMocks();
  document.body.innerHTML = '<div id="app"></div>';
});

describe('device picker', () => {
  it('falls back to the pairing form when no mates are known', async () => {
    listMates.mockResolvedValue([]);

    await import('./main');

    await vi.waitFor(() => expect(pairingHidden()).toBe(false));
    expect(pickerHidden()).toBe(true);
    expect(document.querySelector<HTMLDetailsElement>('.pairing')!.open).toBe(true);
  });

  it('shows one card per known mate instead of the pairing form', async () => {
    listMates.mockResolvedValue([
      samplePairedMate({ mateId: 'mate-1' }),
      samplePairedMate({ mateId: 'mate-2' }),
    ]);

    await import('./main');

    await vi.waitFor(() => expect(pickerHidden()).toBe(false));
    expect(pairingHidden()).toBe(true);
    const cards = document.querySelectorAll('#mate-list .mate-card');
    expect(cards).toHaveLength(2);
    expect(cards[0]!.textContent).toContain('mate-1');
    expect(cards[1]!.textContent).toContain('mate-2');
  });

  it('reconnects to the chosen mate without any manual ticket input, and proceeds to the landing view', async () => {
    const mate = samplePairedMate();
    listMates.mockResolvedValue([mate]);
    reconnectToMate.mockResolvedValue(samplePairedConnection(mate.mateId));

    await import('./main');
    await vi.waitFor(() => expect(pickerHidden()).toBe(false));
    expect(document.querySelector('#picker-relay-ticket')).toBeNull();
    document.querySelector<HTMLButtonElement>('.mate-card-actions .primary')!.click();

    await vi.waitFor(() => expect(document.querySelector<HTMLElement>('#landing')!.hidden).toBe(false));
    expect(reconnectToMate).toHaveBeenCalledWith(mate);
    expect(pickerHidden()).toBe(true);
    expect(pairingHidden()).toBe(true);
  });

  it('prompts re-pairing instead of a raw error when the mate fails the key-mismatch check', async () => {
    const mate = samplePairedMate();
    listMates.mockResolvedValue([mate]);
    reconnectToMate.mockRejectedValue(new MateKeyMismatchError(mate.mateId));

    await import('./main');
    await vi.waitFor(() => expect(pickerHidden()).toBe(false));
    document.querySelector<HTMLButtonElement>('.mate-card-actions .primary')!.click();

    await vi.waitFor(() => {
      expect(document.querySelector('#banner')!.textContent).toMatch(/Pair a new device/);
    });
    // The picker stays up so the user can still pick a different mate, or
    // use the "Pair a new device" link the error points them to.
    expect(pickerHidden()).toBe(false);
  });

  it('prompts re-pairing with a clear message when the stored relay token has expired', async () => {
    const mate = samplePairedMate();
    listMates.mockResolvedValue([mate]);
    reconnectToMate.mockRejectedValue(new RelayTokenExpiredError(mate.mateId));

    await import('./main');
    await vi.waitFor(() => expect(pickerHidden()).toBe(false));
    document.querySelector<HTMLButtonElement>('.mate-card-actions .primary')!.click();

    await vi.waitFor(() => {
      expect(document.querySelector('#banner')!.textContent).toMatch(/relay access has expired/);
    });
    expect(document.querySelector('#banner')!.textContent).toMatch(/Pair a new device/);
    expect(pickerHidden()).toBe(false);
  });

  it('surfaces a plain connection failure (e.g. mate offline) distinctly from a key mismatch', async () => {
    const mate = samplePairedMate();
    listMates.mockResolvedValue([mate]);
    reconnectToMate.mockRejectedValue(new Error('relay connection failed'));

    await import('./main');
    await vi.waitFor(() => expect(pickerHidden()).toBe(false));
    document.querySelector<HTMLButtonElement>('.mate-card-actions .primary')!.click();

    await vi.waitFor(() => {
      expect(document.querySelector('#banner')!.textContent).toBe('relay connection failed');
    });
    expect(document.querySelector('#banner')!.textContent).not.toMatch(/Pair a new device/);
  });

  it('forgets a mate and re-renders, falling back to the pairing form once none remain', async () => {
    const mate = samplePairedMate();
    listMates.mockResolvedValueOnce([mate]).mockResolvedValueOnce([]);
    deleteMate.mockResolvedValue(undefined);

    await import('./main');
    await vi.waitFor(() => expect(pickerHidden()).toBe(false));
    document.querySelector<HTMLButtonElement>('.mate-card-actions .ghost')!.click();

    await vi.waitFor(() => expect(deleteMate).toHaveBeenCalledWith(mate.mateId));
    await vi.waitFor(() => expect(pairingHidden()).toBe(false));
    expect(pickerHidden()).toBe(true);
  });

  it('lets the user jump to pairing a new device from the picker', async () => {
    listMates.mockResolvedValue([samplePairedMate()]);

    await import('./main');
    await vi.waitFor(() => expect(pickerHidden()).toBe(false));
    document.querySelector<HTMLButtonElement>('#picker-pair-new')!.click();

    expect(pickerHidden()).toBe(true);
    const pairing = document.querySelector<HTMLDetailsElement>('.pairing')!;
    expect(pairing.hidden).toBe(false);
    expect(pairing.open).toBe(true);
  });
});

describe('QR pairing form', () => {
  // onConnected() was extracted out of this handler so the device picker's
  // reconnect flow could share it — this guards that the original
  // pairAndConnect submit path still reaches landing correctly afterwards.
  it('pairs via the QR form and reaches the landing view', async () => {
    listMates.mockResolvedValue([]);
    pairAndConnect.mockResolvedValue(samplePairedConnection('mate-9'));

    await import('./main');
    await vi.waitFor(() => expect(pairingHidden()).toBe(false));

    expect(document.querySelector('#relay-ticket')).toBeNull();
    document.querySelector<HTMLTextAreaElement>('#pairing-payload')!.value = 'encoded-bundle';
    document.querySelector<HTMLButtonElement>('#pairing-form button[type="submit"]')!.click();

    await vi.waitFor(() => expect(document.querySelector<HTMLElement>('#landing')!.hidden).toBe(false));
    expect(pairAndConnect).toHaveBeenCalledWith('encoded-bundle');
    expect(pickerHidden()).toBe(true);
    expect(pairingHidden()).toBe(true);
    expect(document.querySelector('#connection-state')!.textContent).toBe('Encrypted');
  });

  it('shows the pairing-failed state and a banner when pairAndConnect rejects', async () => {
    listMates.mockResolvedValue([]);
    pairAndConnect.mockRejectedValue(new Error('pairing code has expired'));

    await import('./main');
    await vi.waitFor(() => expect(pairingHidden()).toBe(false));

    document.querySelector<HTMLTextAreaElement>('#pairing-payload')!.value = 'encoded-bundle';
    document.querySelector<HTMLButtonElement>('#pairing-form button[type="submit"]')!.click();

    await vi.waitFor(() => expect(document.querySelector('#connection-state')!.textContent).toBe('Pairing failed'));
    expect(document.querySelector('#banner')!.textContent).toBe('pairing code has expired');
  });
});
