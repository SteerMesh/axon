import { afterEach, describe, expect, it, vi } from 'vitest';
import { disableWakeNotifications, enableWakeNotifications } from './push';

interface FakeSubscriptionJSON {
  endpoint: string;
  keys: { p256dh: string; auth: string };
}

function fakeRegistration(options: {
  subscribe?: (options: PushSubscriptionOptionsInit) => Promise<FakeSubscriptionJSON | null>;
  existingSubscription?: { unsubscribe: ReturnType<typeof vi.fn> } | null;
}): ServiceWorkerRegistration {
  const subscribe = options.subscribe ?? (async () => ({ endpoint: 'https://push.example/ep', keys: { p256dh: 'p256', auth: 'auth' } }));
  return {
    pushManager: {
      subscribe: vi.fn(async (subscribeOptions: PushSubscriptionOptionsInit) => {
        const json = await subscribe(subscribeOptions);
        if (!json) throw new Error('subscribe rejected');
        return { toJSON: () => json } as unknown as PushSubscription;
      }),
      getSubscription: vi.fn(async () => options.existingSubscription ?? null),
    },
  } as unknown as ServiceWorkerRegistration;
}

function jsonResponse(body: unknown, ok = true): Response {
  return { ok, json: async () => body } as unknown as Response;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('enableWakeNotifications', () => {
  const config = { relayUrl: 'wss://relay.example/v1/connect', relayTicket: 'ticket-123', mateId: 'mate-1', deviceId: 'device-1' };

  it('does nothing and reports false when permission is denied', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);
    const registration = fakeRegistration({});

    const result = await enableWakeNotifications(registration, config, { requestPermission: async () => 'denied' });

    expect(result).toBe(false);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('returns false when the vapid-key fetch fails', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({}, false)));
    const registration = fakeRegistration({});

    const result = await enableWakeNotifications(registration, config, { requestPermission: async () => 'granted' });

    expect(result).toBe(false);
  });

  it('returns false when the relay has no vapid public key configured', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ publicKey: '' })));
    const registration = fakeRegistration({});

    const result = await enableWakeNotifications(registration, config, { requestPermission: async () => 'granted' });

    expect(result).toBe(false);
  });

  it('subscribes with the relay-provided key over HTTPS and registers the subscription', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.includes('/v1/vapid-key')) return jsonResponse({ publicKey: 'AAEC' }); // base64url, no padding needed concerns
      void init;
      return jsonResponse({}, true);
    });
    vi.stubGlobal('fetch', fetchMock);
    const registration = fakeRegistration({});

    const result = await enableWakeNotifications(registration, config, { requestPermission: async () => 'granted' });

    expect(result).toBe(true);
    // The relay URL is wss://, but REST calls must use https://.
    const firstCall = fetchMock.mock.calls[0];
    expect(firstCall).toBeDefined();
    expect(String(firstCall?.[0])).toBe('https://relay.example/v1/vapid-key');

    const secondCall = fetchMock.mock.calls[1];
    expect(secondCall).toBeDefined();
    const [subscribeURL, subscribeInit] = secondCall!;
    expect(String(subscribeURL)).toBe('https://relay.example/v1/push/subscribe');
    expect(subscribeInit?.method).toBe('POST');
    expect((subscribeInit?.headers as Record<string, string>).Authorization).toBe('Bearer ticket-123');
    expect(JSON.parse(subscribeInit?.body as string)).toEqual({
      mate_id: 'mate-1',
      device_id: 'device-1',
      endpoint: 'https://push.example/ep',
      keys: { p256dh: 'p256', auth: 'auth' },
    });

    const subscribeMock = registration.pushManager.subscribe as unknown as ReturnType<typeof vi.fn>;
    const subscribeCall = subscribeMock.mock.calls[0]?.[0] as PushSubscriptionOptionsInit;
    expect(subscribeCall.userVisibleOnly).toBe(true);
    expect(subscribeCall.applicationServerKey).toBeInstanceOf(Uint8Array);
  });

  it('rewrites a plain ws:// relay URL to http:// for REST calls', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({ publicKey: 'AAEC' }));
    vi.stubGlobal('fetch', fetchMock);
    const registration = fakeRegistration({});

    await enableWakeNotifications(registration, { ...config, relayUrl: 'ws://relay.local:8080/v1/connect' }, { requestPermission: async () => 'granted' });

    const firstCall = fetchMock.mock.calls[0];
    expect(firstCall).toBeDefined();
    expect(String(firstCall?.[0])).toBe('http://relay.local:8080/v1/vapid-key');
  });

  it('returns false when the push subscription is missing endpoint or keys', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ publicKey: 'AAEC' })));
    const registration = fakeRegistration({ subscribe: async () => ({ endpoint: '', keys: { p256dh: '', auth: '' } }) });

    const result = await enableWakeNotifications(registration, config, { requestPermission: async () => 'granted' });

    expect(result).toBe(false);
  });

  it('returns false instead of throwing when the browser refuses to subscribe', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => jsonResponse({ publicKey: 'AAEC' })));
    const registration = fakeRegistration({ subscribe: async () => null });

    const result = await enableWakeNotifications(registration, config, { requestPermission: async () => 'granted' });

    expect(result).toBe(false);
  });

  it('returns false instead of throwing when the relay is unreachable', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('network down');
    }));
    const registration = fakeRegistration({});

    const result = await enableWakeNotifications(registration, config, { requestPermission: async () => 'granted' });

    expect(result).toBe(false);
  });
});

describe('disableWakeNotifications', () => {
  const config = { relayUrl: 'wss://relay.example/v1/connect', relayTicket: 'ticket-123', mateId: 'mate-1', deviceId: 'device-1' };

  it('unsubscribes the browser subscription and deletes the relay record', async () => {
    const unsubscribe = vi.fn(async () => true);
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({}, true));
    vi.stubGlobal('fetch', fetchMock);
    const registration = fakeRegistration({ existingSubscription: { unsubscribe } });

    await disableWakeNotifications(registration, config);

    expect(unsubscribe).toHaveBeenCalledOnce();
    const call = fetchMock.mock.calls[0];
    expect(call).toBeDefined();
    const [deleteURL, deleteInit] = call!;
    expect(String(deleteURL)).toBe('https://relay.example/v1/push/subscribe?mate_id=mate-1&device_id=device-1');
    expect(deleteInit?.method).toBe('DELETE');
    expect((deleteInit?.headers as Record<string, string>).Authorization).toBe('Bearer ticket-123');
  });

  it('still deletes the relay record when there is no local subscription', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) => jsonResponse({}, true));
    vi.stubGlobal('fetch', fetchMock);
    const registration = fakeRegistration({ existingSubscription: null });

    await disableWakeNotifications(registration, config);

    expect(fetchMock).toHaveBeenCalledOnce();
  });

  it('never throws, even when both the browser and the relay call fail', async () => {
    const unsubscribe = vi.fn(async () => {
      throw new Error('unsubscribe failed');
    });
    vi.stubGlobal('fetch', vi.fn(async () => {
      throw new Error('relay unreachable');
    }));
    const registration = fakeRegistration({ existingSubscription: { unsubscribe } });

    await expect(disableWakeNotifications(registration, config)).resolves.toBeUndefined();
  });
});
