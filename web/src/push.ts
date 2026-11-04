// Web Push wake notifications. The relay (not this client) decides when to
// send one: it fires a content-free `{"type":"wake"}` push whenever it has
// no connected device peer for a frame. This module only manages the
// subscription lifecycle -- requesting permission, registering with the
// browser's push service, and telling the relay where to find the device.
//
// Every step here is best-effort: an unsupported browser, a denied
// permission, or an unreachable relay must never fail pairing. Callers
// should not need to catch anything from these functions.

export interface WakeNotificationConfig {
  relayUrl: string;
  /** The device-scope Relay Access Token this device last authenticated with. */
  relayToken: string;
  mateId: string;
  deviceId: string;
}

export interface NotificationPermissionApi {
  requestPermission(): Promise<NotificationPermission>;
}

/**
 * Requests notification permission, fetches the relay's current VAPID
 * public key, subscribes the given service worker registration to push,
 * and registers the subscription with the relay. Resolves to whether a
 * subscription was successfully registered; never rejects.
 */
export async function enableWakeNotifications(
  registration: ServiceWorkerRegistration,
  config: WakeNotificationConfig,
  notificationApi: NotificationPermissionApi,
): Promise<boolean> {
  try {
    if ((await notificationApi.requestPermission()) !== 'granted') return false;

    const keyResponse = await fetch(relayHttpURL(config.relayUrl, '/v1/vapid-key'));
    if (!keyResponse.ok) return false;
    const { publicKey } = (await keyResponse.json()) as { publicKey?: string };
    if (!publicKey) return false;

    const subscription = await registration.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: base64URLToBytes(publicKey),
    });
    const { endpoint, keys } = subscription.toJSON() as {
      endpoint?: string;
      keys?: { p256dh?: string; auth?: string };
    };
    if (!endpoint || !keys?.p256dh || !keys.auth) return false;

    const subscribeResponse = await fetch(relayHttpURL(config.relayUrl, '/v1/push/subscribe'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${config.relayToken}` },
      body: JSON.stringify({ mate_id: config.mateId, device_id: config.deviceId, endpoint, keys }),
    });
    return subscribeResponse.ok;
  } catch {
    return false;
  }
}

/**
 * Unsubscribes the given service worker registration from push and removes
 * the relay's subscription record. Best-effort in both directions: a
 * failure here must never block whatever lifecycle action (e.g. forgetting
 * a mate) triggered it.
 */
export async function disableWakeNotifications(
  registration: ServiceWorkerRegistration,
  config: WakeNotificationConfig,
): Promise<void> {
  try {
    const subscription = await registration.pushManager.getSubscription();
    if (subscription) await subscription.unsubscribe();
  } catch {
    // Best-effort: an unsubscribe failure shouldn't block forgetting a mate.
  }
  try {
    const url = new URL(relayHttpURL(config.relayUrl, '/v1/push/subscribe'));
    url.searchParams.set('mate_id', config.mateId);
    url.searchParams.set('device_id', config.deviceId);
    await fetch(url, { method: 'DELETE', headers: { Authorization: `Bearer ${config.relayToken}` } });
  } catch {
    // Best-effort: the relay will still prune the row if it hits a 410/404.
  }
}

/** Rewrites a relay URL (which may be ws:/wss: for the websocket endpoint) to http:/https: for REST calls. */
function relayHttpURL(relayUrl: string, path: string): string {
  const url = new URL(path, relayUrl);
  if (url.protocol === 'ws:') url.protocol = 'http:';
  else if (url.protocol === 'wss:') url.protocol = 'https:';
  return url.toString();
}

function base64URLToBytes(value: string): Uint8Array<ArrayBuffer> {
  const standard = value.replaceAll('-', '+').replaceAll('_', '/');
  const padded = standard + '='.repeat((4 - (standard.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return bytes;
}
