const cacheName = 'mesh-axon-v1';
const shell = ['/', '/index.html', '/manifest.webmanifest', '/axon.svg'];

self.addEventListener('install', (event) => {
  event.waitUntil(caches.open(cacheName).then((cache) => cache.addAll(shell)));
});

self.addEventListener('activate', (event) => {
  event.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((key) => key !== cacheName).map((key) => caches.delete(key)))));
});

self.addEventListener('fetch', (event) => {
  if (event.request.method !== 'GET') return;
  event.respondWith(fetch(event.request).then((response) => {
    const copy = response.clone();
    caches.open(cacheName).then((cache) => cache.put(event.request, copy));
    return response;
  }).catch(() => caches.match(event.request)));
});

// The relay's wake push is content-free by design -- it is always exactly
// `{"type":"wake"}`, never a title/body/session identifier. This handler
// must not try to read notification text out of the payload; it always
// shows the same generic prompt to open the app and check.
self.addEventListener('push', (event) => {
  event.waitUntil(self.registration.showNotification('Mesh Axon', {
    body: 'A session needs attention — open the app to check.',
    icon: '/axon.svg',
    tag: 'axon-wake',
  }));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clients) => {
      for (const client of clients) {
        if ('focus' in client) return client.focus();
      }
      return self.clients.openWindow('/');
    }),
  );
});
