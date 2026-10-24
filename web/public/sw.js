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

self.addEventListener('push', (event) => {
  const message = event.data ? event.data.json() : { title: 'Mesh Axon', body: 'A watched session changed state.' };
  event.waitUntil(self.registration.showNotification(message.title || 'Mesh Axon', {
    body: message.body || 'A watched session changed state.',
    icon: '/axon.svg',
    tag: message.tag || 'axon-session-state',
  }));
});
