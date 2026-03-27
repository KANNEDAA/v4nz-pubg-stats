const CACHE_NAME = 'v4nz-v2';
const STATIC_ASSETS = ['/', '/manifest.json'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(STATIC_ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/clans/')) { e.respondWith(fetch(e.request)); return; }
  if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com' || url.hostname === 'cdnjs.cloudflare.com') {
    e.respondWith(caches.match(e.request).then(cached => { if (cached) return cached; return fetch(e.request).then(resp => { const clone = resp.clone(); caches.open(CACHE_NAME).then(cache => cache.put(e.request, clone)); return resp; }); }));
    return;
  }
  e.respondWith(fetch(e.request).then(resp => { const clone = resp.clone(); caches.open(CACHE_NAME).then(cache => cache.put(e.request, clone)); return resp; }).catch(() => caches.match(e.request)));
});
