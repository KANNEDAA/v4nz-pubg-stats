// V4NZ PUBG Stats — Service Worker v3.1
// FIX v3.1: bypass general cross-origin (arregla avatares Discord 503 + futuros).
// FIX v3.0: bypass de Google Analytics / Tag Manager (gtag.js cargaba mal).
//
// Bug raiz comun: cuando el SW interceptaba un request cross-origin y el
// fetch fallaba (CORS, CDN caido, blocker, etc), el .catch(() => cached)
// devolvia undefined porque la respuesta no estaba en cache. El SW respondia
// con undefined y el navegador lo mostraba como 503/error. Esto rompia
// google-analytics, googletagmanager y cdn.discordapp.com avatares.
//
// Solucion: el SW solo intercepta requests al MISMO origen. Cualquier
// peticion cross-origin se deja pasar al navegador sin tocar (excepto
// los STATIC_ASSETS que precacheamos en install).
const CACHE_NAME = 'v4nz-cache-v31';
const STATIC_ASSETS = [
  '/manifest.json',
  'https://fonts.googleapis.com/css2?family=Orbitron:wght@400;500;600;700;800;900&family=Rajdhani:wght@400;500;600;700&family=Inter:wght@300;400;500;600;700&display=swap'
];

// Install: cache only truly static assets (NOT index.html)
self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(STATIC_ASSETS))
      .then(() => self.skipWaiting())
  );
});

// Activate: clean ALL old caches
self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Fetch strategy
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);

  // BYPASS GENERAL: cualquier request cross-origin pasa sin interceptar.
  // Asi nunca rompemos cdn.discordapp.com, googletagmanager.com,
  // google-analytics.com, ni ningun otro CDN externo. Solo cacheamos
  // recursos del mismo origen + los STATIC_ASSETS precacheados.
  if (url.origin !== self.location.origin) {
    return;
  }

  // Skip non-GET requests
  if (event.request.method !== 'GET') return;

  // API/dynamic calls: NEVER cache
  if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/clans/') ||
      url.pathname.startsWith('/auth/') || url.pathname.startsWith('/favorites/') ||
      url.pathname.startsWith('/players/') || url.pathname.startsWith('/admin/')) {
    return;
  }

  // HTML pages (/, /index.html, /stats/*, /clan/*): NETWORK-FIRST
  // Always try to get fresh HTML, fall back to cache only if offline
  if (event.request.mode === 'navigate' ||
      url.pathname === '/' || url.pathname === '/index.html' ||
      url.pathname.startsWith('/stats/') || url.pathname.startsWith('/clan/')) {
    event.respondWith(
      fetch(event.request)
        .then(response => {
          if (response && response.status === 200) {
            const clone = response.clone();
            caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
          }
          return response;
        })
        .catch(() => caches.match(event.request).then(c => c || caches.match('/')))
    );
    return;
  }

  // Other same-origin static assets (own images, JS, CSS): stale-while-revalidate
  event.respondWith(
    caches.match(event.request).then(cached => {
      const fetchPromise = fetch(event.request).then(response => {
        if (response && response.status === 200 && response.type === 'basic') {
          const clone = response.clone();
          caches.open(CACHE_NAME).then(cache => cache.put(event.request, clone));
        }
        return response;
      }).catch(() => cached);

      return cached || fetchPromise;
    })
  );
});
