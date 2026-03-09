/**
 * FWF App — Service Worker v2.1
 * Cache-first for static assets · Network-first for pages · Offline fallback
 */

const CACHE = 'fwf-app-v4';
const OFFLINE_URL = '/app/offline';

const PRECACHE = [
  '/app/offline',
  '/app/manifest.json',
  '/assets/css/fwf-app.css',
  '/assets/images/logo.png',
  '/assets/images/bg-madhubani.png',
];

// ── Install ──────────────────────────────────────────────
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(PRECACHE).catch(() => {})) // soft fail — don't block install
      .then(() => self.skipWaiting())
  );
});

// ── Activate ─────────────────────────────────────────────
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// ── Fetch ─────────────────────────────────────────────────
self.addEventListener('fetch', e => {
  const { request } = e;
  const url = new URL(request.url);

  // Skip: non-GET, API calls, external domains
  if (request.method !== 'GET') return;
  if (url.pathname.startsWith('/api/')) return;
  if (!url.hostname.includes(self.location.hostname) && !url.pathname.startsWith('/assets/')) return;

  // Static assets → cache-first
  if (
    url.pathname.startsWith('/assets/') ||
    url.pathname.endsWith('.css') ||
    url.pathname.endsWith('.js') ||
    url.pathname.endsWith('.png') ||
    url.pathname.endsWith('.jpg') ||
    url.pathname.endsWith('.svg') ||
    url.pathname.endsWith('.woff2')
  ) {
    e.respondWith(cacheFirst(request));
    return;
  }

  // App pages → network-first with offline fallback
  if (url.pathname.startsWith('/app/')) {
    e.respondWith(networkFirst(request));
    return;
  }
});

async function cacheFirst(req) {
  const cached = await caches.match(req);
  if (cached) return cached;
  try {
    const res = await fetch(req);
    if (res.ok) {
      const cache = await caches.open(CACHE);
      cache.put(req, res.clone());
    }
    return res;
  } catch {
    return new Response('Asset unavailable offline', { status: 503 });
  }
}

async function networkFirst(req) {
  try {
    const res = await fetch(req);
    if (res.ok) {
      const cache = await caches.open(CACHE);
      cache.put(req, res.clone());
    }
    return res;
  } catch {
    const cached = await caches.match(req);
    if (cached) return cached;
    // Return offline page
    const offline = await caches.match(OFFLINE_URL) || await caches.match('/app/offline.html');
    return offline || new Response('<h1>You are offline</h1>', { headers: { 'Content-Type': 'text/html' } });
  }
}
