/**
 * Service Worker for FWF Website
 * Provides offline capability and faster loading through caching
 */

const CACHE_VERSION = 'fwf-v1.0.1';
const CACHE_NAME = `fwf-cache-${CACHE_VERSION}`;

// Assets to cache immediately on install
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/m/index.html',
  '/assets/css/fwf.css',
  '/assets/js/fwf.js',
  '/assets/js/mobile-detect.js',
  '/assets/images/logo.png',
  '/manifest.json'
];

// Assets to cache on first request
const DYNAMIC_CACHE = 'fwf-dynamic-v1';

// Maximum age for cached items (7 days)
const MAX_AGE = 7 * 24 * 60 * 60 * 1000;

/**
 * Install event - cache static assets
 */
self.addEventListener('install', event => {
  console.log('[SW] Installing service worker...');
  
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        console.log('[SW] Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting())
      .catch(err => console.error('[SW] Cache installation failed:', err))
  );
});

/**
 * Activate event - clean up old caches
 */
self.addEventListener('activate', event => {
  console.log('[SW] Activating service worker...');
  
  event.waitUntil(
    caches.keys()
      .then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => {
            if (cacheName !== CACHE_NAME && cacheName !== DYNAMIC_CACHE) {
              console.log('[SW] Deleting old cache:', cacheName);
              return caches.delete(cacheName);
            }
          })
        );
      })
      .then(() => self.clients.claim())
  );
});

/**
 * Fetch event - serve from cache, fallback to network
 */
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // Skip API calls (always fetch fresh)
  if (url.pathname.startsWith('/api/')) {
    return;
  }

  // Skip backend calls
  if (url.hostname.includes('backend') || url.port === '3000') {
    return;
  }

  // Skip non-HTTP(S) schemes like browser extensions
  if (!['http:', 'https:'].includes(url.protocol)) {
    return;
  }

  event.respondWith(
    cacheFirst(request)
      .catch(() => networkFirst(request))
      .catch(() => offlineFallback())
  );
});

/**
 * Cache-first strategy
 */
async function cacheFirst(request) {
  const cache = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  
  if (cached) {
    // Check if cache is still fresh
    const cacheTime = await getCacheTime(request.url);
    if (cacheTime && (Date.now() - cacheTime < MAX_AGE)) {
      console.log('[SW] Serving from cache:', request.url);
      
      // Update cache in background
      updateCache(request);
      
      return cached;
    }
  }
  
  // If not in cache or expired, fetch from network
  return networkFirst(request);
}

/**
 * Network-first strategy with cache fallback
 */
async function networkFirst(request) {
  try {
    const response = await fetch(request);
    
    // Cache successful same-origin responses only
    if (response.ok && request.url.startsWith(self.location.origin)) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
      await setCacheTime(request.url);
      console.log('[SW] Cached from network:', request.url);
    }
    
    return response;
  } catch (error) {
    // Network failed, try cache
    const cache = await caches.open(DYNAMIC_CACHE);
    const cached = await cache.match(request);
    
    if (cached) {
      console.log('[SW] Network failed, serving from cache:', request.url);
      return cached;
    }
    
    throw error;
  }
}

/**
 * Update cache in background
 */
async function updateCache(request) {
  try {
    const response = await fetch(request);
    if (response.ok && request.url.startsWith(self.location.origin)) {
      const cache = await caches.open(CACHE_NAME);
      await cache.put(request, response);
      await setCacheTime(request.url);
      console.log('[SW] Cache updated:', request.url);
    }
  } catch (error) {
    console.log('[SW] Background cache update failed:', request.url);
  }
}

/**
 * Offline fallback page
 */
async function offlineFallback() {
  return new Response(
    `<!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Offline - FWF</title>
      <style>
        body {
          font-family: system-ui, sans-serif;
          display: flex;
          align-items: center;
          justify-content: center;
          min-height: 100vh;
          margin: 0;
          background: linear-gradient(135deg, #1e3a8a 0%, #0f766e 100%);
          color: white;
          text-align: center;
          padding: 20px;
        }
        .container {
          max-width: 400px;
        }
        h1 {
          font-size: 48px;
          margin: 0 0 16px 0;
        }
        p {
          font-size: 18px;
          opacity: 0.9;
          line-height: 1.6;
        }
        button {
          margin-top: 24px;
          padding: 12px 24px;
          font-size: 16px;
          background: white;
          color: #1e3a8a;
          border: none;
          border-radius: 8px;
          cursor: pointer;
          font-weight: bold;
        }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>📡</h1>
        <h2>You're Offline</h2>
        <p>Please check your internet connection and try again.</p>
        <button onclick="window.location.reload()">Retry</button>
      </div>
    </body>
    </html>`,
    {
      headers: { 'Content-Type': 'text/html' }
    }
  );
}

/**
 * Cache timestamp helpers
 */
async function getCacheTime(url) {
  try {
    const cache = await caches.open('fwf-meta');
    const response = await cache.match(url + ':timestamp');
    if (response) {
      const text = await response.text();
      return parseInt(text, 10);
    }
  } catch (e) {
    return null;
  }
  return null;
}

async function setCacheTime(url) {
  try {
    const cache = await caches.open('fwf-meta');
    await cache.put(
      url + ':timestamp',
      new Response(Date.now().toString())
    );
  } catch (e) {
    console.error('[SW] Failed to set cache time:', e);
  }
}

/**
 * Message handler for cache management
 */
self.addEventListener('message', event => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
  
  if (event.data && event.data.type === 'CLEAR_CACHE') {
    event.waitUntil(
      caches.keys().then(cacheNames => {
        return Promise.all(
          cacheNames.map(cacheName => caches.delete(cacheName))
        );
      })
    );
  }
});
