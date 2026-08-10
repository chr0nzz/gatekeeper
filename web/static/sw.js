const CACHE = 'gatekeeper-__GK_VERSION__';
const PRECACHE = [
  '/static/css/main.css',
  '/static/js/theme.js',
  '/static/favicon.svg',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE).then(c => c.addAll(PRECACHE)).then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  if (e.request.method !== 'GET') return;
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/login') ||
      url.pathname.startsWith('/logout') ||
      url.pathname.startsWith('/profile') ||
      url.pathname.startsWith('/admin') ||
      url.pathname.startsWith('/authorize') ||
      url.pathname.startsWith('/_gk')) return;

  if (!url.pathname.startsWith('/static/')) return;

  // Network first so a deployed change is picked up immediately. The cached copy
  // is only a fallback for when the server cannot be reached.
  e.respondWith(
    fetch(e.request).then(res => {
      if (res.ok) {
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(e.request, clone));
      }
      return res;
    }).catch(() => caches.match(e.request))
  );
});
