---
title: Install as an app (PWA)
description: Add GateKeeper to your home screen as a standalone app on mobile and desktop.
---

GateKeeper ships as a Progressive Web App (PWA). You can install it on your phone or computer and use it like a native app - no browser chrome, standalone window, and a home screen icon.

There are two separate apps you can install: one for the regular user portal and one for the admin panel.

## Installing on Android (Chrome)

**User app:**
1. Open GateKeeper in Chrome and sign in.
2. Tap the three-dot menu in the top right.
3. Tap **Add to Home screen** or **Install app**.
4. Confirm - the app installs as **GateKeeper**.

**Admin app:**
1. Open your admin panel (its own domain, e.g. `admin.auth.example.com`) and sign in as admin.
2. Tap the three-dot menu.
3. Tap **Add to Home screen** or **Install app**.
4. Confirm - the app installs as **GK Admin** with a distinct icon.

Both apps can be installed at the same time. They open directly to the correct starting page without browser navigation.

## Installing on iOS (Safari)

1. Open GateKeeper (or your admin panel) in Safari.
2. Tap the Share button (the box with an arrow pointing up).
3. Scroll down and tap **Add to Home Screen**.
4. Edit the name if you like, then tap **Add**.

Repeat the process on the admin panel to add the admin shortcut separately.

::: info
Safari on iOS does not show an automatic install prompt like Chrome does. You need to use the Share menu manually.
:::

## Installing on desktop (Chrome / Edge)

Look for the install icon in the browser's address bar (a small monitor icon or a "+" symbol). Click it and confirm. The app opens in its own window without browser tabs or the address bar.

On desktop, both the user and admin PWAs can be installed as separate windows.

## Updating

PWAs update automatically. GateKeeper's service worker checks for a new version on every page load and applies updates in the background. The next time you open the app, it will be running the latest version.

## Offline behavior

GateKeeper does not work offline - authentication always requires a server connection. The service worker caches static assets (CSS, fonts, icons) to make the app load faster on slow connections, but the login flow itself always contacts the server.
