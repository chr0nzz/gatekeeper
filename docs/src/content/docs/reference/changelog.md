---
title: Changelog
description: Version history for GateKeeper.
---

## v0.2.0

- **OIDC provider** - Full authorization code + PKCE flow. Apps can now use GateKeeper as a proper OIDC identity provider (Traefik Manager, Termix, Grafana, Jellyfin, etc.)
- **OIDC client icons** - Add an icon URL per client. Icons are fetched and cached server-side at save time; the login page loads them from GateKeeper, not external servers.
- **Login page branding** - When signing in via OIDC, the login page shows the app name and cached icon instead of the GateKeeper logo.
- **Client editing** - Edit name, icon, redirect URIs, and optionally rotate the secret of any OIDC client without deleting and recreating it.
- **OIDC endpoint reference** - The clients page now shows all endpoint URLs (authorization, token, userinfo, JWKS, discovery) with copy buttons.
- **Secret generator** - One-click cryptographically random secret generation in the new/edit client dialogs.
- **Trusted device tokens** - After passing 2FA, a 30-day `gk_trust` cookie is set. Users on trusted devices skip the second factor until it expires.
- **Cross-domain ForwardAuth** - HMAC-signed short-lived tokens allow GateKeeper to set per-host cookies for apps on different TLDs.
- **Interactive dashboard chart** - Sign-in activity chart with 24h / 7d / 30d range toggle and hover tooltips backed by real data.
- **Real auth method breakdown** - Dashboard shows live percentages for passkey, TOTP, email OTP, and OIDC logins in the last 24 hours.
- **Command palette** - `⌘K` / `Ctrl+K` opens a search palette. Type to search users and clients by name. Keyboard shortcuts `g d/u/c/a/s` navigate between sections.
- **Audit log improvements** - Event type filter chips (auth / admin / oidc), kind filter (success / warn / fail / info), per-row filter button, correct event count.
- **Mobile navigation** - Bottom navigation bar on screens under 760px.
- **Admin sidebar** - Live user and client counts, version number in the footer.
- **New user sign-in methods** - Create users as "Email + Password" or "Email Only" (passwordless) directly from the new user form.
- **OIDC post-login redirect** - After authenticating via OIDC, GateKeeper correctly completes the auth request and redirects back to the app with an authorization code.
- **Theme persistence** - Dark/light/auto preference now survives full page navigation (was blocked by CSP preventing the inline bootstrap script).

## v0.1.0

Initial release.

- Password + email OTP login
- Passwordless email OTP mode (per-user, admin-configurable)
- TOTP enrollment with QR code and recovery codes
- Passkey (WebAuthn) registration and authentication
- Password recovery via email with rate-limited, single-use tokens
- Authenticated password change with session invalidation
- Forced password change on admin-created accounts
- Traefik ForwardAuth middleware (`/auth/verify`)
- OIDC provider with authorization code + PKCE flow
- OIDC scopes: `openid`, `email`, `profile`, `offline_access`
- RS256 signing with 30-day key rotation
- First-run setup page at `/admin/setup` - no env vars needed for admin credentials
- Admin UI for user and OIDC client management
- Admin profile page - change password, enroll TOTP, register passkeys
- All runtime settings (SMTP, session TTL, allowed domains) configurable in the admin UI
- Append-only audit log
- SQLite persistence with embedded migrations
- Docker multi-stage build (golang:1.26-alpine)
- Astro Starlight documentation site
