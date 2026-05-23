---
title: Changelog
description: Version history for GateKeeper.
---

## v0.3.0

- **Webhooks** - Send push notifications to Discord, Slack, Telegram, ntfy (public and self-hosted), generic JSON endpoints, or email when auth and admin events occur. Configure per-webhook event subscriptions and test delivery inline from the Webhooks page.
- **Access policies** - Create named policies and assign users to them. Attach a policy to an OIDC client to restrict which users can complete authorization, or reference it via `?policy=<name>` on `/auth/verify` for ForwardAuth routes. Policy ForwardAuth URL shown with copy button on the policies page.
- **Admin audit logging** - Admin sign-in (password and passkey), sign-out, failed login attempts, and user deletion are now recorded in the audit log alongside all other events.
- **Audit log retention** - Set a retention period in Settings. Events older than the configured number of days are deleted automatically on startup and daily. Default is 90 days; set to 0 to keep all events.
- **Audit log date filter** - Filter by Today, 7 days, 30 days, 90 days, or All time directly from the toolbar.
- **User profile** - Users can set a display name and pull in a Gravatar avatar from their home screen. The image is fetched server-side and cached in the database so the browser never contacts Gravatar directly.
- **Avatars everywhere** - Display name and avatar appear in the admin user list, user detail page, audit log rows, and dashboard recent events.
- **Dashboard redesign** - Real sparklines from the database on the sign-ins, failed attempts, and OIDC traffic cards. New cards for active sessions, 2FA adoption, and audit log stats. Auth methods card with 24h / 7d / 30d range toggle.
- **Command palette fixes** - `⌘K` / `Ctrl+K` palette now has working keyboard navigation (arrow keys, Enter). All pages including Policies, Webhooks, and Integrations appear in the navigate list. Searching users matches display name in addition to email.
- **New user modal** - Creating a user from the Users page now opens an inline modal instead of navigating to a separate page.
- **Policies table** - Policies page redesigned to match the OIDC clients table layout with description, member count, and used-by columns.
- **System health section** - Consolidates configuration warnings (locked accounts, users without 2FA, OIDC signing key status).

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
