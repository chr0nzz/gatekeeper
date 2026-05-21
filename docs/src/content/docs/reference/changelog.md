---
title: Changelog
description: Version history for GateKeeper.
---

## v0.1.0

Initial release.

- Password + email OTP login
- Passwordless email OTP mode (per-user)
- TOTP enrollment with QR code and recovery codes
- Passkey (WebAuthn) registration and authentication
- Password recovery via email with rate-limited, single-use tokens
- Authenticated password change with session invalidation
- Forced password change on admin-created accounts
- Traefik ForwardAuth middleware (`/auth/verify`)
- OIDC provider with authorization code + PKCE flow
- OIDC scopes: `openid`, `email`, `profile`, `offline_access`
- RS256 signing with 30-day key rotation
- Admin UI for user and OIDC client management
- Append-only audit log
- SQLite persistence with embedded migrations
- Docker multi-stage build
- Astro Starlight documentation site
