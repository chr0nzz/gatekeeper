---
title: Session security
description: How sessions work, cookie flags, TTL, and sliding renewal.
---

## Session model

GateKeeper uses server-side sessions. The session data (user ID, session state) is stored in the SQLite database. The browser only receives an opaque random token (32 bytes of entropy, hex-encoded) stored in a cookie.

This means:

- There is no sensitive data in the cookie itself. An attacker who reads the cookie value gets a token that is valid only until the session expires or is revoked.
- Sessions can be revoked instantly by deleting the database record. The user's cookie becomes useless immediately.

## Cookie flags

Every session cookie is set with:

| Flag | Purpose |
|---|---|
| `HttpOnly` | JavaScript cannot read the cookie, which blocks most XSS-based session theft |
| `Secure` | The cookie is only sent over HTTPS |
| `SameSite=Lax` | The cookie is not sent on cross-site POST requests, which prevents most CSRF attacks |
| `Path=/` | The cookie covers the entire site |

## Session TTL and sliding renewal

Sessions expire after `SESSION_TTL_HOURS` hours (default 8) of inactivity. Every valid request resets this timer, so active users do not get logged out unexpectedly.

Sessions also record a `last_seen` timestamp. The database cleanup job runs every 15 minutes and removes sessions where `expires_at` is in the past.

## Session invalidation

Sessions are revoked (deleted from the database) in these situations:

- The user logs out.
- An admin clicks **Revoke all sessions** for a user.
- The user changes their password (all sessions except the current one are revoked).
- The user completes a password reset via email link (all sessions are revoked).
- The user's account is disabled.

## Admin sessions

Admin sessions are separate from user sessions and use a different cookie (`gk_admin`). They expire after 8 hours and are not subject to the `SESSION_TTL_HOURS` environment variable.
