---
title: Environment variables
description: Complete reference for all GateKeeper environment variables.
---

## Required

| Variable | Example | Description |
|---|---|---|
| `BASE_URL` | `https://auth.example.com` | Public URL. Used as the OIDC issuer, WebAuthn origin, and in all links. No trailing slash. |
| `SECRET_KEY` | 64 hex chars | Minimum 32 characters. Signs sessions and TOTP secrets. Do not change after first run without revoking all sessions. |

Generate a secret key:

```bash
openssl rand -hex 32
```

## Optional

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8282` | Public HTTP port - login, OIDC, and ForwardAuth. |
| `ADMIN_PORT` | `8283` | Admin-only HTTP port. Never expose this publicly - route it only through a private reverse proxy. |
| `ADMIN_URL` | _(empty)_ | Full public URL of the admin panel, e.g. `https://admin.auth.example.com`. Set this when the admin runs on its own subdomain so that admin passkeys work - GateKeeper adds this origin to the WebAuthn allowed origins list. The admin subdomain must be under the same registrable domain as `BASE_URL`. |
| `ADMIN_BASE_PATH` | _(empty)_ | Serve the admin panel under a path prefix instead of the root. Leave empty (default) when the admin has its own domain - the panel is then served at `/`. Set to `/admin` only if you route the admin port under a `/admin` subpath without stripping the prefix. |
| `DB_PATH` | `/data/gatekeeper.db` | SQLite database path. Mount a volume at `/data`. |
| `COOKIE_DOMAIN` | _(empty)_ | Cookie domain for cross-subdomain session sharing, e.g. `.example.com`. Leave empty if all apps share the same domain. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |

## SMTP defaults (overridden by admin UI)

These pre-seed the SMTP settings form. If you save values in the admin settings, those take precedence.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | _(empty)_ | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | _(empty)_ | SMTP username |
| `SMTP_PASSWORD` | _(empty)_ | SMTP password |
| `SMTP_FROM` | _(empty)_ | From address on outgoing emails |
| `SMTP_TLS` | `starttls` | `starttls`, `tls`, or `none` |

## Other defaults (overridden by admin UI)

| Variable | Default | Description |
|---|---|---|
| `SESSION_TTL_HOURS` | `8` | Session lifetime in hours |
| `ALLOWED_EMAIL_DOMAINS` | _(empty)_ | Comma-separated allowed domains. Empty = all. |
| `REGISTRATION_MODE` | `disabled` | Initial registration mode: `disabled`, `invite_only`, `open`, or `approval`. |
| `REGISTRATION_ALLOWED_DOMAINS` | _(empty)_ | Comma-separated domains allowed to self-register. Empty = any. |
| `GITHUB_CLIENT_ID` | _(empty)_ | GitHub OAuth App client ID. Seeded into Settings on first startup. |
| `GITHUB_CLIENT_SECRET` | _(empty)_ | GitHub OAuth App client secret. Seeded into Settings on first startup. |
| `GOOGLE_CLIENT_ID` | _(empty)_ | Google OAuth2 client ID. Seeded into Settings on first startup. |
| `GOOGLE_CLIENT_SECRET` | _(empty)_ | Google OAuth2 client secret. Seeded into Settings on first startup. |
| `DISCORD_CLIENT_ID` | _(empty)_ | Discord application client ID. Seeded into Settings on first startup. |
| `DISCORD_CLIENT_SECRET` | _(empty)_ | Discord application client secret. Seeded into Settings on first startup. |

## Minimal compose file

```yaml
services:
  gatekeeper:
    image: ghcr.io/chr0nzz/gatekeeper:latest
    restart: unless-stopped
    environment:
      BASE_URL: "https://auth.example.com"
      ADMIN_URL: "https://admin.auth.example.com"
      SECRET_KEY: "your-64-char-hex-secret"
    volumes:
      - gatekeeper_data:/data
    ports:
      - "8282:8282"
      - "8283:8283"

volumes:
  gatekeeper_data:
```

Route `auth.example.com` to port `8282` and `admin.auth.example.com` to port `8283` in your reverse proxy. Restrict `8283` to your private network.

## Cross-domain sessions

If you protect apps on multiple subdomains under the same TLD (e.g. `app1.example.com` and `app2.example.com`), set `COOKIE_DOMAIN=.example.com` to share the session cookie.

For apps on completely different domains (different TLDs), GateKeeper uses a short-lived HMAC-signed token to set per-host cookies without needing cookie sharing.
