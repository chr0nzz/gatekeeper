---
title: Configuration
description: Environment variables and admin UI settings.
---

GateKeeper uses a two-tier configuration model:

- **Env vars** - infrastructure settings that require a container restart to change. Keep these minimal.
- **Admin UI** - everything else. Changes take effect immediately with no restart.

## Required env vars

| Variable | Example | Description |
|---|---|---|
| `BASE_URL` | `https://auth.example.com` | Public URL. Used as the OIDC issuer and WebAuthn origin. No trailing slash. |
| `SECRET_KEY` | 64 hex chars | At least 32 characters. Encrypts TOTP secrets and signs sessions. Do not change after first run without revoking all sessions. |

Generate a secret key:

```bash
openssl rand -hex 32
```

## Optional env vars

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Port to listen on |
| `DB_PATH` | `/data/gatekeeper.db` | SQLite database path. Mount a volume here. |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error` |

## Env var fallbacks (overridden by admin UI)

These can be set as defaults via env vars, but any value saved in the admin UI takes precedence. If you set them here, they show up pre-filled in the settings form.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | - | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP port |
| `SMTP_USERNAME` | - | SMTP username |
| `SMTP_PASSWORD` | - | SMTP password |
| `SMTP_FROM` | - | From address for outgoing emails |
| `SMTP_TLS` | `starttls` | `starttls`, `tls`, or `none` |
| `SESSION_TTL_HOURS` | `8` | Session lifetime in hours |
| `ALLOWED_EMAIL_DOMAINS` | - | Comma-separated allowed domains, empty = all |

## Settings managed in the admin UI

Go to `/settings` on your admin panel to configure:

- **Allowed email domains** - restrict which email addresses can log in. Leave blank to allow all.
- **Session timeout** - how many hours before an idle session expires.
- **SMTP** - all mail server settings.

Changes to these settings apply immediately to all new requests, with no restart needed.

## Minimal compose file

```yaml
services:
  gatekeeper:
    image: ghcr.io/chr0nzz/gatekeeper:latest
    environment:
      BASE_URL: "https://auth.example.com"
      SECRET_KEY: "your-secret-key-here"
    volumes:
      - gatekeeper_data:/data

volumes:
  gatekeeper_data:
```
