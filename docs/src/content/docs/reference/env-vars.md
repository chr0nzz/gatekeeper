---
title: Environment variables
description: Complete reference for all GateKeeper environment variables.
---

GateKeeper uses a two-tier configuration model. Most runtime settings are managed through the admin UI at `/admin/settings`. Only infrastructure-level settings that require a container restart belong here.

## Required

| Variable | Description |
|---|---|
| `BASE_URL` | Public URL, e.g. `https://auth.example.com`. No trailing slash. Used as the OIDC issuer and WebAuthn origin. |
| `SECRET_KEY` | At least 32 characters. Encrypts TOTP secrets and signs sessions. Changing this after first run invalidates all existing sessions and TOTP enrollments. |

## Optional

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Port GateKeeper listens on |
| `DB_PATH` | `/data/gatekeeper.db` | Path to the SQLite database. Mount a volume at this path for persistence. |
| `LOG_LEVEL` | `info` | Log verbosity: `debug`, `info`, `warn`, or `error`. Logs are structured JSON to stdout. |

## Admin UI fallback defaults

These env vars set the initial default values shown in `/admin/settings`. Once you save a value in the UI, the UI value takes permanent precedence over the env var. If you never touch the UI, the env var is used.

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | - | SMTP server hostname |
| `SMTP_PORT` | `587` | SMTP server port |
| `SMTP_USERNAME` | - | SMTP authentication username |
| `SMTP_PASSWORD` | - | SMTP authentication password |
| `SMTP_FROM` | - | From address for outgoing emails |
| `SMTP_TLS` | `starttls` | TLS mode: `starttls`, `tls`, or `none` |
| `SESSION_TTL_HOURS` | `8` | Session lifetime in hours |
| `ALLOWED_EMAIL_DOMAINS` | - | Comma-separated allowed email domains. Empty means all domains are allowed. |

## Minimal example

```env
BASE_URL=https://auth.example.com
SECRET_KEY=ceaa65d112d2d1935c249170086246e0...
```

Configure everything else through `/admin/settings` after first run.
