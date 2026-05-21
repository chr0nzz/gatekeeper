---
title: Configuration
description: All environment variables with descriptions and examples.
---

GateKeeper is configured entirely through environment variables. There are no config files.

## Required variables

### `BASE_URL`

The public URL where GateKeeper is reachable, without a trailing slash. This is used as the OIDC issuer URL and as the WebAuthn (passkey) origin.

```env
BASE_URL=https://auth.example.com
```

### `SECRET_KEY`

A random string of at least 32 characters. Used to encrypt TOTP secrets stored in the database and to sign session data. Generate one with:

```bash
openssl rand -hex 32
```

Keep this secret. Changing it will invalidate all existing sessions and TOTP enrollments.

### `ADMIN_EMAIL` and `ADMIN_PASSWORD`

The email and password for the first admin account. These are only used on the very first startup when no admin exists yet. After that, changing these variables has no effect.

### `SMTP_HOST` and `SMTP_FROM`

The hostname of your SMTP server and the "from" address for outgoing emails.

## All variables

```env
# Server
PORT=8080
BASE_URL=https://auth.example.com

# Encryption
SECRET_KEY=<32+ random characters>

# Bootstrap admin (first run only)
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=changeme

# Database
DB_PATH=/data/gatekeeper.db

# SMTP
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=noreply@example.com
SMTP_TLS=starttls    # starttls | tls | none

# Sessions
SESSION_TTL_HOURS=8

# Optional
ALLOWED_EMAIL_DOMAINS=    # comma-separated, empty means allow all
LOG_LEVEL=info            # debug | info | warn | error
```

## SMTP TLS modes

| Value | What it does |
|---|---|
| `starttls` | Connects on the plain port then upgrades to TLS. The default for port 587. |
| `tls` | Connects with TLS from the start. Use this for port 465. |
| `none` | No encryption. Only use this on a trusted internal network. |

## Allowed email domains

Set `ALLOWED_EMAIL_DOMAINS` to a comma-separated list to restrict which email addresses can log in:

```env
ALLOWED_EMAIL_DOMAINS=example.com,mycompany.org
```

Leave it empty to allow any email address.
