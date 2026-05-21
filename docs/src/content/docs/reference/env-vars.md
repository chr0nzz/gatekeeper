---
title: Environment variables
description: Complete reference for all GateKeeper environment variables.
---

| Variable | Required | Default | Description |
|---|---|---|---|
| `PORT` | No | `8080` | Port GateKeeper listens on |
| `BASE_URL` | Yes | - | Public URL, e.g. `https://auth.example.com`. No trailing slash. Used as OIDC issuer and WebAuthn origin. |
| `SECRET_KEY` | Yes | - | At least 32 characters. Used to encrypt TOTP secrets and sign sessions. Do not change after first run without revoking all sessions. |
| `ADMIN_EMAIL` | Yes | - | Email for the bootstrap admin account. Only used on first run. |
| `ADMIN_PASSWORD` | Yes | - | Password for the bootstrap admin account. Only used on first run. |
| `DB_PATH` | No | `/data/gatekeeper.db` | Path to the SQLite database file. Mount a volume here for persistence. |
| `SMTP_HOST` | Yes | - | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP server port |
| `SMTP_USERNAME` | No | - | SMTP authentication username |
| `SMTP_PASSWORD` | No | - | SMTP authentication password |
| `SMTP_FROM` | Yes | - | From address for outgoing emails |
| `SMTP_TLS` | No | `starttls` | TLS mode: `starttls`, `tls`, or `none` |
| `SESSION_TTL_HOURS` | No | `8` | Session lifetime in hours. Renewed on each request. |
| `ALLOWED_EMAIL_DOMAINS` | No | - | Comma-separated list of permitted email domains. Empty means all domains allowed. |
| `LOG_LEVEL` | No | `info` | Log verbosity: `debug`, `info`, `warn`, or `error`. Logs are structured JSON to stdout. |
