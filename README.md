# GateKeeper

A lightweight, self-hosted authentication server. Single Docker container, SQLite database, configured entirely through the admin UI.

## What it does

- **OIDC identity provider** - any app that supports OpenID Connect can delegate login to GateKeeper. Users authenticate once; apps receive a verified identity token. Works with Grafana, Jellyfin, Portainer, Traefik Manager, or any standard OIDC client.
- **ForwardAuth middleware** - protect apps at the reverse proxy level without touching their code. Works with Traefik and any proxy that supports ForwardAuth.
- **Access policies** - create named policies, assign users to them, and attach policies to OIDC clients or ForwardAuth routes to restrict which users can access each app.
- **Multiple sign-in methods** - password + email OTP, passwordless email OTP, TOTP (authenticator app), passkeys (WebAuthn).
- **Webhooks** - push notifications to Discord, Slack, Telegram, ntfy, or any HTTP endpoint when auth and admin events occur.
- **Admin UI** - manage users, OIDC clients, policies, webhooks, settings, and audit log from a browser. No config files or CLI.

## Quick start

```yaml
services:
  gatekeeper:
    image: ghcr.io/chr0nzz/gatekeeper:latest
    restart: unless-stopped
    environment:
      BASE_URL: https://auth.example.com
      SECRET_KEY: your-64-char-hex-secret
    volumes:
      - gatekeeper_data:/data
    ports:
      - "8080:8080"

volumes:
  gatekeeper_data:
```

Generate a secret key:

```bash
openssl rand -hex 32
```

Visit `https://auth.example.com/admin` on first run - you'll be prompted to create your admin account. Everything else (SMTP, session TTL, allowed domains) is configured from the admin UI.

## Sign-in methods

| Method | How it works |
|---|---|
| Password + email OTP | Email + password, then a 6-digit code sent to the user's inbox |
| Passwordless | Email only, then a 6-digit OTP code (enabled per user by admin) |
| TOTP | Email + password, then a code from an authenticator app |
| Passkey | Device biometric or hardware key - no password, no code |

Trusted device tokens skip 2FA for 30 days after first verification on a device.

## OIDC provider

Register clients at `/admin/clients`. Point your app at the discovery endpoint:

| Endpoint | URL |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/authorize` |
| Token | `/oauth/token` |
| Userinfo | `/userinfo` |
| JWKS | `/keys` |

Supports authorization code + PKCE only. Scopes: `openid`, `email`, `profile`, `offline_access`. Tokens signed RS256, keys rotate every 30 days.

Login page shows the client's name and icon when accessed via OIDC.

## ForwardAuth

Every request to a protected app hits `GET /auth/verify` - GateKeeper returns `200` on success, `401` on failure.

```yaml
# traefik/dynamic/middlewares-gk-auth.yml
http:
  middlewares:
    gk-auth:
      forwardAuth:
        address: "https://auth.example.com/auth/verify"
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email
```

Apply `gk-auth@file` to any router. On success, GateKeeper passes `X-Auth-User` (UUID) and `X-Auth-Email` to the upstream app.

To restrict a route to a specific access policy, append `?policy=<name>` to the verify URL.

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `BASE_URL` | Yes | - | Public URL. Used as OIDC issuer and WebAuthn origin. |
| `SECRET_KEY` | Yes | - | 32+ character secret. Signs sessions and encrypts TOTP secrets. |
| `PORT` | No | `8080` | HTTP port to listen on. |
| `DB_PATH` | No | `/data/gatekeeper.db` | SQLite database path. |
| `COOKIE_DOMAIN` | No | - | Cookie domain for cross-subdomain sharing, e.g. `.example.com`. |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, or `error`. |

The following can also be set as env vars and serve as fallback defaults - the admin UI values take precedence at runtime:

| Variable | Default | Description |
|---|---|---|
| `SMTP_HOST` | - | Mail server hostname. |
| `SMTP_PORT` | `587` | Mail server port. |
| `SMTP_USERNAME` | - | SMTP username. |
| `SMTP_PASSWORD` | - | SMTP password. |
| `SMTP_FROM` | - | From address for outgoing mail. |
| `SMTP_TLS` | `starttls` | TLS mode: `starttls`, `tls`, or `none`. |
| `SESSION_TTL_HOURS` | `8` | Session lifetime in hours. |
| `ALLOWED_EMAIL_DOMAINS` | - | Comma-separated allowed domains. Empty means all domains are allowed. |

## Admin UI

| Page | Purpose |
|---|---|
| `/admin` | Dashboard - live stats, activity chart, auth methods breakdown |
| `/admin/users` | Create and manage users, filter by status and 2FA method |
| `/admin/clients` | Register and edit OIDC clients with icons |
| `/admin/policies` | Create access policies and assign users to them |
| `/admin/audit` | Filterable audit log of all auth and admin events |
| `/admin/webhooks` | Configure webhook delivery channels and event subscriptions |
| `/admin/settings` | SMTP, session timeout, allowed domains, audit log retention |
| `/admin/profile` | Admin password, TOTP, passkeys |

Keyboard shortcuts: `⌘K` / `/` command palette, `g d/u/c/a/s/p` navigate sections.

## Security

- Passwords hashed with argon2id (64 MB, 3 iterations, 4 threads)
- Sessions stored server-side in SQLite; cookie is `HttpOnly`, `Secure`, `SameSite=Lax`
- OTP and TOTP lockout after 5 failures in 10 minutes
- Password reset tokens: 32-byte random, argon2id hashed, single-use, 30-minute TTL
- TOTP secrets encrypted at rest with `SECRET_KEY`
- Recovery codes stored as individual argon2id hashes
- OIDC client icons fetched and cached server-side - never loaded from external servers by users
- OIDC tokens signed RS256, keys rotate every 30 days, PKCE required
- CSRF protection on all POST forms
- Secure headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP

## Building from source

Requires Go 1.26+. No CGO required.

```bash
git clone https://github.com/chr0nzz/gatekeeper
cd gatekeeper
go build -o gatekeeper ./cmd/gatekeeper
```

## Docker

```bash
docker build --build-arg VERSION=v0.3.0 -t gatekeeper:v0.3.0 .
```

## Project layout

```
cmd/gatekeeper/       entry point
internal/
  admin/              admin UI handlers
  auth/               password, OTP, TOTP, passkey, session, trusted devices
  audit/              audit log
  config/             environment variable loading
  db/                 SQLite init, migrations, query helpers
  mailer/             SMTP client
  middleware/         ForwardAuth, secure headers, CSRF
  notify/             webhook dispatch
  oidc/               OIDC provider (zitadel/oidc v3)
  templates/          template renderer
  ui/                 user-facing handlers
web/
  static/             CSS, JS (embedded)
  templates/          HTML templates (embedded)
docs/                 Astro Starlight documentation
```

## License

See [LICENSE](LICENSE).
