# GateKeeper

A lightweight, self-hosted authentication server. Runs as a single Docker container, integrates with Traefik as a ForwardAuth middleware, and ships with a built-in OIDC provider so downstream apps can use it as an identity provider.

## Features

- **Traefik ForwardAuth** - protect any app behind Traefik with two labels
- **OIDC provider** - use GateKeeper as an identity provider for apps that support OpenID Connect
- **Multiple login methods** - password + email OTP, passwordless email OTP, TOTP (Google Authenticator / Authy), passkeys (WebAuthn)
- **Password recovery** - self-service forgot-password flow with rate-limited, single-use reset tokens
- **Admin UI** - manage users, OIDC clients, and settings at `/admin`
- **All settings in the UI** - SMTP, session TTL, allowed email domains, and more are configured in the admin panel, not env vars
- **SQLite only** - no external database required
- **Single binary** - everything embedded, zero runtime dependencies

## Quick start

```yaml
# docker-compose.yml
services:
  gatekeeper:
    image: ghcr.io/chr0nzz/gatekeeper:latest
    environment:
      BASE_URL: https://auth.example.com
      SECRET_KEY: your-32-char-random-secret-here
      DB_PATH: /data/gatekeeper.db
    volumes:
      - gatekeeper_data:/data
    ports:
      - "8080:8080"

volumes:
  gatekeeper_data:
```

On first run, visit `https://auth.example.com/admin` - you'll be prompted to create your admin account. All other settings (SMTP, session TTL, allowed domains) are configured from the admin UI after that.

## Authentication flows

| Method | How it works |
|---|---|
| Password + OTP | Email + password, then a 6-digit code sent to the user's inbox |
| Passwordless | Email only, then a 6-digit code (admin-enabled per user) |
| TOTP | Email + password, then a code from an authenticator app |
| Passkey | Device biometric or PIN - no password, no code |

When TOTP is enrolled it replaces email OTP. Passkey login skips both.

## Traefik integration

### ForwardAuth

Every request to a protected service hits `GET /auth/verify`. GateKeeper returns `200` with identity headers on success, `401` on failure.

```yaml
# Traefik file provider (traefik/dynamic/gatekeeper.yml)
http:
  middlewares:
    gk-auth:
      forwardAuth:
        address: "http://gatekeeper:8080/auth/verify"
        authResponseHeaders:
          - X-Auth-User
          - X-Auth-Email

  routers:
    myapp:
      rule: "Host(`app.example.com`)"
      middlewares:
        - gk-auth
      service: myapp-service
```

Identity is passed to the upstream app via:
- `X-Auth-User` - user UUID
- `X-Auth-Email` - user email address

### OIDC provider

GateKeeper exposes a full OIDC provider. Register clients at `/admin/clients`, then point your app at the discovery URL:

```
https://auth.example.com/.well-known/openid-configuration
```

Supports authorization code flow with PKCE only. Scopes: `openid`, `email`, `profile`, `offline_access`.

## Configuration

Only four env vars are required. Everything else is configured in the admin UI.

| Variable | Required | Default | Description |
|---|---|---|---|
| `BASE_URL` | Yes | - | Public URL, e.g. `https://auth.example.com` |
| `SECRET_KEY` | Yes | - | 32+ character random string |
| `DB_PATH` | No | `/data/gatekeeper.db` | SQLite database path |
| `PORT` | No | `8080` | Port to listen on |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, or `error` |

**Env var fallbacks** (overridden by admin UI settings):

| Variable | Description |
|---|---|
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS` | SMTP defaults (set these or configure via UI) |
| `SESSION_TTL_HOURS` | Session lifetime default (default: 8) |
| `ALLOWED_EMAIL_DOMAINS` | Allowed domain default (empty = all) |

## First run

1. Start the container with only `BASE_URL` and `SECRET_KEY` set.
2. Visit `https://auth.example.com/admin` - you'll be redirected to `/admin/setup`.
3. Enter your admin email and password.
4. You're in. Go to `/admin/settings` to configure SMTP and other settings.

## Admin UI

| Page | What you can do |
|---|---|
| `/admin/users` | Create users, manage accounts, revoke sessions |
| `/admin/users/new` | Create a new user |
| `/admin/clients` | Register and manage OIDC clients |
| `/admin/settings` | Configure SMTP, session TTL, allowed email domains |
| `/admin/audit` | Read-only log of all auth events |
| `/admin/profile` | Change admin password, enroll TOTP, add passkeys |

## Security

- Passwords hashed with argon2id (64 MB memory, 3 iterations, 4 threads)
- Sessions stored server-side in SQLite; cookie is `HttpOnly`, `Secure`, `SameSite=Lax`
- OTP and TOTP brute-force lockout after 5 failures in 10 minutes
- Password reset tokens: 32-byte random, argon2id hashed, single-use, 30-minute TTL
- TOTP secrets encrypted at rest with `SECRET_KEY`
- TOTP recovery codes stored as individual argon2id hashes
- OIDC tokens signed with RS256, keys rotate every 30 days
- PKCE required for all OIDC flows
- CSRF protection on all POST forms
- Secure headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP

## Building from source

```bash
git clone https://github.com/chr0nzz/gatekeeper
cd gatekeeper
go mod tidy
go build -o gatekeeper ./cmd/gatekeeper
```

Requires Go 1.26+. No CGO required.

## Docker

```bash
docker build -t gatekeeper .
```

Multi-stage build: `golang:1.26-alpine` builder, `alpine:latest` final image.

## Documentation

Full documentation is in [`/docs`](docs/) as an Astro Starlight site.

```bash
cd docs && npm install && npm run dev
```

## Project layout

```
gatekeeper/
- cmd/gatekeeper/     main entry point
- internal/auth/      password, OTP, TOTP, passkey, session
- internal/oidc/      OIDC provider (zitadel/oidc v3)
- internal/admin/     admin UI handlers
- internal/ui/        user-facing handlers
- internal/middleware/ ForwardAuth, secure headers, CSRF
- internal/mailer/    SMTP client
- internal/audit/     audit log writer
- internal/config/    environment variable loading
- internal/db/        SQLite init, migrations, queries
- web/templates/      HTML templates (embedded)
- web/static/         CSS, passkey JS (embedded)
- docs/               Astro Starlight documentation site
```

## License

See [LICENSE](LICENSE).
