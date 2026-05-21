# GateKeeper

A lightweight, self-hosted authentication server. Runs as a single Docker container, integrates with Traefik as a ForwardAuth middleware, and ships with a built-in OIDC provider so downstream apps can use it as an identity provider.

## Features

- **Traefik ForwardAuth** - protect any app behind Traefik with two labels
- **OIDC provider** - use GateKeeper as an identity provider for apps that support OpenID Connect
- **Multiple login methods** - password + email OTP, passwordless email OTP, TOTP (Google Authenticator / Authy), passkeys (WebAuthn)
- **Password recovery** - self-service forgot-password flow with rate-limited, single-use reset tokens
- **Admin UI** - manage users, OIDC clients, and view the audit log at `/admin`
- **SQLite only** - no external database required
- **Single binary** - everything embedded, zero runtime dependencies

## Quick start

```yaml
# docker-compose.yml
services:
  gatekeeper:
    image: ghcr.io/yourorg/gatekeeper:latest
    environment:
      BASE_URL: https://auth.example.com
      SECRET_KEY: your-32-char-random-secret-here
      ADMIN_EMAIL: admin@example.com
      ADMIN_PASSWORD: changeme
      SMTP_HOST: smtp.example.com
      SMTP_FROM: noreply@example.com
    volumes:
      - gatekeeper_data:/data
    labels:
      - traefik.enable=true
      - traefik.http.routers.gk.rule=Host(`auth.example.com`)
      - traefik.http.middlewares.gk-auth.forwardauth.address=http://gatekeeper:8080/auth/verify
      - traefik.http.middlewares.gk-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email

  myapp:
    image: yourapp
    labels:
      - traefik.enable=true
      - traefik.http.routers.myapp.rule=Host(`app.example.com`)
      - traefik.http.routers.myapp.middlewares=gk-auth

volumes:
  gatekeeper_data:
```

Sign in at `https://auth.example.com/admin` with the bootstrap credentials to create users.

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

Every request to a protected service hits `GET /auth/verify`. GateKeeper returns `200` with identity headers on success, `401` on failure. Traefik handles the redirect to `/login`.

```yaml
# On the GateKeeper service
- traefik.http.middlewares.gk-auth.forwardauth.address=http://gatekeeper:8080/auth/verify
- traefik.http.middlewares.gk-auth.forwardauth.authResponseHeaders=X-Auth-User,X-Auth-Email

# On any protected service
- traefik.http.routers.myapp.middlewares=gk-auth
```

Identity is passed to the upstream app via:
- `X-Auth-User` - user UUID
- `X-Auth-Email` - user email address

### OIDC provider

GateKeeper exposes a full OIDC provider. Configure clients at `/admin/clients`, then point your app at the discovery URL:

```
https://auth.example.com/.well-known/openid-configuration
```

Supports authorization code flow with PKCE only. Scopes: `openid`, `email`, `profile`, `offline_access`.

## Configuration

All configuration is via environment variables.

| Variable | Required | Default | Description |
|---|---|---|---|
| `BASE_URL` | Yes | - | Public URL, e.g. `https://auth.example.com` |
| `SECRET_KEY` | Yes | - | 32+ character random string |
| `ADMIN_EMAIL` | Yes | - | Bootstrap admin email (first run only) |
| `ADMIN_PASSWORD` | Yes | - | Bootstrap admin password (first run only) |
| `DB_PATH` | No | `/data/gatekeeper.db` | SQLite database path |
| `SMTP_HOST` | Yes | - | SMTP server hostname |
| `SMTP_PORT` | No | `587` | SMTP port |
| `SMTP_USERNAME` | No | - | SMTP username |
| `SMTP_PASSWORD` | No | - | SMTP password |
| `SMTP_FROM` | Yes | - | From address for emails |
| `SMTP_TLS` | No | `starttls` | `starttls`, `tls`, or `none` |
| `SESSION_TTL_HOURS` | No | `8` | Session lifetime in hours |
| `ALLOWED_EMAIL_DOMAINS` | No | - | Comma-separated allowed domains, empty = all |
| `LOG_LEVEL` | No | `info` | `debug`, `info`, `warn`, or `error` |

## Security

- Passwords hashed with argon2id (64 MB memory, 3 iterations, 4 threads)
- Sessions stored server-side in SQLite; cookie is `HttpOnly`, `Secure`, `SameSite=Lax`
- OTP and TOTP brute-force lockout after 5 failures in 10 minutes
- Password reset tokens are 32-byte random values stored as argon2id hashes, single-use, 30-minute TTL
- TOTP secrets encrypted at rest with `SECRET_KEY`
- TOTP recovery codes stored as individual argon2id hashes
- OIDC tokens signed with RS256, keys rotate every 30 days
- PKCE required for all OIDC flows
- CSRF protection on all POST forms
- Secure headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP
- All auth events written to an append-only audit log

## Building from source

```bash
git clone https://github.com/yourorg/gatekeeper
cd gatekeeper
go mod tidy
go build -o gatekeeper ./cmd/gatekeeper
```

Requires Go 1.24+. No CGO required (`modernc.org/sqlite` is a pure-Go SQLite driver).

## Docker

```bash
docker build -t gatekeeper .
```

Multi-stage build: `golang:1.24-alpine` builder, `alpine:latest` final image.

## Documentation

Full documentation is in [`/docs`](docs/) as an Astro Starlight site.

```bash
cd docs
npm install
npm run dev
```

Topics covered: installation, all auth flows, Traefik setup, OIDC client integration, admin guide, security model, API reference, environment variable reference, and database schema.

## Project layout

```
gatekeeper/
- cmd/gatekeeper/     main entry point
- internal/auth/      password, OTP, TOTP, passkey, session
- internal/oidc/      OIDC provider (zitadel/oidc v3)
- internal/admin/     admin UI handlers
- internal/ui/        user-facing handlers
- internal/middleware/ ForwardAuth, secure headers
- internal/mailer/    SMTP client
- internal/audit/     audit log writer
- internal/config/    environment variable loading
- internal/db/        SQLite init, migrations
- web/templates/      HTML templates (embedded)
- web/static/         CSS, passkey JS (embedded)
- docs/               Astro Starlight documentation site
```

## License

See [LICENSE](LICENSE).
