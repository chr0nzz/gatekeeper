# GateKeeper

A lightweight, self-hosted authentication server. Single Docker container, SQLite database, configured entirely through the admin UI.

## What it does

- **OIDC identity provider** - any app that supports OpenID Connect can delegate login to GateKeeper. Users authenticate once; apps receive a verified identity token. Works with Grafana, Jellyfin, Portainer, Traefik Manager, or any standard OIDC client.
- **ForwardAuth middleware** - protect apps at the reverse proxy level without touching their code. Works with Traefik, Nginx, and Caddy. Credential injection automatically supplies a stored username and password to apps that do not support SSO.
- **Groups** - create named groups and assign users to them. Group membership is included as a `groups` claim in all OIDC tokens, enabling role mapping in apps like Grafana and Jellyfin.
- **Access policies** - create named policies, assign users to them, and attach policies to OIDC clients or ForwardAuth routes to restrict which users can access each app.
- **Social login** - sign in with GitHub, Google, or Discord. Enable providers from the admin UI; GateKeeper auto-links on email match.
- **Self-registration** - choose between disabled, invite-only, open, and approval-required modes. Invite links are single-use with configurable expiry.
- **Multiple sign-in methods** - password + email OTP, passwordless email OTP, TOTP (authenticator app), passkeys (WebAuthn), QR code (scan with phone to approve), social OAuth2.
- **Webhooks** - push notifications to Discord, Slack, Telegram, ntfy, or any HTTP endpoint when auth and admin events occur.
- **Multiple admin accounts** - create and manage admin accounts from the Admins page. Generate a personal API key per admin for server-side API access using the `X-Api-Key` header.
- **Backups** - encrypted database snapshots to local storage or any S3-compatible object store (AWS S3, Cloudflare R2, Backblaze B2, MinIO). Schedule automatically, download, and restore from the admin UI.
- **Admin UI** - manage users, groups, OIDC clients, policies, invites, webhooks, backups, settings, and audit log from a browser. No config files or CLI.

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

Visit `https://auth.example.com/admin` on first run - you'll be prompted to create your admin account. Everything else (SMTP, session TTL, allowed domains, social login) is configured from the admin UI.

## Sign-in methods

| Method | How it works |
|---|---|
| Password + email OTP | Email + password, then a 6-digit code sent to the user's inbox |
| Passwordless | Email only, then a 6-digit OTP code (enabled per user by admin) |
| TOTP | Email + password, then a code from an authenticator app |
| Passkey | Device biometric or hardware key - no password, no code |
| QR code | Scan with your phone camera - approve on a device already signed in |
| Social | One-click sign-in via GitHub, Google, or Discord |

Trusted device tokens skip 2FA for 30 days after first verification on a device.

## OIDC provider

Register clients at `/admin/clients`. Point your app at the discovery endpoint:

| Endpoint | URL |
|---|---|
| Discovery | `/.well-known/openid-configuration` |
| Authorization | `/authorize` |
| Token | `/oauth/token` |
| Userinfo | `/userinfo` |
| Introspection | `/oauth/introspect` |
| JWKS | `/keys` |

Supports authorization code + PKCE and client credentials flows. Scopes: `openid`, `email`, `profile`, `offline_access`. Tokens signed RS256, keys rotate every 30 days.

The `groups` claim is included in all tokens automatically. Custom claims can be added per client - map user ID, email, display name, group membership, or a literal string to any claim key.

Token introspection (RFC 7662) is supported. Client credentials flow is available per client with configurable allowed scopes.

Login page shows the client's name and icon when accessed via OIDC. RP-initiated logout clears the GateKeeper session and honours `post_logout_redirect_uri`.

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
          - X-Auth-Groups
```

On success, GateKeeper passes `X-Auth-User` (UUID), `X-Auth-Email`, and `X-Auth-Groups` (comma-separated group names) to the upstream app.

Works with Traefik (`forwardAuth`), Nginx (`auth_request`), and Caddy (`forward_auth`). See the Integrations page in the admin UI for full configuration snippets.

To restrict a route to a specific access policy, append `?policy=<name>` to the verify URL.

**Credential injection:** for apps that do not support SSO, store a username and password on the policy. GateKeeper injects `Authorization: Basic` on a successful verify so the app never shows its own login form. Add `Authorization` to `authResponseHeaders` in your Traefik middleware config to enable it.

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
| `REGISTRATION_MODE` | `disabled` | Self-registration mode: `disabled`, `invite_only`, `open`, or `approval`. |
| `REGISTRATION_ALLOWED_DOMAINS` | - | Comma-separated domains allowed to self-register. Empty means any domain. |
| `GITHUB_CLIENT_ID` | - | GitHub OAuth2 app client ID for social login. |
| `GITHUB_CLIENT_SECRET` | - | GitHub OAuth2 app client secret. |
| `GOOGLE_CLIENT_ID` | - | Google OAuth2 client ID for social login. |
| `GOOGLE_CLIENT_SECRET` | - | Google OAuth2 client secret. |
| `DISCORD_CLIENT_ID` | - | Discord OAuth2 application client ID for social login. |
| `DISCORD_CLIENT_SECRET` | - | Discord OAuth2 application client secret. |

## Admin UI

| Page | Purpose |
|---|---|
| `/admin` | Dashboard - live stats, activity chart, auth methods breakdown |
| `/admin/users` | Create and manage users, approve pending registrations |
| `/admin/groups` | Create groups and manage membership |
| `/admin/clients` | Register and edit OIDC clients, custom claims, client credentials |
| `/admin/policies` | Create access policies and assign users to them |
| `/admin/invites` | Generate single-use invite links with configurable expiry |
| `/admin/audit` | Filterable audit log of all auth and admin events |
| `/admin/webhooks` | Configure webhook delivery channels and event subscriptions |
| `/admin/integrations` | Reverse proxy configuration snippets (Traefik, Nginx, Caddy) |
| `/admin/social` | Enable and configure GitHub, Google, and Discord social login |
| `/admin/admins` | Create and manage admin accounts |
| `/admin/backups` | Encrypted database backups to local storage or S3-compatible object stores |
| `/admin/profile` | Admin display name, password, TOTP, passkeys, session revocation |
| `/admin/settings` | SMTP, session timeout, allowed domains, registration mode, email branding, audit log retention |

Keyboard shortcuts: `⌘K` / `/` command palette, `g d/u/c/a/s/p` navigate sections.

## Security

- Passwords hashed with argon2id (64 MB, 3 iterations, 4 threads)
- Sessions stored server-side in SQLite; cookie is `HttpOnly`, `Secure`, `SameSite=Lax`
- OTP and TOTP lockout after 5 failures in 10 minutes
- Login rate limiting: 20 failed attempts per 15-minute window per IP
- OTP issuance rate limited to 3 codes per 10-minute window per user
- Password reset tokens: 32-byte random, argon2id hashed, single-use, 30-minute TTL
- TOTP secrets and injected app credentials encrypted at rest with AES-256-GCM derived from `SECRET_KEY`
- Email OTP codes stored as HMAC-SHA256 digests - a database dump without the key cannot reconstruct active codes
- Recovery codes stored as individual argon2id hashes
- OIDC client icons fetched and cached server-side - never loaded from external servers by users
- OIDC tokens signed RS256, keys rotate every 30 days, PKCE required
- CSRF protection on all POST forms
- Secure headers: HSTS, X-Frame-Options, X-Content-Type-Options, CSP

## Building from source

Requires Go 1.24+. No CGO required.

```bash
git clone https://github.com/chr0nzz/gatekeeper
cd gatekeeper
go build -o gatekeeper ./cmd/gatekeeper
```

## Docker

```bash
docker build --build-arg VERSION=v0.8.0 -t gatekeeper:v0.8.0 .
```

## Project layout

```
cmd/gatekeeper/       entry point
internal/
  admin/              admin UI handlers
  auth/               password, OTP, TOTP, passkey, session, trusted devices
  audit/              audit log
  backup/             encrypted database backup engine, S3 client, scheduler
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
docs/                 VitePress documentation site
```

## License

See [LICENSE](LICENSE).
