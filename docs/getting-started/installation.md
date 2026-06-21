---
title: Installation
description: Run GateKeeper with Docker Compose.
---

GateKeeper runs as a single Docker container. It creates its own SQLite database on first run and manages all schema migrations automatically.

## Prerequisites

- Docker and Docker Compose
- A domain with TLS (or a local setup for testing)
- An SMTP server - you can configure this later through the admin UI

## 1. Create a compose file

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

GateKeeper listens on two ports:

- **`8282`** - the public side: login, OIDC, and ForwardAuth. Route your public domain (`auth.example.com`) here.
- **`8283`** - the admin panel, served at the root. Route a private domain (`admin.example.com`) here and keep it off the public internet. Set `ADMIN_URL` to that domain so admin passkeys work.

Generate a `SECRET_KEY`:

```bash
openssl rand -hex 32
```

## 2. Start the container

```bash
docker compose up -d
```

## 3. Create your admin account

Visit your admin URL (the value of `ADMIN_URL`, e.g. `https://admin.auth.example.com`). The admin panel runs on its own port (`ADMIN_PORT`, default `8283`) and is served at the root - there is no `/admin` path prefix. GateKeeper redirects to `/setup` on first run - enter your email and a password to create the admin account. This page only appears once.

## 4. Configure SMTP

Go to `/settings` on your admin panel and fill in your mail server details. GateKeeper needs this to send one-time login codes and password reset emails.

## Updating

```bash
docker compose pull
docker compose up -d
```

Schema migrations run automatically on startup.

## Next steps

- **Protect apps** - use [Traefik ForwardAuth](/integrations/traefik-forwardauth) to require login for any service, or connect apps via [OIDC](/oidc/provider)
- **Add users** - go to `/users` → New user
- **Connect apps** - register OIDC clients at `/clients`
