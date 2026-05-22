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
      SECRET_KEY: "your-64-char-hex-secret"
    volumes:
      - gatekeeper_data:/data
    ports:
      - "8080:8080"

volumes:
  gatekeeper_data:
```

Generate a `SECRET_KEY`:

```bash
openssl rand -hex 32
```

## 2. Start the container

```bash
docker compose up -d
```

## 3. Create your admin account

Visit `https://auth.example.com/admin`. GateKeeper redirects to `/admin/setup` on first run - enter your email and a password to create the admin account. This page only appears once.

## 4. Configure SMTP

Go to `/admin/settings` and fill in your mail server details. GateKeeper needs this to send one-time login codes and password reset emails.

## Updating

```bash
docker compose pull
docker compose up -d
```

Schema migrations run automatically on startup.

## Next steps

- **Protect apps** - use [Traefik ForwardAuth](/integrations/traefik-forwardauth) to require login for any service, or connect apps via [OIDC](/oidc/provider)
- **Add users** - go to `/admin/users` → New user
- **Connect apps** - register OIDC clients at `/admin/clients`
