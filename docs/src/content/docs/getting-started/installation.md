---
title: Installation
description: Run GateKeeper with Docker and connect it to Traefik.
---

GateKeeper runs as a single Docker container and stores everything in a SQLite database file. There are no external databases to set up.

## Prerequisites

- Docker and Docker Compose
- Traefik already running (or follow the example below)
- An SMTP server - you can add this later through the admin UI

## 1. Create a compose file

```yaml
services:
  gatekeeper:
    image: ghcr.io/chr0nzz/gatekeeper:latest
    restart: unless-stopped
    environment:
      BASE_URL: "https://auth.example.com"
      SECRET_KEY: "your-32-char-random-secret-here"
    volumes:
      - gatekeeper_data:/data

volumes:
  gatekeeper_data:
```

That's all that's required to start. SMTP, session timeout, and allowed domains are all configured through the admin UI after first login.

Generate a `SECRET_KEY` with:

```bash
openssl rand -hex 32
```

## 2. Start the container

```bash
docker compose up -d
```

GateKeeper creates the SQLite database automatically on first run and applies all schema migrations.

## 3. Create your admin account

Visit `https://auth.example.com/admin` in your browser. GateKeeper redirects you to `/admin/setup` where you choose your admin email and password. This page is only shown once - once an admin account exists, it redirects to the normal login.

## 4. Configure SMTP

Go to `/admin/settings` and fill in your SMTP details. GateKeeper needs this to send one-time login codes and password reset emails.

## 5. Connect Traefik

Add GateKeeper to your Traefik file provider config. See [ForwardAuth setup](/traefik/forwardauth) for the full configuration.

## Updating

```bash
docker compose pull gatekeeper
docker compose up -d gatekeeper
```

Schema migrations run automatically on startup.
