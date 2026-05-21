---
title: Installation
description: Run GateKeeper with Docker and connect it to Traefik.
---

GateKeeper runs as a single Docker container and stores all its data in a SQLite database file. There are no external databases to set up.

## Prerequisites

- Docker and Docker Compose
- Traefik v3 already running (or you can use the included `docker-compose.yml` example)
- An SMTP server to send OTP and password reset emails

## 1. Get the compose file

Copy the example `docker-compose.yml` from the repository, or use the snippet below as a starting point.

## 2. Configure environment variables

At minimum you need to set:

| Variable | Example | What it is |
|---|---|---|
| `BASE_URL` | `https://auth.example.com` | The public URL where GateKeeper is reachable |
| `SECRET_KEY` | 32+ random characters | Used to encrypt session data and TOTP secrets |
| `ADMIN_EMAIL` | `admin@example.com` | Email for the initial admin account |
| `ADMIN_PASSWORD` | a strong password | Password for the initial admin account |
| `SMTP_HOST` | `smtp.example.com` | Your SMTP server |
| `SMTP_FROM` | `noreply@example.com` | The "from" address for emails |

See [Environment variables](/reference/env-vars) for the full list.

## 3. Start everything

```bash
docker compose up -d
```

GateKeeper will create the SQLite database at the path set by `DB_PATH` (default `/data/gatekeeper.db`) and run all schema migrations automatically on startup.

## 4. Protect an app

Add these two labels to any service in your compose file:

```yaml
labels:
  # Docker label format
  - traefik.http.routers.myapp.middlewares=gatekeeper-auth
```

The `gatekeeper-auth` middleware is defined on the GateKeeper service itself. Any request to `myapp` will now require a valid GateKeeper session.

## Persisting data

Mount a volume at `/data` so the database survives container restarts:

```yaml
volumes:
  - gatekeeper_data:/data
```

The included compose file already does this.

## Updating

Pull the new image and restart:

```bash
docker compose pull gatekeeper
docker compose up -d gatekeeper
```

GateKeeper runs migrations automatically on startup, so there's nothing else to do.
