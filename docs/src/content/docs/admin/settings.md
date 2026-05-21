---
title: Settings
description: Runtime configuration overview.
---

GateKeeper's settings are managed entirely through environment variables. The settings page at `/admin/settings` is a reference to this documentation - there are no editable fields in the UI.

To change a setting, update the environment variable in your `docker-compose.yml` and restart GateKeeper:

```bash
docker compose up -d gatekeeper
```

## Why environment variables only

This is a deliberate design choice. Environment variables make configuration auditable (they live in your compose file or secrets manager), easy to version-control (no separate config file to track), and simple to apply (restart the container).

## Key settings to review

**Session TTL** (`SESSION_TTL_HOURS`, default 8): how long a session lasts after the last request. Shorter is more secure; longer is more convenient. Users on corporate networks with idle timeouts may appreciate a shorter value.

**Allowed email domains** (`ALLOWED_EMAIL_DOMAINS`): comma-separated list of domains that can log in. Leave empty to allow all. If your users are all `company.com`, set this to `company.com` to prevent external accounts.

**Log level** (`LOG_LEVEL`, default `info`): set to `debug` to see every request. Logs are structured JSON to stdout.

For the full variable reference, see [Environment variables](/reference/env-vars).
