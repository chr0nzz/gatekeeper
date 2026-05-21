---
title: Settings
description: Configure GateKeeper from the admin UI - no restart required.
---

The settings page at `/admin/settings` lets you configure GateKeeper while it is running. All changes apply immediately.

## Access control

### Allowed email domains

A comma-separated list of email domains that are permitted to log in.

```
example.com, contractor.org
```

Leave blank to allow any email address. When a domain list is set, login attempts from other domains are rejected with an "invalid credentials" error (the same message as a wrong password, to avoid revealing whether an account exists).

### Session timeout

How many hours a session stays active after the last request. The default is 8 hours. The counter resets on each authenticated request, so active users are not logged out.

Shorter values improve security - a stolen session cookie becomes useless sooner. Longer values are more convenient for users on trusted devices.

The minimum is 1 hour. You can go up to 720 hours (30 days) for a "remember me" style experience.

## SMTP

GateKeeper sends emails for two purposes: one-time login codes and password reset links. Without a working SMTP configuration, users cannot complete login or recover their passwords.

| Field | Description |
|---|---|
| Host | Your SMTP server hostname, e.g. `smtp.fastmail.com` |
| Port | `587` for STARTTLS, `465` for TLS, `25` for plain |
| Username | SMTP authentication username |
| Password | SMTP authentication password. Leave blank to keep the current value. |
| From address | The "from" field on all outgoing emails |
| TLS mode | `STARTTLS` - connects plainly then upgrades (port 587). `TLS` - encrypted from the start (port 465). `None` - no encryption, for internal mail servers only. |

## Env var fallbacks

All settings on this page can also be set as environment variables, which act as the default when no value has been saved in the UI. See [Configuration](/getting-started/configuration) for the full list.

If you set both an env var and a UI value, the UI value wins.
