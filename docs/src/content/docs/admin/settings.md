---
title: Settings
description: Configure GateKeeper from the admin UI - no restart required.
---

The settings page at `/admin/settings` lets you configure GateKeeper while it is running. All changes apply immediately with no restart.

## Access control

### Allowed email domains

A comma-separated list of email domains permitted to log in or be created.

```
example.com, contractor.org
```

Leave blank to allow any email address. When a domain list is set, attempts from other domains fail with an "invalid credentials" error (indistinguishable from a wrong password, to avoid revealing whether an account exists).

### Session timeout

How many hours a session stays alive after the last authenticated request. Resets on every request, so active users are never logged out. Default is 8 hours, maximum is 720 (30 days).

## SMTP

GateKeeper sends email for two purposes: one-time login codes and password reset links. Without working SMTP, users cannot complete email OTP login or recover their passwords.

| Field | Description |
|---|---|
| Host | SMTP server hostname, e.g. `smtp.fastmail.com` |
| Port | `587` for STARTTLS, `465` for TLS, `25` for plain |
| Username | SMTP authentication username |
| Password | Leave blank to keep the current value |
| From address | The "from" field on all outgoing emails |
| TLS mode | `STARTTLS` (port 587), `TLS` (port 465), or `None` |

Click **Send test** to verify your SMTP config sends a message to the From address.

## OIDC provider

Read-only information about GateKeeper's OIDC configuration:

- **Issuer** - the base URL, used as the OIDC issuer identifier
- **Discovery** - `/.well-known/openid-configuration`
- **Signing** - RS256, keys rotate every 30 days automatically

## ForwardAuth snippet

A ready-to-paste config snippet for protecting apps via ForwardAuth. See the [Traefik ForwardAuth integration](/integrations/traefik-forwardauth) for the full setup guide.

## Unsaved changes

When you edit any field, a sticky save bar appears at the bottom of the page. Click **Save changes** to apply, or **Discard** to revert all edits. Changes are not applied until you save.

## Env var fallbacks

All settings on this page can be pre-seeded via environment variables (see [Configuration](/getting-started/configuration)). The UI value always takes precedence over an env var. If no UI value has been saved, the env var value is shown as the default.
