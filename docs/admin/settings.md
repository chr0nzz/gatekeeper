---
title: Settings
description: Configure GateKeeper from the admin UI - no restart required.
---

The settings page at `/settings` lets you configure GateKeeper while it is running. All changes apply immediately with no restart.

## Access control

### Allowed email domains

A comma-separated list of email domains permitted to log in or be created.

```
example.com, contractor.org
```

Leave blank to allow any email address. When a domain list is set, attempts from other domains fail with an "invalid credentials" error (indistinguishable from a wrong password, to avoid revealing whether an account exists).

### Protected app domains

Applies to apps protected with ForwardAuth that live on a different domain than GateKeeper itself.

After signing in, GateKeeper only returns a user to a destination it trusts. Anything else is refused and the user lands on the GateKeeper home page instead. List your protected apps here so the return trip is allowed:

```
jellyfin.example.net
.example.org
```

One per line or comma-separated. Each entry covers that domain **and all of its subdomains**, so `example.org` allows `app.example.org` and `media.example.org`. Writing it as `.example.org`, `*.example.org`, or pasting a full URL all mean the same thing.

You do not need an entry for your own GateKeeper domain, your admin domain, or anything under the session cookie domain. Those are always allowed.

Changes take effect immediately, with no restart.

## Session timeout

How many hours a session stays alive after the last authenticated request. Resets on every request, so active users are never logged out. Default is 8 hours, maximum is 720 (30 days).

## Password policy

Rules every new password must satisfy. They apply immediately and cover every place a password is set, including passwords an admin sets on someone else's behalf.

| Setting | Default | Range |
|---|---|---|
| Minimum length | 12 | 8 to 128 |
| Require at least one uppercase letter | Off | On or off |
| Require at least one number | Off | On or off |
| Require at least one symbol | Off | On or off |

The sign-up, reset, and change-password forms all pick up the configured minimum, so what a user sees matches what the server enforces.

Raising the minimum length generally does more for security than turning on the character requirements. See [Password policy](/security/password-policy) for the reasoning and for how passwords are hashed.

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

## Login page branding

Customize the appearance of the login, registration, and password reset pages.

| Field | Description |
|---|---|
| App name | Shown in the sign-in heading ("Sign in to ..."). Leave blank to show "GateKeeper". |
| Tagline | Short line of text below the heading on the sign-in page. |
| Logo URL | A public image URL that replaces the GateKeeper mark. Leave blank to keep the default mark. |

When an OIDC client has its own icon configured, that icon takes priority over the logo URL on the sign-in page.

## Email branding

Customize the appearance of all outgoing emails (login codes, password resets, and password change notifications).

| Field | Description |
|---|---|
| Sender name | Shown in the email header and footer text. Defaults to "GateKeeper". |
| Logo URL | A public image URL displayed in the email header. Leave blank to show the sender name as text instead. |
| Accent color | Hex color used for the header background and button color. Defaults to `#2563eb`. |

Changes apply to the next email sent - no restart required.

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
