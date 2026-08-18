---
title: Admin API key
description: Authenticate server-side API requests to GateKeeper using a personal API key.
---

Each admin account can generate a personal API key. The key lets server-side services call GateKeeper's admin API without a browser session - useful for dashboards, monitoring scripts, or any tool that needs to read GateKeeper data programmatically.

## Generating a key

Go to **My account** (`/profile`) and scroll to the **API key** card. Click **Generate key**.

The key is shown once, immediately after generating it. Copy it then. Only a hash of the key is stored, so it cannot be displayed again. If you lose it, generate a new one.

## Rotating the key

Click **Rotate key** on the same card. You will be asked to confirm before the old key is invalidated. The new key is shown immediately after rotation.

Store only one key at a time. There is no way to retrieve the current key after leaving the page, but you can always rotate and copy the new value.

## Using the key

Send the key in the `X-Api-Key` request header:

```http
GET /admin/users HTTP/1.1
Host: auth.example.com
X-Api-Key: your-api-key-here
```

## What a key can reach

A key is limited to the read-only statistics endpoints, which is what a dashboard or monitoring script needs:

| Endpoint | Returns |
|---|---|
| `/api/dashboard-stats` | Counts of users, sign-ins, tokens, failures |
| `/api/activity` | Sign-in activity over time |
| `/api/auth-methods` | Breakdown of sign-in methods in use |
| `/api/version-check` | The latest released version |

Everything else in the admin panel is refused with `403`, including the user list, the audit log, settings, and the search endpoint, which returns email addresses. Signing in with a browser is unaffected.

A key is a long-lived credential with no second factor behind it, which is why it cannot read the rest of the panel. Attempts to use one outside these endpoints are recorded in the audit log as `admin.api_key_denied`.

## Security

- Only a hash of the key is stored, so a copy of the database does not yield a usable key. Rotating one invalidates the previous value immediately and is recorded as `admin.api_key_rotated`.
- Use the key only in server-side code. Do not expose it in client-side JavaScript or commit it to version control.
- Treat it like a password: use a secrets manager or environment variable to pass it to the services that need it.
