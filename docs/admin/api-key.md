---
title: Admin API key
description: Authenticate server-side API requests to GateKeeper using a personal API key.
---

Each admin account can generate a personal API key. The key lets server-side services call GateKeeper's admin API without a browser session - useful for dashboards, monitoring scripts, or any tool that needs to read GateKeeper data programmatically.

## Generating a key

Go to **My account** (`/profile`) and scroll to the **API key** card. Click **Generate key**. The key is displayed once - copy it now. Click the eye icon to reveal it, then use the copy button.

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

The key is accepted on all admin API endpoints in place of a session cookie. Session-based access (browser login) continues to work alongside key-based access.

## Security

- The key is stored in the database alongside your admin account. Rotating it immediately invalidates the previous value.
- Use the key only in server-side code. Do not expose it in client-side JavaScript or commit it to version control.
- Treat it like a password: use a secrets manager or environment variable to pass it to the services that need it.
