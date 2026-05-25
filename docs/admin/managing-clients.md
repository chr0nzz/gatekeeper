---
title: Managing OIDC clients
description: Register, edit, and manage OIDC clients in the admin panel.
---

OIDC clients are applications that delegate authentication to GateKeeper. Manage them at `/admin/clients`.

## Endpoint reference

The clients page shows a reference table with all URLs you need when configuring an app:

| Field | URL |
|---|---|
| Discovery | `https://auth.example.com/.well-known/openid-configuration` |
| Authorization URL | `https://auth.example.com/authorize` |
| Token URL | `https://auth.example.com/oauth/token` |
| Userinfo URL | `https://auth.example.com/userinfo` |
| Issuer | `https://auth.example.com` |
| JWKS URI | `https://auth.example.com/keys` |

Apps that support OIDC discovery only need the discovery URL - they will auto-configure from it.

## Registering a client

Click **New client** and fill in:

- **Display name** - shown in the admin UI and on the login page when users authenticate via this client.
- **Icon URL** - optional. Paste a direct image URL (PNG, SVG, etc.). GateKeeper fetches and caches the image server-side immediately on save - icons are never loaded from external servers by users. Browse [selfh.st/icons](https://selfh.st/icons/) for a large library of self-hosted app icons.
- **Client ID** - a short identifier like `grafana` or `jellyfin-prod`. This is public and appears in authorization requests. Lowercase, digits, dashes, and underscores only. Cannot be changed after creation.
- **Client secret** - click **Generate** to create a cryptographically random secret, or paste your own. Store it securely - GateKeeper will not show it again after you close the dialog.
- **Redirect URIs** - the callback URLs your app sends users to after authentication. One per line. Must match exactly, including path and scheme.

## Editing a client

Click the pencil icon on any client row. You can change:

- Display name
- Icon URL (GateKeeper re-fetches and re-caches the image on save)
- Redirect URIs
- Client secret (leave blank to keep the current one; click **Generate** to rotate)

The client ID cannot be changed.

## Redirect URI requirements

URIs must match exactly. `https://app.example.com/callback` and `https://app.example.com/callback?extra=param` are different URIs.

Use HTTPS for all production redirect URIs. `http://localhost` is acceptable for local development only.

## Deleting a client

Click the trash icon on any client row. This immediately revokes the client's ability to authenticate. Existing tokens expire naturally according to their TTL (15 minutes for access tokens, 30 days for refresh tokens).

## Login page branding

When a user is sent to GateKeeper from an OIDC client, the login page automatically shows:
- The client's display name in the heading ("Sign in to Grafana")
- The client's cached icon above the heading

This only works when the user arrives via the `/authorize` endpoint (i.e., through the standard OIDC flow). Direct `/login` access shows the GateKeeper logo.
