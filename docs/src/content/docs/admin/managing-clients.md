---
title: Managing OIDC clients
description: Register and manage OIDC clients in the admin panel.
---

OIDC clients are applications that use GateKeeper as their identity provider. Manage them at `/admin/clients`.

## Registering a client

Click **New client** and fill in:

- **Client ID** - a short identifier for the app, like `grafana` or `myapp`. This is public and appears in authorization requests.
- **Client secret** - a long random string. Keep this private. It is stored in the database and never shown again after creation, so copy it before saving.
- **Display name** - a human-readable name shown in the admin UI.
- **Redirect URIs** - the callback URLs your app is allowed to use after authentication. Enter one per line. These must match exactly, including the path.

## Redirect URI requirements

Redirect URIs must match exactly. `https://app.example.com/callback` and `https://app.example.com/callback?extra=param` are treated as different URIs.

Use HTTPS for all production redirect URIs. `http://localhost` is acceptable for local development.

## Deleting a client

Click **Delete** next to any client. This immediately revokes the client's ability to authenticate. Existing access and refresh tokens for that client are not automatically revoked - they expire naturally according to their TTL.

## Client secret rotation

There is no built-in rotation workflow. To rotate a secret, delete the existing client and create a new one with the same client ID but a new secret. Update your application's configuration before deleting the old client to avoid downtime.
