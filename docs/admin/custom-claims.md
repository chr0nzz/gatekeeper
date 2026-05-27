---
title: Custom claims
description: Inject extra fields into OIDC tokens on a per-client basis.
---

# Custom claims

GateKeeper can inject additional claims (token fields) into access and ID tokens for specific OIDC clients. This lets you pass user attributes to apps that expect non-standard fields without changing how other clients work.

Manage custom claims at **Admin - OIDC Clients** - click the claims icon next to any client.

## Value sources

| Source | Token value |
|--------|-------------|
| User ID | The user's internal UUID (`sub` value) |
| Email | The user's email address |
| Display name | The user's display name, or empty if not set |
| Groups array | An array of the user's group names (same as the built-in `groups` claim, but under a different key) |
| Literal value | A fixed string you type in - same for every user |

## Adding a claim

1. Open the claims page for a client.
2. Enter a **claim key** - the field name that will appear in the token (letters, digits, underscores only).
3. Select a **value source**.
4. For literal values, type the static string.
5. Click **Add**.

The claim appears immediately in the next token issued for that client.

## Reserved keys

The following keys are reserved by the OIDC spec and cannot be overridden: `sub`, `iss`, `aud`, `exp`, `iat`, `auth_time`, `nonce`, `acr`, `amr`, `azp`, `at_hash`, `c_hash`, `jti`.

## Example - Grafana role mapping

Grafana can map an OIDC claim to its role system. Add a claim with key `role` and value source **Literal value** set to `Viewer` to give all users the Viewer role by default. Or use **Groups array** under a custom key if you want Grafana to map group names to roles.

## Example - Authelia

Authelia's OIDC authorization policy can match on arbitrary claims. Add a claim with key `department` and source **Literal value** or pull it from the display name depending on your naming convention.
