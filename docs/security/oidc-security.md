---
title: OIDC security
description: PKCE enforcement, key rotation, and token lifetimes.
---

## PKCE required

PKCE (Proof Key for Code Exchange, pronounced "pixie") is a security extension to OAuth 2.0 that prevents authorization code interception. In the standard authorization code flow, an attacker who intercepts the code (for example, through a compromised redirect URI) can exchange it for tokens. PKCE prevents this by requiring the client to prove it initiated the request.

GateKeeper requires PKCE for all authorization requests. Clients that do not send a `code_challenge` parameter will receive an error.

## Implicit flow disabled

The implicit flow returns access tokens directly in the URL fragment, making them visible in browser history and server logs. GateKeeper does not support it. Use the authorization code flow with PKCE.

## Signing keys

OIDC tokens are signed with 2048-bit RSA keys using the RS256 algorithm (RSA with SHA-256).

A key is retired 30 days after it was created and replaced with a freshly generated one. GateKeeper checks hourly, so a restart is never needed for rotation to happen. Only one key signs tokens at a time.

A retired key keeps being published for another 48 hours so that tokens it signed still verify. Access and ID tokens live 15 minutes, so this is far longer than any token can outlast its key. Once that window passes the retired key is deleted.

Public keys are published at `/oauth/jwks` in JSON Web Key Set (JWKS) format, including retired keys still inside their window. Any client can fetch this to verify token signatures without contacting GateKeeper for each request.

The admin dashboard shows when the current key was created and when it is next due to rotate, under System health.

## Token lifetimes

Short-lived tokens limit the window an attacker has if a token is stolen.

| Token | Lifetime |
|---|---|
| Access token | 15 minutes |
| Refresh token | 30 days |
| ID token | 15 minutes |

Refresh tokens are stored server-side. They can be revoked immediately by deleting the token record. Access tokens cannot be revoked before they expire (this is inherent to bearer tokens).

## Client authentication

Confidential clients (server-side apps) must authenticate using HTTP Basic Auth with their client ID and secret on the token endpoint. Public clients are not supported.
